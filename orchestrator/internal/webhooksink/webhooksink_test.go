package webhooksink

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/audspect/bas/internal/testutil"
	"github.com/jackc/pgx/v5/pgxpool"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

// seedToken inserts a dlp_sink_tokens row directly, matching
// issueSinkTokensAndSubstitute's own insert shape.
func seedToken(t *testing.T, pool *pgxpool.Pool, token, runID, techniqueID string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO dlp_sink_tokens (token, run_id, technique_id, expires_at) VALUES ($1, $2, $3, $4)`,
		token, runID, techniqueID, time.Now().Add(10*time.Minute),
	); err != nil {
		t.Fatalf("seed dlp_sink_tokens: %v", err)
	}
}

// assertReceiptRecorded polls for up to 5s since the HTTP response may
// return before the write is visible to a separate connection.
func assertReceiptRecorded(t *testing.T, pool *pgxpool.Pool, token, wantChannel string, wantSize int) {
	t.Helper()
	var channel string
	var size int
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := pool.QueryRow(context.Background(),
			`SELECT channel, payload_size FROM dlp_sink_receipts WHERE token = $1`, token,
		).Scan(&channel, &size)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no dlp_sink_receipts row for token within 5s: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if channel != wantChannel {
		t.Errorf("channel = %q, want %q", channel, wantChannel)
	}
	if size != wantSize {
		t.Errorf("payload_size = %d, want %d", size, wantSize)
	}
}

func assertNoReceipt(t *testing.T, pool *pgxpool.Pool, token string) {
	t.Helper()
	time.Sleep(200 * time.Millisecond) // let any (incorrect) write land before checking
	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM dlp_sink_receipts WHERE token = $1`, token,
	).Scan(&count); err != nil {
		t.Fatalf("count receipts: %v", err)
	}
	if count != 0 {
		t.Errorf("dlp_sink_receipts rows for unmatched token = %d, want 0", count)
	}
}

// slackTeamsBody builds the {"text": "..."} JSON body Slack and MS Teams
// incoming webhooks both use.
func slackTeamsBody(t *testing.T, text string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	return b
}

func TestRateLimiter_AllowsUpToLimitPerWindow(t *testing.T) {
	rl := newRateLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !rl.allow("10.0.0.1") {
			t.Fatalf("request %d should be allowed within the limit", i)
		}
	}
	if rl.allow("10.0.0.1") {
		t.Error("4th request in the same window should be rejected")
	}
}

func TestRateLimiter_TracksSourcesIndependently(t *testing.T) {
	rl := newRateLimiter(1, time.Minute)
	if !rl.allow("10.0.0.1") {
		t.Fatal("first request from 10.0.0.1 should be allowed")
	}
	if !rl.allow("10.0.0.2") {
		t.Error("a different source IP must have its own independent limit")
	}
}

func TestTokenExists_FalseForNilDB(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if tokenExists(ctx, nil, "any-token") {
		t.Error("tokenExists must not panic or return true when db is nil / ctx is cancelled")
	}
}
