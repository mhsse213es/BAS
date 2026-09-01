package sftpsink

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// validToken64 is genuinely 64 hex characters -- matching
// generateSinkToken(32)'s real hex-encoded output length exactly.
const validToken64 = "abcd1234ef567890abcd1234ef567890abcd1234ef567890abcd1234ef5678ab"

func TestFilenameToken_AcceptsExpectedShape(t *testing.T) {
	token, ok := filenameToken("/" + validToken64 + ".dat")
	if !ok {
		t.Fatal("expected the <64-hex-char-token>.dat shape to be accepted")
	}
	if token != validToken64 {
		t.Errorf("token = %q, unexpected", token)
	}
}

func TestFilenameToken_RejectsWrongExtension(t *testing.T) {
	if _, ok := filenameToken("/" + validToken64 + ".txt"); ok {
		t.Error("a non-.dat extension must be rejected")
	}
}

func TestFilenameToken_RejectsNonHexOrWrongLength(t *testing.T) {
	cases := []string{
		"/not-hex-at-all.dat",
		"/abcd.dat", // too short
		"/abcd1234ef567890abcd1234ef567890abcd1234ef567890abcd1234ef56780000.dat", // too long
	}
	for _, c := range cases {
		if _, ok := filenameToken(c); ok {
			t.Errorf("filenameToken(%q) should be rejected", c)
		}
	}
}

func TestFilenameToken_RejectsDirectoryTraversalOrExtraPathSegments(t *testing.T) {
	if _, ok := filenameToken("/sub/abcd1234ef567890abcd1234ef567890abcd1234ef567890abcd1234ef5678.dat"); ok {
		t.Error("a path with directory segments must be rejected -- this listener supports exactly one flat write target")
	}
}

func TestSessionWriter_BufferedThenClosedRecordsReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "session1234567890session1234567890session1234567890session1234"
		w := newSessionWriter(token, pool, "10.0.0.7")
		payload := []byte("[BAS-SIM-DLP] synthetic exfil payload")
		n, err := w.WriteAt(payload, 0)
		if err != nil {
			t.Fatalf("WriteAt: %v", err)
		}
		if n != len(payload) {
			t.Fatalf("WriteAt wrote %d bytes, want %d", n, len(payload))
		}
		if err := w.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		var payloadHash string
		var payloadSize int
		var channel, sourceIP string
		if err := pool.QueryRow(context.Background(),
			`SELECT payload_hash, payload_size, channel, source_ip FROM dlp_sink_receipts WHERE token = $1`,
			token,
		).Scan(&payloadHash, &payloadSize, &channel, &sourceIP); err != nil {
			t.Fatalf("query dlp_sink_receipts: %v", err)
		}
		wantSum := sha256.Sum256(payload)
		if payloadHash != hex.EncodeToString(wantSum[:]) {
			t.Errorf("payload_hash = %q, want sha256 of the written content", payloadHash)
		}
		if payloadSize != len(payload) {
			t.Errorf("payload_size = %d, want %d", payloadSize, len(payload))
		}
		if channel != "sftp" {
			t.Errorf("channel = %q, want sftp", channel)
		}
		if sourceIP != "10.0.0.7" {
			t.Errorf("source_ip = %q, want 10.0.0.7", sourceIP)
		}
	})
}

func TestSessionWriter_OversizedWriteRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "oversize1234567890oversize1234567890oversize1234567890oversize"
		w := newSessionWriter(token, pool, "10.0.0.8")
		tooBig := make([]byte, MaxUploadBytes+1)
		if _, err := w.WriteAt(tooBig, 0); err == nil {
			t.Error("a write exceeding MaxUploadBytes must be rejected")
		}
	})
}

func TestSessionWriter_WritesAcrossMultipleCallsAccumulateCorrectly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "multi1234567890multi1234567890multi1234567890multi1234567890ab"
		w := newSessionWriter(token, pool, "10.0.0.9")
		if _, err := w.WriteAt([]byte("hello, "), 0); err != nil {
			t.Fatalf("first WriteAt: %v", err)
		}
		if _, err := w.WriteAt([]byte("world"), 7); err != nil {
			t.Fatalf("second WriteAt: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		var payloadSize int
		if err := pool.QueryRow(context.Background(),
			`SELECT payload_size FROM dlp_sink_receipts WHERE token = $1`, token,
		).Scan(&payloadSize); err != nil {
			t.Fatalf("query dlp_sink_receipts: %v", err)
		}
		if payloadSize != len("hello, world") {
			t.Errorf("payload_size = %d, want %d (writes at sequential offsets must accumulate, not overwrite)", payloadSize, len("hello, world"))
		}
	})
}

func TestRateLimiter_AllowsUpToLimitThenBlocks(t *testing.T) {
	rl := newRateLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !rl.allow("10.0.0.1") {
			t.Fatalf("request %d should be allowed within the limit", i+1)
		}
	}
	if rl.allow("10.0.0.1") {
		t.Error("request beyond the limit should be blocked")
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
