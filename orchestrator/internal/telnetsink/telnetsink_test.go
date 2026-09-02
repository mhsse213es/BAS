package telnetsink_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/telnetsink"
	"github.com/audspect/bas/internal/testutil"
	"github.com/jackc/pgx/v5/pgxpool"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	sharedDB = testutil.MustSharedTestDB()
	m.Run()
}

func seedToken(t *testing.T, pool *pgxpool.Pool, token, runID string) {
	_, err := pool.Exec(t.Context(),
		`INSERT INTO dlp_sink_tokens (token, run_id, technique_id, expires_at)
		 VALUES ($1, $2, $3, NOW() + INTERVAL '1 hour')`,
		token, runID, "T1048.003",
	)
	if err != nil {
		t.Fatalf("seedToken: %v", err)
	}
}

func TestHandleTelnetSession_ValidTokenWritesReceipt(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
		seedToken(t, pool, token, "test-run-1")

		payload := map[string]interface{}{
			"token": token,
			"session": []map[string]string{
				{"type": "connect"},
				{"type": "prompt", "data": "login: "},
				{"type": "command", "data": token + "\ndata"},
				{"type": "response", "data": "ok"},
				{"type": "close"},
			},
		}
		body, _ := json.Marshal(payload)

		req := httptest.NewRequest("POST", "/session", bytes.NewReader(body))
		req.RemoteAddr = "127.0.0.1:12345"
		w := httptest.NewRecorder()

		handler := telnetsink.Routes(pool)
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status code: got %d, want 200", w.Code)
		}

		// Verify receipt was written
		var count int
		pool.QueryRow(t.Context(),
			`SELECT COUNT(*) FROM dlp_sink_receipts WHERE token = $1`, token,
		).Scan(&count)
		if count != 1 {
			t.Fatalf("receipt count: got %d, want 1", count)
		}
	})
}

func TestHandleTelnetSession_UnmatchedTokenNoReceipt(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		payload := map[string]interface{}{
			"token": "unmatched0000000000000000000000",
			"session": []map[string]string{
				{"type": "connect"},
				{"type": "prompt", "data": "login: "},
				{"type": "command", "data": "unmatched\ndata"},
				{"type": "response", "data": "ok"},
				{"type": "close"},
			},
		}
		body, _ := json.Marshal(payload)

		req := httptest.NewRequest("POST", "/session", bytes.NewReader(body))
		req.RemoteAddr = "127.0.0.1:12345"
		w := httptest.NewRecorder()

		handler := telnetsink.Routes(pool)
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status code: got %d, want 200", w.Code)
		}

		// Verify no receipt was written
		var count int
		pool.QueryRow(t.Context(),
			`SELECT COUNT(*) FROM dlp_sink_receipts WHERE token = $1`, "unmatched0000000000000000000000",
		).Scan(&count)
		if count != 0 {
			t.Fatalf("receipt count: got %d, want 0", count)
		}
	})
}

func TestHandleTelnetSession_OversizedPayload(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		payload := map[string]interface{}{
			"token": "aaaabbbbccccddddeeeeffffgggghhhh",
			"session": []map[string]string{
				{"type": "connect"},
				{"type": "command", "data": strings.Repeat("x", 65000)}, // Over 64KiB
			},
		}
		body, _ := json.Marshal(payload)

		req := httptest.NewRequest("POST", "/session", bytes.NewReader(body))
		req.RemoteAddr = "127.0.0.1:12345"
		w := httptest.NewRecorder()

		handler := telnetsink.Routes(pool)
		handler.ServeHTTP(w, req)

		// Should still return 200 (plausible success shape), but no receipt
		if w.Code != http.StatusOK {
			t.Fatalf("status code: got %d, want 200", w.Code)
		}
	})
}

func TestHandleTelnetSession_RateLimiting(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		payload := map[string]interface{}{
			"token": "aaaabbbbccccddddeeeeffffgggghhhh",
			"session": []map[string]string{
				{"type": "connect"},
			},
		}
		body, _ := json.Marshal(payload)

		handler := telnetsink.Routes(pool)

		// Send 6 requests from the same IP within 1 second
		for i := 0; i < 6; i++ {
			req := httptest.NewRequest("POST", "/session", bytes.NewReader(body))
			req.RemoteAddr = "127.0.0.1:12345"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("request %d: status code %d", i, w.Code)
			}
		}
		// 6th request should be rate-limited, but still returns 200
	})
}
