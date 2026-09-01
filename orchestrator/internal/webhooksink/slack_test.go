package webhooksink

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

const slackPath = "/slack/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

func TestSlackWebhook_MatchedTokenRecordsReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718"
		seedToken(t, pool, token, "run-slack-1", "T1567.004")

		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		text := token + "\n[BAS-SIM-DLP] test payload"
		body := slackTeamsBody(t, text)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+slackPath, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		assertReceiptRecorded(t, pool, token, "webhook-slack", len(body))
	})
}

func TestSlackWebhook_UnmatchedTokenStillSucceedsNoReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		body := slackTeamsBody(t, "never-issued-token\nunrelated body")
		req, _ := http.NewRequest(http.MethodPost, srv.URL+slackPath, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200 even for an unmatched token", resp.StatusCode)
		}
		assertNoReceipt(t, pool, "never-issued-token")
	})
}

func TestSlackWebhook_OversizedBodyRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		tooBig := slackTeamsBody(t, string(bytes.Repeat([]byte("x"), MaxPayloadBytes+1024)))
		req, _ := http.NewRequest(http.MethodPost, srv.URL+slackPath, bytes.NewReader(tooBig))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Error("a body exceeding MaxPayloadBytes should not return 200")
		}
	})
}
