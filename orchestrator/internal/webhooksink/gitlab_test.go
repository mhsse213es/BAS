package webhooksink

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestGitLabSnippet_MatchedTokenRecordsReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3"
		seedToken(t, pool, token, "run-gitlab-1", "T1567.001")

		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		payload := map[string]any{
			"title":      "bas-sim",
			"visibility": "private",
			"file_name":  token + ".dat",
			"content":    "[BAS-SIM-DLP] test payload",
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/gitlab/api/v4/snippets", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("PRIVATE-TOKEN", "bas-sim-fake-token-0000000000000000")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Errorf("status = %d, want 201 (matching real GitLab Snippet creation's own success code)", resp.StatusCode)
		}
		assertReceiptRecorded(t, pool, token, "coderepo-gitlab", len(body))
	})
}

func TestGitLabSnippet_UnmatchedTokenStillSucceedsNoReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		payload := map[string]any{
			"title":      "bas-sim",
			"visibility": "private",
			"file_name":  "never-issued.dat",
			"content":    "x",
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/gitlab/api/v4/snippets", bytes.NewReader(body))
		req.Header.Set("PRIVATE-TOKEN", "bas-sim-fake-token-0000000000000000")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Errorf("status = %d, want 201 even for an unmatched token", resp.StatusCode)
		}
		assertNoReceipt(t, pool, "never-issued")
	})
}
