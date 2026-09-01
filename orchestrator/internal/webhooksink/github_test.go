package webhooksink

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestGitHubGist_MatchedTokenRecordsReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2"
		seedToken(t, pool, token, "run-github-1", "T1567.001")

		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		payload := map[string]any{
			"description": "bas-sim",
			"public":      false,
			"files": map[string]any{
				token + ".dat": map[string]string{"content": "[BAS-SIM-DLP] test payload"},
			},
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/github/gists", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "token bas-sim-fake-pat-0000000000000000")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Errorf("status = %d, want 201 (matching real GitHub Gist creation's own success code)", resp.StatusCode)
		}
		assertReceiptRecorded(t, pool, token, "coderepo-github", len(body))
	})
}

func TestGitHubGist_UnmatchedTokenStillSucceedsNoReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		payload := map[string]any{
			"description": "bas-sim",
			"public":      false,
			"files":       map[string]any{"never-issued.dat": map[string]string{"content": "x"}},
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/github/gists", bytes.NewReader(body))
		req.Header.Set("Authorization", "token bas-sim-fake-pat-0000000000000000")
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

// TestGitHubGist_MissingAuthHeaderStillAccepted pins the deliberate
// "presence-of-header fidelity only, never real validation" decision from
// the spec: a request with no Authorization header at all must still be
// accepted and still record its receipt. The channel tests whether DLP
// inspected the traffic, not whether the caller authenticated.
func TestGitHubGist_MissingAuthHeaderStillAccepted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4"
		seedToken(t, pool, token, "run-github-2", "T1567.001")

		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		payload := map[string]any{
			"files": map[string]any{token + ".dat": map[string]string{"content": "x"}},
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/github/gists", bytes.NewReader(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Errorf("status = %d, want 201 -- the auth header is never validated", resp.StatusCode)
		}
		assertReceiptRecorded(t, pool, token, "coderepo-github", len(body))
	})
}
