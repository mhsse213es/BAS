package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/pki/pkitest"
)

func tokenRouter(h *Handler) http.Handler {
	r := chi.NewRouter()
	r.Post("/api/enrollment-tokens", h.CreateEnrollmentToken)
	r.Get("/api/enrollment-tokens", h.ListEnrollmentTokens)
	r.Delete("/api/enrollment-tokens/{id}", h.RevokeEnrollmentToken)
	return r
}

type issuedToken struct {
	Token     string `json:"token"`
	ID        string `json:"id"`
	AgentID   string `json:"agentId"`
	ExpiresAt string `json:"expiresAt"`
}

func issueToken(t *testing.T, h *Handler, body map[string]any) (issuedToken, int) {
	t.Helper()
	b, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	tokenRouter(h).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/enrollment-tokens", bytes.NewReader(b)))
	var out issuedToken
	json.Unmarshal(rec.Body.Bytes(), &out)
	return out, rec.Code
}

// enrollWith bootstraps agentID presenting only the given enrolment token and/or shared secret.
func enrollWith(t *testing.T, h *Handler, agentID, token, secret string) int {
	t.Helper()
	csr, _ := pkitest.GenerateTestCSR("ignored")
	body, _ := json.Marshal(map[string]string{"agentId": agentID, "csrPem": string(csr)})
	req := httptest.NewRequest(http.MethodPost, "/api/agents/enroll-csr", bytes.NewReader(body))
	req.RemoteAddr = "203.0.113.9:5555"
	if token != "" {
		req.Header.Set("X-Enrollment-Token", token)
	}
	if secret != "" {
		req.Header.Set("X-Agent-Token", secret)
	}
	rec := httptest.NewRecorder()
	h.EnrollCSR(rec, req)
	return rec.Code
}

func tokenHandler(t *testing.T, pool *pgxpool.Pool) *Handler {
	h, _ := newTestHandlerWithPKI(t, pool)
	return h.WithEnrollmentMode("token")
}

func TestEnrollmentToken_IsSingleUseAndBoundToItsAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := tokenHandler(t, pool)

		// In token mode the shared secret alone must not enrol anyone.
		if c := enrollWith(t, h, revAgentA, "", "test-bootstrap-secret"); c != http.StatusUnauthorized {
			t.Errorf("shared secret in token mode = %d, want 401", c)
		}
		if c := enrollWith(t, h, revAgentA, "", ""); c != http.StatusUnauthorized {
			t.Errorf("no credential in token mode = %d, want 401", c)
		}

		tok, code := issueToken(t, h, map[string]any{"agentId": revAgentA})
		if code != http.StatusOK || tok.Token == "" {
			t.Fatalf("issue = %d, token %q", code, tok.Token)
		}
		// A token for agent A must not enrol agent B, and a refusal must not consume it.
		if c := enrollWith(t, h, revAgentB, tok.Token, ""); c != http.StatusUnauthorized {
			t.Errorf("token used for another agent = %d, want 401", c)
		}
		if c := enrollWith(t, h, revAgentA, tok.Token, ""); c != http.StatusOK {
			t.Fatalf("valid token = %d, want 200 (a refused attempt for another agent must not burn it)", c)
		}
		// Reuse is refused, including after the first certificate expired.
		pool.Exec(context.Background(), `UPDATE agent_certificates SET expires_at = NOW() - interval '1 hour' WHERE agent_id = $1`, revAgentA)
		if c := enrollWith(t, h, revAgentA, tok.Token, ""); c != http.StatusUnauthorized {
			t.Errorf("replay of a consumed token = %d, want 401", c)
		}
	})
}

func TestEnrollmentToken_ExpiredAndRevokedAreRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := tokenHandler(t, pool)
		expired, _ := issueToken(t, h, map[string]any{"agentId": revAgentA})
		pool.Exec(context.Background(), `UPDATE agent_enrollment_tokens SET expires_at = NOW() - interval '1 minute' WHERE id::text = $1`, expired.ID)
		if c := enrollWith(t, h, revAgentA, expired.Token, ""); c != http.StatusUnauthorized {
			t.Errorf("expired token = %d, want 401", c)
		}

		revoked, _ := issueToken(t, h, map[string]any{"agentId": revAgentB})
		rec := httptest.NewRecorder()
		tokenRouter(h).ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/enrollment-tokens/"+revoked.ID, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("revoke token = %d", rec.Code)
		}
		if c := enrollWith(t, h, revAgentB, revoked.Token, ""); c != http.StatusUnauthorized {
			t.Errorf("revoked token = %d, want 401", c)
		}
	})
}

func TestEnrollmentToken_StoredOnlyAsHashAndNeverListed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := tokenHandler(t, pool)
		tok, _ := issueToken(t, h, map[string]any{"agentId": revAgentA, "note": "finance laptop"})
		var stored string
		if err := pool.QueryRow(context.Background(), `SELECT token_hash FROM agent_enrollment_tokens WHERE id::text = $1`, tok.ID).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(tok.Token))
		if stored != hex.EncodeToString(sum[:]) {
			t.Error("the table should hold the SHA-256 of the token")
		}
		rec := httptest.NewRecorder()
		tokenRouter(h).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/enrollment-tokens", nil))
		if strings.Contains(rec.Body.String(), tok.Token) || strings.Contains(rec.Body.String(), stored) {
			t.Error("the listing must not reveal the token or its hash")
		}
		if !strings.Contains(rec.Body.String(), revAgentA) {
			t.Error("the listing should show the agent the token is for")
		}
		if len(tok.Token) < 40 {
			t.Errorf("token too short (%d chars) to carry 256 bits of randomness", len(tok.Token))
		}
	})
}

func TestEnrollmentToken_IssueByHostnameUsesTheAgentIDDerivation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := tokenHandler(t, pool)
		tok, code := issueToken(t, h, map[string]any{"hostname": "FIN-LAPTOP-07"})
		if code != http.StatusOK {
			t.Fatalf("issue by hostname = %d", code)
		}
		// agent/identity.go: hex(SHA-256(hostname))[:16], with the hostname exactly as the OS reports it.
		sum := sha256.Sum256([]byte("FIN-LAPTOP-07"))
		if want := hex.EncodeToString(sum[:])[:16]; tok.AgentID != want {
			t.Errorf("agentId = %s, want %s", tok.AgentID, want)
		}
		bad := map[string]map[string]any{
			"neither":      {},
			"both":         {"agentId": revAgentA, "hostname": "x"},
			"malformed id": {"agentId": "NOT-HEX"},
			"ttl too long": {"agentId": revAgentA, "ttlHours": 24 * 365},
			"negative ttl": {"agentId": revAgentA, "ttlHours": -1},
		}
		for name, body := range bad {
			if _, c := issueToken(t, h, body); c != http.StatusBadRequest {
				t.Errorf("%s = %d, want 400", name, c)
			}
		}
	})
}

func TestEnrollmentToken_RepeatedFailuresFromOneAddressAreThrottled(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := tokenHandler(t, pool)
		var last int
		for i := 0; i < 30; i++ {
			last = enrollWith(t, h, revAgentA, "wrong-token-"+strings.Repeat("x", i), "")
		}
		if last != http.StatusTooManyRequests {
			t.Errorf("after 30 bad tokens from one address the response was %d, want 429", last)
		}
	})
}

func bulkRequest(h *Handler, body map[string]any, query string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	r.Post("/api/enrollment-tokens/bulk", h.BulkCreateEnrollmentTokens)
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/enrollment-tokens/bulk"+query, bytes.NewReader(b)))
	return rec
}

func TestEnrollmentTokenBulk_OneTokenPerHostnameEachWorksForItsOwnAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := tokenHandler(t, pool)
		hosts := []string{"FIN-01", "FIN-02", "HR-LAPTOP-9", "FIN-01"} // one duplicate
		rec := bulkRequest(h, map[string]any{"hostnames": hosts, "note": "Q4 rollout"}, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("bulk = %d: %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Tokens []struct {
				Hostname string `json:"hostname"`
				AgentID  string `json:"agentId"`
				Token    string `json:"token"`
			} `json:"tokens"`
			Duplicates []string `json:"duplicates"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out.Tokens) != 3 || len(out.Duplicates) != 1 || out.Duplicates[0] != "FIN-01" {
			t.Fatalf("tokens=%d duplicates=%v, want 3 tokens and FIN-01 reported as a duplicate", len(out.Tokens), out.Duplicates)
		}
		seen := map[string]bool{}
		for _, tk := range out.Tokens {
			if tk.AgentID != agentIDForHostname(tk.Hostname) {
				t.Errorf("%s: agentId %s does not match the agent's derivation", tk.Hostname, tk.AgentID)
			}
			if seen[tk.Token] || tk.Token == "" {
				t.Errorf("%s: token missing or repeated", tk.Hostname)
			}
			seen[tk.Token] = true
		}
		// Each token enrols its own agent and nobody else's.
		first, second := out.Tokens[0], out.Tokens[1]
		if c := enrollWith(t, h, second.AgentID, first.Token, ""); c != http.StatusUnauthorized {
			t.Errorf("a token used for a different host = %d, want 401", c)
		}
		if c := enrollWith(t, h, first.AgentID, first.Token, ""); c != http.StatusOK {
			t.Errorf("a token used for its own host = %d, want 200", c)
		}
	})
}

func TestEnrollmentTokenBulk_IsAllOrNothingAndBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := tokenHandler(t, pool)
		count := func() int {
			var n int
			pool.QueryRow(context.Background(), `SELECT count(*) FROM agent_enrollment_tokens`).Scan(&n)
			return n
		}
		tooMany := make([]string, 501)
		for i := range tooMany {
			tooMany[i] = "host-" + strings.Repeat("x", i%5) + string(rune('a'+i%26)) + strings.Repeat("y", i/26)
		}
		bad := map[string]map[string]any{
			"empty list":  {"hostnames": []string{}},
			"blank name":  {"hostnames": []string{"ok-host", "   "}},
			"too many":    {"hostnames": tooMany},
			"ttl too big": {"hostnames": []string{"a"}, "ttlHours": 24 * 365},
		}
		for name, body := range bad {
			if c := bulkRequest(h, body, "").Code; c != http.StatusBadRequest {
				t.Errorf("%s = %d, want 400", name, c)
			}
		}
		if n := count(); n != 0 {
			t.Errorf("%d tokens were created by rejected requests, want none", n)
		}
	})
}

func TestEnrollmentTokenBulk_CSVForHandingOut(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := tokenHandler(t, pool)
		rec := bulkRequest(h, map[string]any{"hostnames": []string{"FIN-01", "FIN-02"}}, "?format=csv")
		if rec.Code != http.StatusOK {
			t.Fatalf("csv = %d", rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
			t.Errorf("Content-Type = %q", ct)
		}
		if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
			t.Errorf("Cache-Control = %q, tokens must not be cached", cc)
		}
		lines := strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
		if len(lines) != 3 || !strings.HasPrefix(lines[0], "hostname,agentId,token,expiresAt") {
			t.Errorf("unexpected CSV:\n%s", rec.Body.String())
		}
	})
}
