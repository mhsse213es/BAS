// orchestrator/internal/api/enroll_csr_handlers_test.go
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/pki"
	"github.com/audspect/bas/internal/pki/pkitest"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// newTestHandlerWithPKI builds a Handler wired with the real shared test
// pool (see testmain_test.go's sharedDB and RunWithPool for the
// container-backed isolation pattern this package already uses, e.g.
// TestEnrollAgent_AuthGate_NoRowCreatedOnFailure in agent_auth_test.go)
// plus a fresh throwaway CA and a known bootstrap secret.
func newTestHandlerWithPKI(t *testing.T, pool *pgxpool.Pool) (*Handler, *pki.CA) {
	t.Helper()
	ca, err := pki.LoadOrGenerateCA(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	h := New(pool, ws.NewHub(), nil, "").
		WithAgentSecret("test-bootstrap-secret").
		WithPKI(ca)
	return h, ca
}

func TestEnrollCSR_ValidBootstrapSecretIssuesCertificate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h, _ := newTestHandlerWithPKI(t, pool)
		csrPEM, err := pkitest.GenerateTestCSR("requested-cn-ignored")
		if err != nil {
			t.Fatalf("GenerateTestCSR: %v", err)
		}
		body, _ := json.Marshal(map[string]string{
			"agentId": "abc123deadbeef01",
			"csrPem":  string(csrPEM),
		})
		req := httptest.NewRequest(http.MethodPost, "/api/agents/enroll-csr", bytes.NewReader(body))
		req.Header.Set("X-Agent-Token", "test-bootstrap-secret")
		rec := httptest.NewRecorder()

		h.EnrollCSR(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			CertPEM string `json:"certPem"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if resp.CertPEM == "" {
			t.Error("response did not include a signed certificate")
		}
	})
}

func TestEnrollCSR_WrongBootstrapSecretRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h, _ := newTestHandlerWithPKI(t, pool)
		csrPEM, _ := pkitest.GenerateTestCSR("cn")
		body, _ := json.Marshal(map[string]string{"agentId": "abc123deadbeef01", "csrPem": string(csrPEM)})
		req := httptest.NewRequest(http.MethodPost, "/api/agents/enroll-csr", bytes.NewReader(body))
		req.Header.Set("X-Agent-Token", "wrong-secret")
		rec := httptest.NewRecorder()

		h.EnrollCSR(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rec.Code)
		}
	})
}

func TestEnrollCSR_RejectsBootstrapForAlreadyEnrolledAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h, _ := newTestHandlerWithPKI(t, pool)
		csrPEM, _ := pkitest.GenerateTestCSR("cn")
		body, _ := json.Marshal(map[string]string{"agentId": "abc123deadbeef01", "csrPem": string(csrPEM)})

		// First bootstrap succeeds.
		req1 := httptest.NewRequest(http.MethodPost, "/api/agents/enroll-csr", bytes.NewReader(body))
		req1.Header.Set("X-Agent-Token", "test-bootstrap-secret")
		rec1 := httptest.NewRecorder()
		h.EnrollCSR(rec1, req1)
		if rec1.Code != http.StatusOK {
			t.Fatalf("first bootstrap: status = %d, body = %s", rec1.Code, rec1.Body.String())
		}

		// Second bootstrap for the SAME agentId, with a fresh CSR, must be
		// rejected -- this identity already holds a valid certificate and must
		// renew via mTLS instead (spec Section 2, "Bootstrap reuse limit").
		csrPEM2, _ := pkitest.GenerateTestCSR("cn2")
		body2, _ := json.Marshal(map[string]string{"agentId": "abc123deadbeef01", "csrPem": string(csrPEM2)})
		req2 := httptest.NewRequest(http.MethodPost, "/api/agents/enroll-csr", bytes.NewReader(body2))
		req2.Header.Set("X-Agent-Token", "test-bootstrap-secret")
		rec2 := httptest.NewRecorder()
		h.EnrollCSR(rec2, req2)

		if rec2.Code != http.StatusConflict {
			t.Errorf("second bootstrap for an already-enrolled agent: status = %d, want 409", rec2.Code)
		}
	})
}

func TestEnrollCSR_MalformedCSRRejectedWith400(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h, _ := newTestHandlerWithPKI(t, pool)
		body, _ := json.Marshal(map[string]string{"agentId": "abc123deadbeef01", "csrPem": "not a csr"})
		req := httptest.NewRequest(http.MethodPost, "/api/agents/enroll-csr", bytes.NewReader(body))
		req.Header.Set("X-Agent-Token", "test-bootstrap-secret")
		rec := httptest.NewRecorder()

		h.EnrollCSR(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
	})
}
