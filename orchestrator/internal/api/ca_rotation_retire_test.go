package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"encoding/pem"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/pki"
	"github.com/audspect/bas/internal/ws"
)

func caKeyIDHex(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.SubjectKeyId) == 0 {
		t.Fatal("test CA has no SubjectKeyId; the retire check cannot work without one")
	}
	return hex.EncodeToString(c.SubjectKeyId)
}

type retireStatus struct {
	State          string   `json:"state"`
	Ready          bool     `json:"readyToRetire"`
	OnNew          int      `json:"agentsOnNewCA"`
	Total          int      `json:"agentsTotal"`
	Pending        []string `json:"agentsPendingRenewal"`
	NewCAKeyID     string   `json:"newCAKeyId"`
	ReadyToPromote *bool    `json:"readyToPromote"`
}

func getRetireStatus(t *testing.T, h *Handler) retireStatus {
	t.Helper()
	rec := httptest.NewRecorder()
	rotationRouter(h).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/ca-rotation/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var out retireStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// After promote, retire is only safe once every agent that can still connect presents a certificate from the
// new CA. An agent whose issuer is unknown counts as still pending: retiring early locks it out.
func TestCARotationStatus_ReadyToRetireOnlyWhenEveryAgentHoldsANewCACert(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h, dir := rotationHandler(t, pool, ws.NewHub())
		if _, err := pki.StartRotation(dir, time.Now()); err != nil {
			t.Fatal(err)
		}
		if _, err := pki.PromoteRotation(dir, time.Now()); err != nil {
			t.Fatal(err)
		}
		newID := caKeyIDHex(t, filepath.Join(dir, "ca-cert.pem"))
		oldID := caKeyIDHex(t, filepath.Join(dir, "previous-ca-cert.pem"))
		for _, id := range []string{revAgentA, revAgentB} {
			seedAgentRow(t, pool, id)
		}
		set := func(agent, issuer string) {
			if _, err := pool.Exec(context.Background(), `UPDATE agents SET cert_issuer_key_id=$2 WHERE agent_id=$1`, agent, issuer); err != nil {
				t.Fatal(err)
			}
		}

		st := getRetireStatus(t, h)
		if st.State != "promoted" || st.Ready || st.OnNew != 0 || st.Total != 2 || st.NewCAKeyID != newID {
			t.Fatalf("status = %+v, want promoted, not ready, 0 of 2 on the new CA, key id %s", st, newID)
		}
		if st.ReadyToPromote != nil {
			t.Errorf("readyToPromote must only be reported while prepared, got %v", *st.ReadyToPromote)
		}

		set(revAgentA, newID)
		set(revAgentB, oldID)
		st = getRetireStatus(t, h)
		if st.Ready || st.OnNew != 1 || len(st.Pending) != 1 || st.Pending[0] != revAgentB {
			t.Fatalf("status = %+v, want B pending (still holds an old-CA certificate)", st)
		}

		set(revAgentB, newID)
		if st = getRetireStatus(t, h); !st.Ready || st.OnNew != 2 {
			t.Fatalf("status = %+v, want ready with both agents on the new CA", st)
		}

		// A revoked agent can no longer connect and must not block the retire.
		seedAgentRow(t, pool, "abc123deadbeef09")
		_, _ = pool.Exec(context.Background(), `UPDATE agents SET state='revoked' WHERE agent_id=$1`, "abc123deadbeef09")
		if st = getRetireStatus(t, h); !st.Ready || st.Total != 2 {
			t.Fatalf("status = %+v, a revoked agent must not count", st)
		}

		// With no agents there is nothing to verify; that is not "ready".
		_, _ = pool.Exec(context.Background(), `UPDATE agents SET state='revoked'`)
		if st = getRetireStatus(t, h); st.Ready {
			t.Fatalf("status = %+v, zero agents must not read as ready to retire", st)
		}
	})
}

func TestPeerIssuerKeyID(t *testing.T) {
	if got := peerIssuerKeyID(httptest.NewRequest(http.MethodGet, "/", nil)); got != "" {
		t.Errorf("no TLS = %q, want empty", got)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.TLS = &tls.ConnectionState{}
	if got := peerIssuerKeyID(r); got != "" {
		t.Errorf("no peer certificate = %q, want empty", got)
	}
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{AuthorityKeyId: []byte{0xab, 0xcd}}}}
	if got := peerIssuerKeyID(r); got != "abcd" {
		t.Errorf("issuer key id = %q, want abcd", got)
	}
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}
	if got := peerIssuerKeyID(r); got != "" {
		t.Errorf("certificate without an authority key id = %q, want empty (unknown, never a guess)", got)
	}
}
