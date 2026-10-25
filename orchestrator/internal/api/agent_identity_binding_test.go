package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/ws"
)

// withCertIdentity simulates a request that arrived on the mTLS listener with a verified certificate for id.
func withCertIdentity(r *http.Request, id string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxKeyAuthenticatedAgentID, id))
}

func TestAgentMatchesCertificate(t *testing.T) {
	cases := []struct {
		name, cert, claimed string
		ok                  bool
	}{
		{"same agent", "abc123deadbeef01", "abc123deadbeef01", true},
		{"another agent's ID", "abc123deadbeef01", "abc123deadbeef02", false},
		{"no certificate (legacy listener)", "", "abc123deadbeef02", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/x", nil)
			if tc.cert != "" {
				r = withCertIdentity(r, tc.cert)
			}
			rec := httptest.NewRecorder()
			if got := agentMatchesCertificate(rec, r, tc.claimed); got != tc.ok {
				t.Fatalf("got %v, want %v", got, tc.ok)
			}
			if !tc.ok && rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rec.Code)
			}
		})
	}
}

// Every agent route that takes an AgentID from the request must refuse a certificate for a different
// agent (audit F-02). The handlers have no database here: the refusal has to come before any use of it.
func TestAgentRoutes_RefuseAnotherAgentsCertificate(t *testing.T) {
	h := New(nil, ws.NewHub(), nil, "").WithAgentSecret("s")
	const mine, theirs = "abc123deadbeef01", "abc123deadbeef02"
	routes := []struct {
		name    string
		method  string
		path    string // chi pattern
		url     string
		body    string
		handler http.HandlerFunc
	}{
		{"heartbeat", "POST", "/api/heartbeat", "/api/heartbeat", `{"agentId":"` + theirs + `"}`, h.Heartbeat},
		{"unenroll", "POST", "/api/agents/unenroll", "/api/agents/unenroll", `{"agentId":"` + theirs + `"}`, h.UnenrollAgent},
		{"enroll", "POST", "/api/agents/enroll", "/api/agents/enroll", `{"agentId":"` + theirs + `","hostname":"h"}`, h.EnrollAgent},
		{"uninstall-result", "POST", "/api/agents/{agentId}/uninstall-result", "/api/agents/" + theirs + "/uninstall-result", `{"success":true}`, h.UninstallAgentResult},
		{"log events", "POST", "/api/agents/events", "/api/agents/events", `{"events":[{"event_type":"op_log","agent_id":"` + theirs + `","payload":{}}]}`, h.ReceiveEvents},
		{"host events", "POST", "/api/scenarios/runs/{runId}/host-events", "/api/scenarios/runs/r1/host-events", `{"agentId":"` + theirs + `","events":[]}`, h.SubmitRunHostEvents},
		{"sharphound", "POST", "/api/attackpath/sharphound", "/api/attackpath/sharphound?agentId=" + theirs + "&hostname=h", `zip`, h.SubmitAttackPathSharpHound},
		{"attack-path collect", "POST", "/api/attackpath/collect", "/api/attackpath/collect", `{"agentId":"` + theirs + `"}`, h.SubmitAttackPathCollection},
	}
	for _, rt := range routes {
		t.Run(rt.name, func(t *testing.T) {
			router := chi.NewRouter()
			router.MethodFunc(rt.method, rt.path, rt.handler)
			req := httptest.NewRequest(rt.method, rt.url, bytes.NewBufferString(rt.body))
			req.Header.Set("X-Agent-Token", "s")
			req = withCertIdentity(req, mine)
			rec := httptest.NewRecorder()
			func() {
				defer func() { recover() }() // a nil-database panic means the check came too late; the status assert reports it
				router.ServeHTTP(rec, req)
			}()
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 (body: %s)", rec.Code, rec.Body.String())
			}
		})
	}
}
