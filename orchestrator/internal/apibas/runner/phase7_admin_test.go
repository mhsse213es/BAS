package runner_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/lab"
)

// Administrative access to the NBFC pack. The administrator reaches an administrative route only with the administrator role
// and the route's grant. Every attempt is audited with the identity, role, action, target, grant and outcome. The vulnerable
// build keeps the weakness the scenario AUTHZ-106 tests: it does not check the role or the grant.

// adminCall sends one request as the named identity and returns the status and body.
func adminCall(t *testing.T, e *env, identity, method, path string) (int, string) {
	t.Helper()
	tok, err := e.secrets.Resolve("apibas/lab/" + identity)
	if err != nil {
		t.Fatalf("%s token: %v", identity, err)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, e.srv.URL+path, strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", identity, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// auditFor returns the audit records that name one identity and one target.
func auditFor(t *testing.T, e *env, identity, target string) []map[string]any {
	t.Helper()
	all, err := e.admin.NBFCAudit(context.Background())
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	var out []map[string]any
	for _, rec := range all {
		if rec["identity"] == identity && rec["target"] == target {
			out = append(out, rec)
		}
	}
	return out
}

// The fixed build serves an authorized administrator, with the public projection only, and audits the allowed attempt.
func TestPhase7_AdminAuthorizedSucceedsFixed(t *testing.T) {
	e := newEnvWith(t, lab.ModeFixed, fixture.NBFCTwoBorrower(), nil, false)
	status, body := adminCall(t, e, "nbfc-admin", http.MethodGet, "/api/nbfc/admin/loans/LOAN-B-001")
	if status != http.StatusOK {
		t.Fatalf("authorized administrator: status %d, want 200 (%s)", status, body)
	}
	if strings.Contains(body, "BAS-SIM-LOAN-B-ACC") {
		t.Error("the administrative loan read returned a protected field; the administrator's projection is public only")
	}
	recs := auditFor(t, e, "nbfc-admin", "LOAN-B-001")
	if len(recs) != 1 || recs[0]["outcome"] != "allowed" || recs[0]["role"] != "administrator" || recs[0]["permission"] != "loans:read" {
		t.Errorf("audit for the authorized read: %+v, want one allowed record with role administrator and grant loans:read", recs)
	}
}

// An administrator without the grant for the route is refused, and the refusal is audited.
func TestPhase7_AdminWithoutGrantDeniedFixed(t *testing.T) {
	e := newEnvWith(t, lab.ModeFixed, fixture.NBFCTwoBorrower(), nil, false)
	status, _ := adminCall(t, e, "nbfc-admin", http.MethodGet, "/api/nbfc/admin/kyc/KYC-B-001")
	if status != http.StatusForbidden {
		t.Fatalf("administrator without kyc:read: status %d, want 403", status)
	}
	recs := auditFor(t, e, "nbfc-admin", "KYC-B-001")
	if len(recs) != 1 || recs[0]["outcome"] != "denied" || recs[0]["reason"] != "policy" {
		t.Errorf("audit for the refused KYC read: %+v, want one denied record for policy", recs)
	}
}

// An ordinary borrower is refused on the administrative route in the fixed build, and the refusal is audited with the
// borrower's role.
func TestPhase7_BorrowerDeniedFixed(t *testing.T) {
	e := newEnvWith(t, lab.ModeFixed, fixture.NBFCTwoBorrower(), nil, false)
	status, body := adminCall(t, e, "borrower-a", http.MethodGet, "/api/nbfc/admin/loans/LOAN-B-001")
	if status != http.StatusForbidden {
		t.Fatalf("borrower: status %d, want 403 (%s)", status, body)
	}
	if strings.Contains(body, "BAS-SIM-LOAN-B-ACC") {
		t.Error("the refused borrower received a protected value")
	}
	recs := auditFor(t, e, "borrower-a", "LOAN-B-001")
	if len(recs) != 1 || recs[0]["outcome"] != "denied" || recs[0]["role"] != "borrower" {
		t.Errorf("audit for the borrower's attempt: %+v, want one denied record with role borrower", recs)
	}
}

// The vulnerable build keeps the weakness: a borrower reads the protected loan through the administrative route. The audit
// shows the attempt as allowed, which is what the build did.
func TestPhase7_BorrowerAllowedVulnerable(t *testing.T) {
	e := newEnvWith(t, lab.ModeVulnerable, fixture.NBFCTwoBorrower(), nil, false)
	status, body := adminCall(t, e, "borrower-a", http.MethodGet, "/api/nbfc/admin/loans/LOAN-B-001")
	if status != http.StatusOK || !strings.Contains(body, "BAS-SIM-LOAN-B-ACC") {
		t.Fatalf("vulnerable build: status %d, body %s; want 200 with the protected value", status, body)
	}
	recs := auditFor(t, e, "borrower-a", "LOAN-B-001")
	if len(recs) != 1 || recs[0]["outcome"] != "allowed" {
		t.Errorf("audit for the vulnerable attempt: %+v, want one allowed record", recs)
	}
}

// The audit trail is written for every attempt, in order, and names the identity each time.
func TestPhase7_AuditRecordsEveryAttempt(t *testing.T) {
	e := newEnvWith(t, lab.ModeFixed, fixture.NBFCTwoBorrower(), nil, false)
	adminCall(t, e, "nbfc-admin", http.MethodGet, "/api/nbfc/admin/loans/LOAN-A-001")
	adminCall(t, e, "borrower-b", http.MethodGet, "/api/nbfc/admin/loans/LOAN-B-001")
	all, err := e.admin.NBFCAudit(context.Background())
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("audit has %d records, want 2: %+v", len(all), all)
	}
	if all[0]["identity"] != "nbfc-admin" || all[0]["outcome"] != "allowed" || all[1]["identity"] != "borrower-b" || all[1]["outcome"] != "denied" {
		t.Errorf("audit order or content wrong: %+v", all)
	}
}
