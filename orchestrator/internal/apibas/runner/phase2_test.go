package runner_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/apibas/catalog"
	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
	"github.com/audspect/bas/internal/apibas/runner"
)

func scenarioByID(t *testing.T, id string) contract.Scenario {
	t.Helper()
	all, err := catalog.All()
	if err != nil {
		t.Fatalf("catalog.All: %v", err)
	}
	for _, s := range all {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("scenario %s not in catalog", id)
	return contract.Scenario{}
}

// runWith runs a scenario with explicit adapters, so a test can remove one.
func runWith(t *testing.T, e *env, s contract.Scenario, state runner.StateReader, reset runner.Resetter) runner.Report {
	t.Helper()
	r, err := runner.New(runner.Config{
		BaseURL: e.url,
		Fixture: e.fx,
		Secrets: e.secrets,
		State:   state,
		Reset:   reset,
	})
	if err != nil {
		t.Fatalf("runner.New: %v", err)
	}
	rep, err := r.Run(context.Background(), s)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return rep
}

// Phase 2 tranche: each scenario must FAIL against the planted flaw and PASS
// against the fixed build, with the same scenario and the same runner.
func TestPhase2_VulnerableFailsFixedPasses(t *testing.T) {
	cases := []struct {
		id     string
		object string // object the scenario targets, to check the fixture binding
	}{
		{"API-BAS-AUTHN-001", "ORD-2001"},
		{"API-BAS-AUTHN-002", "ORD-1001"},
		{"API-BAS-AUTHZ-002", "ORD-2001"},
		{"API-BAS-AUTHZ-003", "ORD-1001"},
	}
	for _, tc := range cases {
		t.Run(tc.id+"/vulnerable", func(t *testing.T) {
			e := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
			s := scenarioByID(t, tc.id)
			if s.Preconditions.Object != tc.object {
				t.Fatalf("scenario targets %s, want %s", s.Preconditions.Object, tc.object)
			}
			rep := e.run(t, s, e.state)
			if rep.Outcome.Result != grade.FAIL || rep.Outcome.Exploitability != grade.Exploited {
				t.Fatalf("got %s / %s (%s), want FAIL / exploited",
					rep.Outcome.Result, rep.Outcome.Exploitability, rep.Outcome.Reason)
			}
		})
		t.Run(tc.id+"/fixed", func(t *testing.T) {
			e := newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
			rep := e.run(t, scenarioByID(t, tc.id), e.state)
			if rep.Outcome.Result != grade.PASS || rep.Outcome.Control != grade.Enforced {
				t.Fatalf("got %s / %s (%s), want PASS / enforced",
					rep.Outcome.Result, rep.Outcome.Control, rep.Outcome.Reason)
			}
		})
	}
}

// AUTHZ-002 mutates state, so the sandbox reset must restore the seed and the
// report must say so.
func TestPhase2_SandboxRunIsResetAfterwards(t *testing.T) {
	e := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
	rep := runWith(t, e, scenarioByID(t, "API-BAS-AUTHZ-002"), e.state, e.admin)
	if rep.Outcome.Result != grade.FAIL {
		t.Fatalf("Result = %s, want FAIL", rep.Outcome.Result)
	}
	if rep.Reset != "ok" {
		t.Errorf("Reset = %q, want ok", rep.Reset)
	}
	state, err := e.admin.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if got := state["ORD-2001"].Status; got != "pending" {
		t.Errorf("ORD-2001 status after cleanup = %q, want seed value pending", got)
	}
}

// A sandbox scenario with no reset adapter cannot be cleaned up, so it must
// not run at all.
func TestPhase2_SandboxWithoutResetIsSkippedWithoutTraffic(t *testing.T) {
	e := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
	rep := runWith(t, e, scenarioByID(t, "API-BAS-AUTHZ-002"), e.state, nil)
	if rep.Outcome.Result != grade.SKIPPED || rep.Outcome.Reason != grade.ReasonAdapterUnavailable {
		t.Fatalf("got %s/%s, want SKIPPED/%s", rep.Outcome.Result, rep.Outcome.Reason, grade.ReasonAdapterUnavailable)
	}
	if n := e.apiHits.Load(); n != 0 {
		t.Errorf("%d API requests sent for an uncleanable sandbox scenario", n)
	}
}

// A property-level claim is about an attacker changing their own object. An
// attacker who does not own the object is a different claim and must not be
// graded under this one.
func TestPhase2_PropertyClaimRequiresOwnerAttacker(t *testing.T) {
	e := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
	s := scenarioByID(t, "API-BAS-AUTHZ-003")
	s.Steps = append([]contract.Step(nil), s.Steps...)
	s.Steps[1].Identity = "customer-b" // not the owner of ORD-1001

	rep := e.run(t, s, e.state)
	if rep.Outcome.Result != grade.SKIPPED || rep.Outcome.Reason != grade.ReasonPreconditionMissing {
		t.Fatalf("got %s/%s, want SKIPPED/%s", rep.Outcome.Result, rep.Outcome.Reason, grade.ReasonPreconditionMissing)
	}
	if n := e.apiHits.Load(); n != 0 {
		t.Errorf("%d API requests sent for a precondition skip", n)
	}
}

// A revoked-token scenario needs the revoked credential. Without it the run is
// a precondition skip, never a pass.
func TestPhase2_MissingRevokedCredentialIsPreconditionSkip(t *testing.T) {
	e := newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
	delete(e.secrets, "apibas/lab/customer-a-revoked")
	rep := e.run(t, scenarioByID(t, "API-BAS-AUTHN-002"), e.state)
	if rep.Outcome.Result != grade.SKIPPED || rep.Outcome.Reason != grade.ReasonPreconditionMissing {
		t.Fatalf("got %s/%s, want SKIPPED/%s", rep.Outcome.Result, rep.Outcome.Reason, grade.ReasonPreconditionMissing)
	}
}

// The revoked-token attack must actually send the revoked credential. A lab
// that ignored the header would make the test vacuous, so this checks the
// request carried the revoked token and was refused.
func TestPhase2_RevokedAttackIsRefusedByFixedBuild(t *testing.T) {
	e := newEnv(t, lab.ModeFixed, fixture.OrdersTwoTenant())
	rep := e.run(t, scenarioByID(t, "API-BAS-AUTHN-002"), e.state)
	attack := rep.Exchanges[len(rep.Exchanges)-1]
	if attack.Auth != "revoked" || attack.Status != 401 {
		t.Fatalf("attack auth=%s status=%d, want revoked / 401", attack.Auth, attack.Status)
	}
}

// The mass-assignment PATCH echoes protected values, so a FAIL could come from
// disclosure alone. This checks the state change itself on the vulnerable build,
// so the grader is not the only evidence that the flaw exists.
func TestPhase2_MassAssignmentChangesOwnerOnlyInVulnerable(t *testing.T) {
	e := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
	tok, err := e.secrets.Resolve("apibas/lab/customer-a")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPatch, e.url+"/api/orders/ORD-1001", strings.NewReader(`{"owner_id": "cust-b"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PATCH: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("vulnerable PATCH status = %d, want 200", resp.StatusCode)
	}
	state, err := e.admin.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if got := state["ORD-1001"].OwnerID; got != "cust-b" {
		t.Errorf("owner after mass assignment = %q, want cust-b", got)
	}
}

// Anonymous attacks must carry no credential at all.
func TestPhase2_AnonymousAttackSendsNoCredential(t *testing.T) {
	e := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
	rep := e.run(t, scenarioByID(t, "API-BAS-AUTHN-001"), e.state)
	attack := rep.Exchanges[len(rep.Exchanges)-1]
	if attack.Auth != "none" || attack.Identity != "anonymous" {
		t.Fatalf("attack auth=%s identity=%s, want none / anonymous", attack.Auth, attack.Identity)
	}
	if attack.Status != 200 {
		t.Fatalf("vulnerable build status for anonymous read = %d, want 200", attack.Status)
	}
}
