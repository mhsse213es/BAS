package runner_test

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/apibas/catalog"
	"github.com/audspect/bas/internal/apibas/detect"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// Phase 4 closure: the detection gaps left after batches 4a and 4b. Expectations, written before the run:
//
//   DET-004  vulnerable FAIL/exploited, fixed PASS/enforced. REL-010 (correlated across identities) detected in both.
//   DET-006  a healthy control (owner reads of own orders) raises no alert. An unhealthy control (a foreign read) must
//            raise REL-004. The healthy control alone cannot show the detector works.
//   DET-008  an alert names the affected resource: its action path, its requesting identity and the owners it named.
//   DET-010  an alert can be traced to retained access events: the trigger event is one of the run's retained events,
//            and its action matches the alert's.
//   sweep    every catalogued scenario has an explicit detection status. A fixture_validated scenario declares a
//            detection block. A not_evaluated scenario states a reason and declares none. The two never mix.

// detBlueprintIDs are the ten DET IDs of the blueprint (docs/api-bas-blueprint.md, section DET).
var detBlueprintIDs = []string{
	"API-BAS-DET-001", "API-BAS-DET-002", "API-BAS-DET-003", "API-BAS-DET-004", "API-BAS-DET-005",
	"API-BAS-DET-006", "API-BAS-DET-007", "API-BAS-DET-008", "API-BAS-DET-009", "API-BAS-DET-010",
}

// TestPhase4_DET004CrossIdentityCorrelation runs two identities reading each other's orders in one run.
func TestPhase4_DET004CrossIdentityCorrelation(t *testing.T) {
	if testing.Short() {
		t.Skip("Phase 4 closure run skipped in -short mode")
	}
	fx := fixtureFor(t, "orders-two-tenant")
	s := scenarioByID(t, "API-BAS-DET-004")
	for _, mode := range []lab.Mode{lab.ModeVulnerable, lab.ModeFixed} {
		e := newEnvFaults(t, mode, fx, s.Preconditions.LabFaults)
		o := e.run(t, s, e.state).Outcome
		if mode == lab.ModeVulnerable {
			if o.Result != grade.FAIL || o.Exploitability != grade.Exploited {
				t.Errorf("DET-004 vulnerable: %s/%s (%s), want FAIL/exploited", o.Result, o.Exploitability, o.Reason)
			}
		} else if o.Result != grade.PASS || o.Control != grade.Enforced {
			t.Errorf("DET-004 fixed: %s/%s (%s), want PASS/enforced", o.Result, o.Control, o.Reason)
		}
		if o.Detection != detect.Detected {
			t.Errorf("DET-004 %s: REL-010 %q, want detected", modeName(mode), o.Detection)
		}
	}
}

// TestPhase4_DET006HealthyAndUnhealthyControls sends benign traffic and one foreign read through the lab, then grades
// the retained events. Benign traffic must raise nothing. The foreign read must raise REL-004 (unhealthy control).
func TestPhase4_DET006HealthyAndUnhealthyControls(t *testing.T) {
	if testing.Short() {
		t.Skip("Phase 4 closure run skipped in -short mode")
	}
	fx := fixtureFor(t, "orders-two-tenant")
	e := newEnvFaults(t, lab.ModeFixed, fx, nil)
	ctx := context.Background()

	send := func(tag, customer, path string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, e.url+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+e.secrets["apibas/lab/"+customer])
		req.Header.Set("X-BAS-Run", tag)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("send: %v", err)
		}
		resp.Body.Close()
	}
	alertsFor := func(tag string) []detect.Alert {
		t.Helper()
		events, err := e.admin.AccessEvents(ctx, tag)
		if err != nil {
			t.Fatalf("AccessEvents: %v", err)
		}
		if len(events) == 0 {
			t.Fatalf("no access events retained for %s", tag)
		}
		f := detect.NewElasticFixture()
		if err := f.Ingest(events); err != nil {
			t.Fatalf("ingest: %v", err)
		}
		return f.Alerts(tag)
	}

	// Healthy control: owner reads, kept under the burst threshold so only the behaviour under test is measured.
	healthy := randomToken(t)
	for i := 0; i < detect.BurstThreshold-1; i++ {
		send(healthy, "customer-b", "/api/orders/ORD-2001")
	}
	if got := alertsFor(healthy); len(got) != 0 {
		t.Errorf("healthy traffic raised %d alerts (%v), want none", len(got), got)
	}

	// Measured false positive (DET-006): the same benign reads at volume reach the burst threshold. REL-005 counts
	// requests regardless of outcome, so ordinary volume alerts. This is recorded as a finding, not hidden.
	volume := randomToken(t)
	for i := 0; i < 2*detect.BurstThreshold; i++ {
		send(volume, "customer-b", "/api/orders/ORD-2001")
	}
	for _, a := range alertsFor(volume) {
		if a.RuleID != "APIBAS-REL-005" {
			t.Errorf("benign volume raised %s, want only the volume rule REL-005", a.RuleID)
		}
	}
	t.Logf("DET-006 finding: %d benign owner reads raised REL-005 (burst threshold %d)", 2*detect.BurstThreshold, detect.BurstThreshold)

	unhealthy := randomToken(t)
	send(unhealthy, "customer-a", "/api/orders/ORD-2001")
	found := false
	for _, a := range alertsFor(unhealthy) {
		if a.RuleID == "APIBAS-REL-004" {
			found = true
		}
	}
	if !found {
		t.Error("unhealthy control (foreign read) did not raise REL-004: the detector is silent")
	}
}

// TestPhase4_DET008DET010AlertsTraceToEvidence runs the cross-customer read in the vulnerable build and checks that the
// alert names the affected resource and traces to a retained event.
func TestPhase4_DET008DET010AlertsTraceToEvidence(t *testing.T) {
	if testing.Short() {
		t.Skip("Phase 4 closure run skipped in -short mode")
	}
	fx := fixtureFor(t, "orders-two-tenant")
	s := scenarioByID(t, "API-BAS-DET-005")
	e := newEnvFaults(t, lab.ModeVulnerable, fx, s.Preconditions.LabFaults)
	rep := e.run(t, s, e.state)
	if rep.RunTag == "" {
		t.Fatal("report has no run tag")
	}
	events, err := e.admin.AccessEvents(context.Background(), rep.RunTag)
	if err != nil {
		t.Fatalf("AccessEvents: %v", err)
	}
	f := detect.NewElasticFixture()
	if err := f.Ingest(events); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	var alert *detect.Alert
	for _, a := range f.Alerts(rep.RunTag) {
		if a.RuleID == "APIBAS-REL-004" {
			alert = &a
		}
	}
	if alert == nil {
		t.Fatal("REL-004 did not fire on the cross-customer read")
	}
	// DET-008: the alert names the affected resource.
	if !strings.Contains(alert.Action, "/api/orders/ORD-2001") {
		t.Errorf("DET-008: alert action %q does not name the affected order ORD-2001", alert.Action)
	}
	if !slices.Contains(alert.Owners, "cust-b") {
		t.Errorf("DET-008: alert owners %v do not name the affected owner cust-b", alert.Owners)
	}
	if alert.Identity != "cust-a" {
		t.Errorf("DET-008: alert identity %q, want the verified customer identity cust-a", alert.Identity)
	}
	// DET-010: the trigger event is retained and matches the alert.
	trigger := -1
	for i, ev := range events {
		if ev.Seq == alert.TriggerSeq {
			trigger = i
		}
	}
	if trigger < 0 {
		t.Fatalf("DET-010: trigger seq %d is not among the %d retained events", alert.TriggerSeq, len(events))
	}
	if events[trigger].Action != alert.Action || events[trigger].CorrelationID != rep.RunTag {
		t.Errorf("DET-010: retained trigger event %+v does not match the alert", events[trigger])
	}
}

// TestPhase4_DetectionStatusSweep checks every catalogued scenario carries an explicit detection status, and that
// not_evaluated and a detection result never mix. It also counts each DET ID's coverage: at most one scenario each.
func TestPhase4_DetectionStatusSweep(t *testing.T) {
	all, err := catalog.All()
	if err != nil {
		t.Fatalf("catalog.All: %v", err)
	}
	validated, notEvaluated := 0, 0
	covered := map[string]string{}
	scenarioIDs := map[string]bool{}
	for _, s := range all {
		scenarioIDs[s.ID] = true
	}
	for _, s := range all {
		switch s.DetectionAssert.Status {
		case "fixture_validated":
			validated++
			if s.Detection == nil {
				t.Errorf("%s: fixture_validated without a detection block", s.ID)
			}
		case "not_evaluated":
			notEvaluated++
			if s.Detection != nil {
				t.Errorf("%s: not_evaluated but declares a detection block", s.ID)
			}
			if strings.TrimSpace(s.DetectionAssert.Reason) == "" {
				t.Errorf("%s: not_evaluated without a reason", s.ID)
			}
		default:
			t.Errorf("%s: detection status %q is neither fixture_validated nor not_evaluated", s.ID, s.DetectionAssert.Status)
		}
		// A DET-category scenario grades its own DET ID. Naming another scenario's DET ID in detection_covers would
		// count that ID twice.
		if strings.HasPrefix(s.ID, "API-BAS-DET-") && s.Detection != nil {
			covered[s.ID] = s.ID
		}
		for _, det := range s.DetectionCovers {
			if scenarioIDs[det] {
				t.Errorf("%s names %s in detection_covers, but %s is a scenario that grades itself", s.ID, det, det)
			}
			if prev, ok := covered[det]; ok {
				t.Errorf("%s is covered by both %s and %s: coverage counted twice", det, prev, s.ID)
			}
			covered[det] = s.ID
		}
	}
	// DET IDs that are not catalogue scenarios are graded by a named acceptance test in this package.
	testGraded := map[string]string{
		"API-BAS-DET-001": "TestPhase34_DetectionMatchesDeclaredExpectations (declared attacks only; see sweep counts)",
		"API-BAS-DET-006": "TestPhase4_DET006HealthyAndUnhealthyControls",
		"API-BAS-DET-008": "TestPhase4_DET008DET010AlertsTraceToEvidence",
		"API-BAS-DET-010": "TestPhase4_DET008DET010AlertsTraceToEvidence",
	}
	for _, det := range detBlueprintIDs {
		if _, ok := covered[det]; ok {
			continue
		}
		if by, ok := testGraded[det]; ok {
			t.Logf("DET coverage: %s graded by %s", det, by)
			continue
		}
		t.Errorf("DET coverage: %s has no scenario and no named test", det)
	}
	t.Logf("detection status: %d scenarios fixture_validated, %d not_evaluated, %d DET IDs covered by a scenario",
		validated, notEvaluated, len(covered))
}
