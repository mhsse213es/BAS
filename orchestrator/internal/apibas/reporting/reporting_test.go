package reporting

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/apibas/grade"
)

var noticed = time.Date(2026, 10, 21, 8, 0, 0, 0, time.UTC)

// cert is the candidate CERT-In obligation: six hours from awareness. The deadline is a scenario parameter, not engine
// behaviour, so the tests pass it in.
var cert = Policy{Incident: "INC-1", Obligations: []Obligation{{ID: "CERT-6H", Recipient: "cert-in-receiver", Deadline: "6h", ProvisionRef: "IN-CERTIN-70B-II"}}}

// pol names INC-1 as the incident and gives the obligations.
func pol(obs ...Obligation) Policy { return Policy{Incident: "INC-1", Obligations: obs} }

func incident() Evidence {
	return Evidence{Incidents: []Incident{{ID: "INC-1", Category: "cyber", NoticedAt: noticed, Eligible: true}}}
}

// complete is a dispatch with every evidence field present.
func complete(recipient string, at time.Time) Dispatch {
	return Dispatch{
		IncidentID: "INC-1", Recipient: recipient, Status: StatusDispatched, DispatchedAt: at,
		ReportHash: "sha256:abc", ReceiptRef: "SIM-RCPT-1", Mode: ModeSimulated,
	}
}

func withDispatch(ev Evidence, d Dispatch) Evidence {
	ev.Dispatches = append(ev.Dispatches, d)
	return ev
}

func expect(t *testing.T, name string, got Result, want grade.Result, reason string) {
	t.Helper()
	if got.Outcome.Result != want {
		t.Errorf("%s: result %s, want %s (%s)", name, got.Outcome.Result, want, got.Reason)
	}
	if got.Reason != reason {
		t.Errorf("%s: reason %q, want %q", name, got.Reason, reason)
	}
}

func TestOnTimeCompleteDispatchPasses(t *testing.T) {
	ev := withDispatch(incident(), complete("cert-in-receiver", noticed.Add(time.Hour)))
	got := Evaluate(cert, ev)
	expect(t, "on time", got, grade.PASS, "")
	if got.Mode != ModeSimulated {
		t.Errorf("simulated dispatch reported mode %s", got.Mode)
	}
	if got.ReceiptGenuine {
		t.Error("a simulated receipt was reported as genuine")
	}
}

// A dispatch exactly at the deadline is on time; one second later is late.
func TestDeadlineBoundary(t *testing.T) {
	atEdge := withDispatch(incident(), complete("cert-in-receiver", noticed.Add(6*time.Hour)))
	expect(t, "at the deadline", Evaluate(cert, atEdge), grade.PASS, "")
	late := withDispatch(incident(), complete("cert-in-receiver", noticed.Add(6*time.Hour+time.Second)))
	expect(t, "one second late", Evaluate(cert, late), grade.FAIL, ReasonDeadlineMissed)
}

func TestLateDispatchFails(t *testing.T) {
	ev := withDispatch(incident(), complete("cert-in-receiver", noticed.Add(7*time.Hour)))
	expect(t, "late", Evaluate(cert, ev), grade.FAIL, ReasonDeadlineMissed)
}

func TestFailedDispatchFails(t *testing.T) {
	d := complete("cert-in-receiver", noticed.Add(time.Hour))
	d.Status = StatusFailed
	expect(t, "failed dispatch", Evaluate(cert, withDispatch(incident(), d)), grade.FAIL, ReasonDispatchFailed)
}

func TestOmittedRecipientFails(t *testing.T) {
	expect(t, "no dispatch", Evaluate(cert, incident()), grade.FAIL, ReasonObligationOmitted)
}

// A dispatch to a recipient the obligations do not name is a wrong-recipient failure, even if the right one also got it.
func TestWrongRecipientFails(t *testing.T) {
	ev := withDispatch(incident(), complete("unexpected-receiver", noticed.Add(time.Hour)))
	expect(t, "misrouted", Evaluate(cert, ev), grade.FAIL, ReasonWrongRecipient)
	ev = withDispatch(ev, complete("cert-in-receiver", noticed.Add(time.Hour)))
	expect(t, "misrouted and correct", Evaluate(cert, ev), grade.FAIL, ReasonWrongRecipient)
}

// Every field the evidence model needs must be present. Missing any one of them is a failure, never a PASS.
func TestMissingEvidenceCannotPass(t *testing.T) {
	fields := map[string]func(*Dispatch){
		"dispatch timestamp": func(d *Dispatch) { d.DispatchedAt = time.Time{} },
		"payload hash":       func(d *Dispatch) { d.ReportHash = "" },
		"receipt":            func(d *Dispatch) { d.ReceiptRef = "" },
		"mode":               func(d *Dispatch) { d.Mode = "" },
	}
	for name, drop := range fields {
		d := complete("cert-in-receiver", noticed.Add(time.Hour))
		drop(&d)
		expect(t, "missing "+name, Evaluate(cert, withDispatch(incident(), d)), grade.FAIL, ReasonEvidenceMissing)
	}
}

func TestMissingAwarenessTimeFails(t *testing.T) {
	ev := incident()
	ev.Incidents[0].NoticedAt = time.Time{}
	ev = withDispatch(ev, complete("cert-in-receiver", noticed.Add(time.Hour)))
	expect(t, "no awareness time", Evaluate(cert, ev), grade.FAIL, ReasonEvidenceMissing)
}

func TestNoIncidentIsSkipped(t *testing.T) {
	expect(t, "no incident", Evaluate(cert, Evidence{}), grade.SKIPPED, ReasonNoIncident)
}

func TestIneligibleIncidentIsSkipped(t *testing.T) {
	ev := incident()
	ev.Incidents[0].Eligible = false
	expect(t, "not eligible", Evaluate(cert, ev), grade.SKIPPED, ReasonNotEligible)
}

// Two records for the named incident are ambiguous and fail, rather than one being picked.
func TestDuplicateIncidentIsAmbiguous(t *testing.T) {
	ev := incident()
	ev.Incidents = append(ev.Incidents, Incident{ID: "INC-1", NoticedAt: noticed, Eligible: true})
	expect(t, "ambiguous", Evaluate(cert, ev), grade.FAIL, ReasonEvidenceAmbiguous)
}

// Evidence about another incident does not grade the named one.
func TestOtherIncidentOnlyIsSkipped(t *testing.T) {
	ev := Evidence{Incidents: []Incident{{ID: "INC-OTHER", NoticedAt: noticed, Eligible: true}}}
	expect(t, "named incident absent", Evaluate(cert, ev), grade.SKIPPED, ReasonNoIncident)
}

// A provision that states no numeric deadline gives no timeliness grade. The obligation is SKIPPED, not graded against a
// value the engine made up.
func TestUndefinedDeadlineIsSkipped(t *testing.T) {
	obs := []Obligation{{ID: "CBUAE-IMMEDIATE", Recipient: "cbuae", Deadline: "", ProvisionRef: "AE-CBUAE-6-1-2-6"}}
	ev := withDispatch(incident(), complete("cbuae", noticed.Add(time.Minute)))
	ev.Incidents[0].ID = "INC-1"
	expect(t, "no deadline in provision", Evaluate(pol(obs...), ev), grade.SKIPPED, ReasonDeadlineUndefined)
}

func TestInvalidDeadlineFails(t *testing.T) {
	obs := []Obligation{{ID: "BAD", Recipient: "r", Deadline: "soon", ProvisionRef: "IN-CERTIN-70B-II"}}
	ev := withDispatch(incident(), complete("r", noticed.Add(time.Hour)))
	expect(t, "invalid deadline", Evaluate(pol(obs...), ev), grade.FAIL, ReasonDeadlineInvalid)
}

// Separate obligations to different recipients are each graded. One missed recipient fails the whole workflow.
func TestSeparateRecipientsAreEachRequired(t *testing.T) {
	obs := []Obligation{
		{ID: "A", Recipient: "regulator", Deadline: "6h", ProvisionRef: "P-A"},
		{ID: "B", Recipient: "customer-notice", Deadline: "24h", ProvisionRef: "P-B"},
	}
	ev := withDispatch(incident(), complete("regulator", noticed.Add(time.Hour)))
	got := Evaluate(pol(obs...), ev)
	expect(t, "one of two recipients", got, grade.FAIL, ReasonObligationOmitted)
	ev = withDispatch(ev, complete("customer-notice", noticed.Add(2*time.Hour)))
	expect(t, "both recipients", Evaluate(pol(obs...), ev), grade.PASS, "")
}

// A live receipt is the only kind that can be genuine. A simulated run never reports one, even with every other field set.
func TestGenuineReceiptOnlyFromLiveDispatch(t *testing.T) {
	live := complete("cert-in-receiver", noticed.Add(time.Hour))
	live.Mode = ModeLive
	got := Evaluate(cert, withDispatch(incident(), live))
	expect(t, "live", got, grade.PASS, "")
	if got.Mode != ModeLive || !got.ReceiptGenuine {
		t.Errorf("live dispatch: mode %s genuine %t", got.Mode, got.ReceiptGenuine)
	}
	sim := withDispatch(incident(), complete("cert-in-receiver", noticed.Add(time.Hour)))
	if Evaluate(cert, sim).ReceiptGenuine {
		t.Error("simulated dispatch reported a genuine receipt")
	}
}

// Evidence from another incident never counts toward this one.
func TestDispatchForAnotherIncidentIsIgnored(t *testing.T) {
	d := complete("cert-in-receiver", noticed.Add(time.Hour))
	d.IncidentID = "INC-OTHER"
	expect(t, "other incident", Evaluate(cert, withDispatch(incident(), d)), grade.FAIL, ReasonObligationOmitted)
}
