// Package reporting grades a regulatory reporting workflow: whether an incident or breach was reported to each required
// recipient, on time, with complete evidence.
//
// The package does not hard-code a deadline. Each obligation carries its own deadline, declared by the scenario from the
// applicable provision. An empty deadline means the provision states no number, and the obligation is SKIPPED rather than
// graded against an invented value.
//
// A dispatch against a simulated receiver is not proof of regulatory submission. Every dispatch records its Mode. A
// simulated dispatch never produces a genuine receipt, and Result reports whether every receipt was genuine.
package reporting

import (
	"fmt"
	"time"

	"github.com/audspect/bas/internal/apibas/grade"
)

// Mode says where a dispatch went. A simulated dispatch reached only a fixture receiver.
type Mode string

const (
	ModeSimulated Mode = "simulated"
	ModeLive      Mode = "live"
)

// Dispatch statuses.
const (
	StatusDispatched = "dispatched"
	StatusFailed     = "failed"
)

// Reason codes. A reason says why an obligation or the whole workflow did not pass.
const (
	ReasonDeadlineMissed    = "deadline_missed"
	ReasonDispatchFailed    = "dispatch_failed"
	ReasonObligationOmitted = "obligation_omitted"
	ReasonWrongRecipient    = "wrong_recipient"
	ReasonEvidenceMissing   = "evidence_missing"
	ReasonEvidenceAmbiguous = "evidence_ambiguous"
	ReasonNoIncident        = "no_incident"
	ReasonNotEligible       = "not_eligible"
	ReasonDeadlineUndefined = "deadline_not_defined_by_provision"
	ReasonDeadlineInvalid   = "deadline_invalid"
)

// Obligation is one reporting duty: the recipient, the deadline the provision sets, and the provision it comes from.
type Obligation struct {
	ID           string `yaml:"id"`
	Recipient    string `yaml:"recipient"`
	Deadline     string `yaml:"deadline"`
	ProvisionRef string `yaml:"provision_ref"`
}

// Policy is the reporting block a scenario declares. Incident names the incident the obligations apply to, so the grade
// never mixes evidence from another incident.
type Policy struct {
	Incident    string       `yaml:"incident"`
	Obligations []Obligation `yaml:"obligations"`
}

// Incident is the awareness record the workflow starts from. NoticedAt is the time the organisation became aware, so the
// deadline clock starts there.
type Incident struct {
	ID        string    `json:"id"`
	Category  string    `json:"category"`
	NoticedAt time.Time `json:"noticed_at"`
	Eligible  bool      `json:"eligible"`
}

// Dispatch is one attempt to report to a recipient. ReportHash is the hash of the payload that was sent.
type Dispatch struct {
	IncidentID   string    `json:"incident_id"`
	Recipient    string    `json:"recipient"`
	Status       string    `json:"status"`
	DispatchedAt time.Time `json:"dispatched_at"`
	ReportHash   string    `json:"report_hash"`
	ReceiptRef   string    `json:"receipt_ref"`
	Mode         Mode      `json:"mode"`
}

// Evidence is what the grader reads. The runner fetches it from the adapter, not from the HTTP response.
type Evidence struct {
	Incidents  []Incident `json:"incidents"`
	Dispatches []Dispatch `json:"dispatches"`
}

// ObligationResult is the grade for one obligation.
type ObligationResult struct {
	ID             string
	Result         grade.Result
	Reason         string
	ReceiptGenuine bool
}

// Result is the whole workflow's grade, with the mode of evidence it rests on.
type Result struct {
	Outcome        grade.Outcome
	Mode           Mode
	ReceiptGenuine bool
	Obligations    []ObligationResult
	Reason         string
}

// Evaluate grades the workflow. It fails closed: any missing, ambiguous or unexpected evidence never yields PASS.
func Evaluate(p Policy, ev Evidence) Result {
	obs := p.Obligations
	var matched []Incident
	for _, in := range ev.Incidents {
		if in.ID == p.Incident {
			matched = append(matched, in)
		}
	}
	if len(matched) == 0 {
		return finish(Result{}, grade.SKIPPED, ReasonNoIncident)
	}
	if len(matched) > 1 {
		return finish(Result{}, grade.FAIL, ReasonEvidenceAmbiguous)
	}
	inc := matched[0]
	if !inc.Eligible {
		return finish(Result{}, grade.SKIPPED, ReasonNotEligible)
	}
	if inc.NoticedAt.IsZero() {
		return finish(Result{}, grade.FAIL, ReasonEvidenceMissing)
	}
	wanted := map[string]bool{}
	for _, o := range obs {
		wanted[o.Recipient] = true
	}
	var res Result
	var failReason, skipReason string
	for _, d := range ev.Dispatches {
		if d.IncidentID != inc.ID {
			continue
		}
		if !wanted[d.Recipient] && failReason == "" {
			failReason = ReasonWrongRecipient
		}
	}
	res.ReceiptGenuine = true
	allLive := true
	for _, o := range obs {
		or := gradeObligation(o, inc, ev.Dispatches)
		res.Obligations = append(res.Obligations, or)
		if or.Result == grade.FAIL && failReason == "" {
			failReason = or.Reason
		}
		if or.Result == grade.SKIPPED && skipReason == "" {
			skipReason = or.Reason
		}
		if !or.ReceiptGenuine {
			res.ReceiptGenuine = false
		}
	}
	for _, d := range ev.Dispatches {
		if d.Mode != ModeLive {
			allLive = false
		}
	}
	if allLive && len(ev.Dispatches) > 0 {
		res.Mode = ModeLive
	} else {
		res.Mode = ModeSimulated
	}
	switch {
	case failReason != "":
		return finish(res, grade.FAIL, failReason)
	case skipReason != "":
		return finish(res, grade.SKIPPED, skipReason)
	}
	return finish(res, grade.PASS, "")
}

// gradeObligation grades one obligation. It is strict: a successful dispatch with incomplete evidence fails.
func gradeObligation(o Obligation, inc Incident, all []Dispatch) ObligationResult {
	or := ObligationResult{ID: o.ID}
	// A missing or incomplete dispatch fails whether or not the provision states a deadline, so it is checked first.
	var window time.Duration
	hasWindow := o.Deadline != ""
	if hasWindow {
		w, err := time.ParseDuration(o.Deadline)
		if err != nil || w <= 0 {
			or.Result, or.Reason = grade.FAIL, ReasonDeadlineInvalid
			return or
		}
		window = w
	}
	var best *Dispatch
	failed := false
	for i := range all {
		d := &all[i]
		if d.IncidentID != inc.ID || d.Recipient != o.Recipient {
			continue
		}
		if d.Status == StatusFailed {
			failed = true
			continue
		}
		if best == nil || d.DispatchedAt.Before(best.DispatchedAt) {
			best = d
		}
	}
	if best == nil {
		or.Result, or.Reason = grade.FAIL, ReasonObligationOmitted
		if failed {
			or.Reason = ReasonDispatchFailed
		}
		return or
	}
	if best.DispatchedAt.IsZero() || best.ReportHash == "" || best.ReceiptRef == "" || best.Mode == "" {
		or.Result, or.Reason = grade.FAIL, ReasonEvidenceMissing
		return or
	}
	if !hasWindow {
		// The dispatch is complete, but the provision states no number to grade timeliness against.
		or.Result, or.Reason = grade.SKIPPED, ReasonDeadlineUndefined
		or.ReceiptGenuine = best.Mode == ModeLive
		return or
	}
	if best.DispatchedAt.After(inc.NoticedAt.Add(window)) {
		or.Result, or.Reason = grade.FAIL, ReasonDeadlineMissed
		return or
	}
	or.Result = grade.PASS
	or.ReceiptGenuine = best.Mode == ModeLive
	return or
}

// finish builds the grade.Outcome in the existing vocabulary. A reporting outcome makes no exploitation claim, so
// Exploitability is not applicable. Control is set from the result, and detection is not evaluated.
func finish(res Result, r grade.Result, reason string) Result {
	if res.Mode == "" {
		// Nothing was dispatched live, so the evidence is simulated.
		res.Mode = ModeSimulated
	}
	res.Reason = reason
	out := grade.Outcome{
		Result:         r,
		Exploitability: grade.ExploitNotApplicable,
		Detection:      "not_evaluated",
		Confidence:     grade.ConfidenceEvidenceBacked,
		Reason:         reason,
	}
	switch r {
	case grade.PASS:
		out.Control = grade.Enforced
		out.Reason = ""
	case grade.FAIL:
		out.Control = grade.Failed
	default:
		out.Control = grade.ControlInconclusive
		out.Confidence = grade.ConfidenceInconclusive
	}
	res.Outcome = out
	return res
}

// String is a one-line summary for logs and reports.
func (r Result) String() string {
	return fmt.Sprintf("%s mode=%s genuine_receipt=%t reason=%q", r.Outcome.Result, r.Mode, r.ReceiptGenuine, r.Reason)
}
