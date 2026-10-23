// Package dbrun is the orchestrator-side wiring for one dbsim step: it takes
// what the agent reported (a DBProbeResult inside an ExecResult), asks the
// SIEM about the probe's marker through the Task 12 correlator, folds in the
// Task 9 audit evidence, and returns the graded Outcome, the dlpreport.Record
// and the stored report.
//
// It lives in its own package for the same reason as dbcorrelate (ruling
// R-AG): it imports internal/detectverify, so internal/dbsim, internal/db and
// internal/testutil must never import it.
//
// Everything the agent returns is untrusted data here: counts and lengths are
// bounded, text is redacted again, audit events are only believed when they
// carry this run's marker, and nothing is ever executed or interpreted.
package dbrun

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/dbsim/dbcorrelate"
	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/dlpreport"
)

// Bounds on the agent's report (the agent already applies tighter ones).
const (
	maxNotes       = 64
	maxNoteBytes   = 1024
	maxAuditEvents = 50
	maxStmtBytes   = 1024
	maxReasonBytes = 300
)

// AgentExec is the part of the agent's protocol.ExecResult that dbsim needs
// (JSON tags match the agent wire). The orchestrator never imports agent code.
type AgentExec struct {
	ExitCode          int                  `json:"exitCode"`
	Stderr            string               `json:"stderr"`
	TimedOut          bool                 `json:"timedOut,omitempty"`
	Vetoed            bool                 `json:"vetoed,omitempty"`
	VetoedBlockSource string               `json:"vetoedBlockSource,omitempty"`
	DBProbe           *dbsim.DBProbeResult `json:"dbProbe,omitempty"`
}

// StepInput is everything needed to evaluate one executed dbsim step.
type StepInput struct {
	// Scenario carries the expectations (prevention, detection, response,
	// audit, observation) for this step. The wiring never invents them.
	Scenario dbsim.ScenarioMeta
	// Spec is the spec the orchestrator compiled and signed for this step
	// (dbbuild.BuildSteps): run id, marker and probe id come from here, never
	// from the agent's answer.
	Spec dbsim.DBProbeSpec
	Exec AgentExec
	// Principal is the DB account the probe ran as (a test-account name).
	Principal string
	// DBHost/DBIP identify the database server and AgentIP the agent host; the
	// correlator queries both and unions the alerts (spec R1).
	DBHost, DBIP, AgentIP string
	// Window is the detection window after the probe; SkewAllowance pads it.
	Window, SkewAllowance time.Duration
	// GrantsChecked, when set, is dbsim.DiffReport.GrantsChecked (DB-02); it
	// overrides the probe's row count for the empty-observation guard.
	GrantsChecked *int
	// Diff is a policy diff that was ACTUALLY performed (dbsim.Report). Leave it
	// nil when none was: nothing in dbrun computes or fabricates one, and a DB-02
	// step without it grades ERROR (ruling R-AJ).
	Diff *dbsim.DiffReport
	// ClassificationRuleName is policy data for DB-07 (probe read_classified_fixture):
	// the name of the classification-specific detection rule whose alert counts as
	// a correct classification. Empty (the default) means no verdict can be given:
	// Classification stays NotEvaluated and the run is never a PASS (ruling R-AM).
	// The generic marker rule never counts, whatever is configured here.
	ClassificationRuleName string
	// Now is an optional clock (zero means time.Now).
	Now func() time.Time
}

// Observations are the agent's key=value notes, parsed once.
type Observations struct {
	Shape         string `json:"shape,omitempty"`
	RowsRead      int    `json:"rowsRead"`     // the typed wire value
	NoteRowsRead  int    `json:"noteRowsRead"` // the rows_read note, 0 when absent
	BytesRead     int    `json:"bytesRead"`
	Truncated     bool   `json:"truncated"`
	RowCapApplied int    `json:"rowCapApplied"`
	DurationMs    int    `json:"durationMs"`
	// RowsDisagree is set when the typed RowsRead and the rows_read note differ.
	RowsDisagree bool `json:"rowsDisagree,omitempty"`
}

// Evaluation is the graded result of one step.
type Evaluation struct {
	Outcome      dbsim.Outcome
	Report       dbsim.StoredReport
	Record       dlpreport.Record
	Result       dbsim.RunResult
	Observations Observations
	// Correlation is the correlator's finding; nil when no correlation was
	// attempted (no detection expected, probe did not complete, no connector).
	Correlation *dbcorrelate.Result `json:"-"`
	// CorrelationErr is the (redacted) lookup error, empty when none.
	CorrelationErr string
}

func bound(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && n < len(s) && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}

// boundProbe copies the agent's result with every collection and string
// bounded; it never trusts sizes the agent chose.
func boundProbe(p dbsim.DBProbeResult) dbsim.DBProbeResult {
	out := p
	out.Notes = nil
	for i, n := range p.Notes {
		if i >= maxNotes {
			break
		}
		out.Notes = append(out.Notes, dbsim.Redact(bound(n, maxNoteBytes)))
	}
	out.AuditEvents = nil
	for i, e := range p.AuditEvents {
		if i >= maxAuditEvents {
			break
		}
		// Bounded first so redaction never scans an agent-sized string; the
		// marker leads the statement, so redaction leaves it intact.
		e.Statement = dbsim.Redact(bound(e.Statement, maxStmtBytes))
		e.Principal = dbsim.Redact(bound(e.Principal, 256))
		e.Source = dbsim.Redact(bound(e.Source, 128))
		out.AuditEvents = append(out.AuditEvents, e)
	}
	out.ErrorClass = bound(p.ErrorClass, 64)
	out.AuditStatus = bound(p.AuditStatus, 32)
	out.CleanupStatus = bound(p.CleanupStatus, 32)
	if p.RowsRead < 0 {
		out.RowsRead = 0
	}
	return out
}

func reasonOf(p dbsim.DBProbeResult, stderr string) string {
	r := ""
	if len(p.Notes) > 0 {
		r = p.Notes[0]
	}
	if r == "" {
		r = stderr
	}
	return dbsim.Redact(bound(r, maxReasonBytes))
}

// classifyExec turns the agent's execution result into the Outcome's
// ran/skipped/refused/error fields.
func classifyExec(ex AgentExec, o *dbsim.Outcome) {
	if ex.DBProbe == nil {
		if ex.Vetoed {
			o.GateRefusal = "agent veto (" + dbsim.Redact(bound(ex.VetoedBlockSource, 64)) + "): " + dbsim.Redact(bound(ex.Stderr, maxReasonBytes))
			return
		}
		o.ExecutionError = fmt.Sprintf("agent returned no dbprobe result (exit code %d): %s", ex.ExitCode, dbsim.Redact(bound(ex.Stderr, maxReasonBytes)))
		return
	}
	o.Probe = boundProbe(*ex.DBProbe)
	reason := reasonOf(o.Probe, ex.Stderr)
	switch o.Probe.ErrorClass {
	case "gate_refused", "identity_error":
		// A policy/scope decision (including a target-identity mismatch): the
		// probe was refused before any SQL.
		o.GateRefusal = o.Probe.ErrorClass + ": " + reason
	case "credential_unresolved", "adapter_unsupported":
		// The test cannot legitimately run here.
		o.Skipped = o.Probe.ErrorClass + ": " + reason
	case "connect_error", "fixture_error":
		o.ExecutionError = o.Probe.ErrorClass + ": " + reason
	default:
		o.ProbeRan = true
		if o.Probe.ErrorClass == "cleanup_incident" {
			o.SafetyIncident = true // fail closed even if the flag was lost
		}
	}
}

func parseObservations(p dbsim.DBProbeResult) Observations {
	n := dbsim.ParseNotes(p.Notes)
	var ob Observations
	ob.RowsRead = p.RowsRead
	ob.Shape, _ = n.Get("shape")
	ob.NoteRowsRead, _ = n.Int("rows_read")
	ob.BytesRead, _ = n.Int("bytes_read")
	ob.Truncated, _ = n.Bool("truncated")
	ob.RowCapApplied, _ = n.Int("row_cap_applied")
	ob.DurationMs, _ = n.Int("duration_ms")
	if v, ok := n.Int("rows_read"); ok && v != p.RowsRead {
		ob.RowsDisagree = true
	}
	return ob
}

// Evaluate grades one executed step. conn may be nil (no detection connector
// configured): a scenario that expects detection is then Unverifiable, never a
// pass. The returned error is only for unusable input; a failed SIEM lookup is
// reported in Evaluation.CorrelationErr and graded Unverifiable.
func Evaluate(ctx context.Context, conn detectverify.Connector, in StepInput) (Evaluation, error) {
	if strings.TrimSpace(in.Spec.Marker) == "" || strings.TrimSpace(in.Spec.RunID) == "" || in.Spec.ProbeID == "" {
		return Evaluation{}, errors.New("dbrun: the compiled spec must carry a run id, marker and probe id")
	}
	if in.Window <= 0 {
		return Evaluation{}, errors.New("dbrun: a positive detection window is required")
	}
	if in.Spec.ProbeID == dbsim.ProbeReadGrants {
		// R-AK: forced, not left to the caller.
		in.Scenario.RequirePolicyDiff = true
	}
	// R-AM, forced like R-AK: a classification probe always carries a
	// classification expectation and is always correlated, whatever the caller's
	// scenario meta says.
	classifyProbe := in.Spec.ProbeID == dbsim.ProbeReadClassifiedFixture
	if classifyProbe {
		in.Scenario.ExpectClassification = true
	}
	now := time.Now
	if in.Now != nil {
		now = in.Now
	}
	ev := Evaluation{}
	o := dbsim.Outcome{
		ProbeID: in.Spec.ProbeID,
		Marker:  in.Spec.Marker, RunID: in.Spec.RunID, Principal: in.Principal,
		CollectedAt: now().UTC(), Observed: in.GrantsChecked, Diff: in.Diff,
	}
	classifyExec(in.Exec, &o)
	if in.Exec.DBProbe != nil {
		ev.Observations = parseObservations(o.Probe)
		if ev.Observations.RowsDisagree {
			o.Limitations = append(o.Limitations, fmt.Sprintf("The agent's typed row count (%d) and its rows_read note (%d) disagree; the typed value is used for grading.", ev.Observations.RowsRead, ev.Observations.NoteRowsRead))
		}
	}

	probeAt := o.Probe.DBTime
	if probeAt.IsZero() {
		probeAt = o.Probe.AgentTime
	}
	if !o.Probe.DBTime.IsZero() && !o.Probe.AgentTime.IsZero() {
		d := o.Probe.DBTime.Sub(o.Probe.AgentTime)
		if d < 0 {
			d = -d
		}
		if d > in.SkewAllowance+2*time.Second {
			o.Limitations = append(o.Limitations, fmt.Sprintf("The database-reported probe time and the agent's clock differ by %s (clock skew or latency); the database time is used for the detection window.", d.Round(time.Second)))
		}
	}

	// Correlate only when the probe completed and detection is part of the
	// expectation: a SIEM query for a refused/failed probe or a scenario that
	// expects no alert would only create noise.
	_, incident := cleanupIncident(o)
	// DB-06 (auth_after_revoke) is never correlated: its denial carries no marker.
	if o.ProbeID == dbsim.ProbeAuthAfterRevoke {
		in.Scenario.ExpectDetection, in.Scenario.ExpectResponse = false, false
	}
	if (in.Scenario.ExpectDetection || classifyProbe) && dbsim.ProbeCompleted(o) && !incident {
		switch {
		case conn == nil:
			o.Limitations = append(o.Limitations, "No detection connector is configured: detection telemetry is unverifiable.")
		case probeAt.IsZero():
			o.Limitations = append(o.Limitations, "The probe reported no timestamp, so no detection window can be anchored: detection telemetry is unverifiable.")
		default:
			res, err := dbcorrelate.Correlate(ctx, conn, dbcorrelate.CorrelationInput{
				Marker: in.Spec.Marker, Principal: in.Principal, RunID: in.Spec.RunID,
				DBHost: in.DBHost, DBIP: in.DBIP, AgentIP: in.AgentIP,
				ProbeAt: probeAt, Window: in.Window, SkewAllowance: in.SkewAllowance,
			})
			if err != nil {
				ev.CorrelationErr = dbsim.Redact(bound(err.Error(), 500))
			}
			ev.Correlation = &res
			c := res.ToCorrelation()
			c.AlertRefs = dbcorrelate.AlertRefs(res.Alerts, in.Spec.Marker)
			if c.Telemetry == dlpreport.TelemetryPresent && (c.Match == dbsim.MatchExactMarker || c.Match == dbsim.MatchStrongContextual) {
				// A marker-correlated SIEM alert was raised: that is the lowest
				// rung of the response ladder and nothing more.
				c.Response = dlpreport.ResponseAlerted
				c.Limitations = strings.Replace(c.Limitations, dbcorrelate.ResponseNotAssessedNote,
					"Response=Alerted records only that the SIEM raised an alert correlated to this probe; no case, escalation or remediation was assessed.", 1)
			}
			c.Limitations = dbsim.Redact(c.Limitations)
			o.Corr = c
		}
	}

	if classifyProbe && incident {
		o.Classification = dlpreport.ClassificationNotEvaluated
		o.Limitations = append(o.Limitations, "Classification not evaluated: fixture cleanup was not verified, so the run is graded ERROR and no classification verdict is computed.")
	} else if classifyProbe {
		var rules []string
		hidden := 0
		if ev.Correlation != nil {
			hidden = ev.Correlation.StrongDropped
			for _, a := range ev.Correlation.Alerts {
				rules = append(rules, a.RuleName)
			}
		}
		cls, lim := dbsim.ClassifyByRule(in.ClassificationRuleName, o, rules, hidden)
		o.Classification = cls
		o.Limitations = append(o.Limitations, lim)
	}

	rep, err := dbsim.BuildReport(in.Scenario, o)
	if err != nil {
		return Evaluation{}, fmt.Errorf("dbrun: build report: %w", err)
	}
	ev.Outcome, ev.Report, ev.Record, ev.Result = o, rep, rep.Record, rep.Result
	return ev, nil
}

// cleanupIncident is incident-equivalent for the pipeline: a flagged incident,
// a non-benign cleanup status, or (via the shared dbsim.CleanupUnverified, the
// same rule grade() uses) a fixture-gated probe whose cleanup is not positively
// "ok". Such a run is graded ERROR, so it is neither correlated nor classified.
func cleanupIncident(o dbsim.Outcome) (string, bool) {
	st := o.CleanupStatus
	if st == "" {
		st = o.Probe.CleanupStatus
	}
	inc := o.SafetyIncident || o.Probe.SafetyIncident
	switch st {
	case "", dbsim.CleanupOK, dbsim.CleanupNotApplicable:
	default:
		inc = true
	}
	if dbsim.CleanupUnverified(o) {
		inc = true
	}
	return st, inc
}
