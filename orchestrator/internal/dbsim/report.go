package dbsim

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/audspect/bas/internal/dlpreport"
)

// RunResult is the dedicated-store grade (docs/dbsim-discovery.md B3, same
// vocabulary as apibas_runs.result). It is deliberately NOT the killchain or
// models verdict vocabulary.
type RunResult string

const (
	ResultPass    RunResult = "PASS"
	ResultFail    RunResult = "FAIL"
	ResultError   RunResult = "ERROR"
	ResultSkipped RunResult = "SKIPPED"
)

// Valid reports whether r is one of the four stored grades.
func (r RunResult) Valid() bool {
	switch r {
	case ResultPass, ResultFail, ResultError, ResultSkipped:
		return true
	}
	return false
}

// DimensionGrade is the per-dimension verdict kept in the stored report so
// prevention, detection and response are never collapsed into one status.
type DimensionGrade string

const (
	DimPass         DimensionGrade = "pass"
	DimFail         DimensionGrade = "fail"
	DimNotExpected  DimensionGrade = "not_expected"
	DimUnverifiable DimensionGrade = "unverifiable"
	// DimSkipped: the dimension could not legitimately be tested (for example
	// the target has no queryable audit source). It is never a pass.
	DimSkipped DimensionGrade = "skipped"
)

// Dimensions is the separated per-dimension grading.
type Dimensions struct {
	Prevention     DimensionGrade `json:"prevention"`
	Detection      DimensionGrade `json:"detection"`
	Response       DimensionGrade `json:"response"`
	Classification DimensionGrade `json:"classification"`
	// Audit grades the target's own audit coverage/evidence (DB-04); it is
	// DimNotExpected for scenarios that do not expect it.
	Audit DimensionGrade `json:"audit,omitempty"`
}

// MatchGrade is the correlator's marker-match confidence (Task 12 produces it).
type MatchGrade string

const (
	MatchExactMarker      MatchGrade = "exact_marker"
	MatchStrongContextual MatchGrade = "strong_contextual"
	MatchAmbiguous        MatchGrade = "ambiguous"
	MatchNone             MatchGrade = "none"
)

// ScenarioMeta is the static description of the scenario being rendered.
type ScenarioMeta struct {
	ID                    string   `json:"id"`
	Version               string   `json:"version"`
	ControlObjective      string   `json:"controlObjective"`
	Preconditions         string   `json:"preconditions"`
	SyntheticDataManifest string   `json:"syntheticDataManifest"`
	ActionAttempted       string   `json:"actionAttempted"`
	ExpectedPrevention    string   `json:"expectedPrevention"` // "deny" | "allow" | ""
	ExpectDetection       bool     `json:"expectDetection"`
	ExpectResponse        bool     `json:"expectResponse"`
	Engine                string   `json:"engine"`
	TargetID              string   `json:"targetId"`
	Mode                  ExecMode `json:"mode"`
	// ExpectAudit: the audit readback of this probe's own marker (the agent's
	// AuditStatus/AuditEvents) is part of the expectation.
	ExpectAudit bool `json:"expectAudit,omitempty"`
	// ExpectAuditConfig: the probe is read_audit_config and its
	// "audit_config: covered|partial|none" summary is part of the expectation.
	ExpectAuditConfig bool `json:"expectAuditConfig,omitempty"`
	// RequireObservation: an empty observation (zero rows/grants) means the
	// account could not see the object, so it can never be graded as a pass
	// (DB-02: a catalog the account cannot read looks exactly like a clean one).
	RequireObservation bool `json:"requireObservation,omitempty"`
}

// Correlation is caller-supplied (the Task 12 correlator will produce it).
// Evaluated=false means "no correlation was attempted", which is different
// from "attempted and found nothing" (Evaluated=true, Telemetry=Absent).
type Correlation struct {
	Evaluated   bool                       `json:"evaluated"`
	Telemetry   dlpreport.TelemetryOutcome `json:"telemetry"`
	Response    dlpreport.ResponseOutcome  `json:"response"`
	Latency     time.Duration              `json:"latencyNs"`
	Match       MatchGrade                 `json:"match"`
	Alerts      int                        `json:"alerts"`
	Limitations string                     `json:"limitations,omitempty"`
	// AlertRefs are minimised references to the matched alerts (id, time,
	// rule, host and a redacted excerpt), never the raw alert document. The
	// wiring layer fills it; it is bounded and redacted again on storage.
	AlertRefs []AlertRef `json:"alertRefs,omitempty"`
}

// MaxAlertRefs and MaxAlertExcerptBytes bound what is stored per alert.
const (
	MaxAlertRefs         = 5
	MaxAlertExcerptBytes = 512
)

// AlertRef is what the report keeps of one matched SIEM alert.
type AlertRef struct {
	ID      string    `json:"id,omitempty"`
	Time    time.Time `json:"time"`
	Rule    string    `json:"rule,omitempty"`
	Host    string    `json:"host,omitempty"`
	Excerpt string    `json:"excerpt,omitempty"`
}

// Outcome is everything known about one scenario execution.
type Outcome struct {
	Probe          DBProbeResult
	ProbeRan       bool
	GateRefusal    string
	ExecutionError string
	Skipped        string
	Corr           Correlation
	// Classification is set by DB-07 only; otherwise NotEvaluated (or empty,
	// which is treated as NotEvaluated).
	Classification dlpreport.ClassificationOutcome
	CollectedAt    time.Time
	// Principal is the DB role/account the probe ran as. It is stored and
	// reported on purpose (spec section 9 requires it in results): it is a
	// test-account name, not a secret. Credentials, passwords and DSNs are
	// never stored; redact() is a defensive pass over every free-text field.
	Principal string
	Marker    string
	RunID     string
	// CleanupStatus and SafetyIncident report the synthetic-fixture teardown
	// (copied from the probe result by the caller, or read from o.Probe when
	// unset). A safety incident, or a residual/failed/unrecognised status,
	// grades ERROR: never PASS, never FAIL, never SKIPPED.
	CleanupStatus  string
	SafetyIncident bool
	// Observed, when set, is the number of items actually observed (for DB-02
	// the DiffReport.GrantsChecked). It overrides Probe.RowsRead for the
	// RequireObservation guard.
	Observed *int
	// Limitations are extra caller-supplied limitation lines (redacted when
	// rendered), for example "agent row counts disagree".
	Limitations []string
}

// unobservable returns a non-empty reason when the scenario requires a
// non-empty observation and the probe returned none. A denial is its own
// observation and is not "unobservable".
func unobservable(s ScenarioMeta, o Outcome) string {
	if !s.RequireObservation || !o.ProbeRan || o.Probe.Denied || o.ExecutionError != "" || probeErrored(o) {
		return ""
	}
	n := o.Probe.RowsRead
	if o.Observed != nil {
		n = *o.Observed
	}
	if n > 0 {
		return ""
	}
	return "no grants observed: account may lack catalog visibility"
}

// cleanupState returns the effective cleanup status and whether the fixture
// teardown is a safety incident. Either source (Outcome or the probe result)
// can raise it; only an empty, "ok" or "not_applicable" status is benign, so
// an unrecognised value fails closed.
func cleanupState(o Outcome) (status string, incident bool) {
	status = o.CleanupStatus
	if status == "" {
		status = o.Probe.CleanupStatus
	}
	incident = o.SafetyIncident || o.Probe.SafetyIncident
	switch status {
	case "", CleanupOK, CleanupNotApplicable:
	default:
		incident = true
	}
	return status, incident
}

// errorClassAllowedRead lists agent error classes that still mean the read
// itself was permitted (the engine let rows flow until our own row cap).
// row_limit_exceeded therefore maps to Enforcement Allowed: a "deny"
// expectation FAILs and only an "allow" expectation passes.
var errorClassAllowedRead = map[string]bool{"row_limit_exceeded": true}

// errorClassDenial lists the agent error classes that are genuine denials.
// Denied=true with any other class (timeout, canceled, connection errors,
// engine-specific codes) is not a trustworthy denial: Enforcement is Unknown.
var errorClassDenial = map[string]bool{"": true, "permission_denied": true, "auth_failed": true, "read_only_violation": true}

// ProbeCompleted reports whether the probe ran to an observation (success,
// denial or an allowed read stopped by the row cap), as opposed to not running
// or failing with an execution-type error class.
func ProbeCompleted(o Outcome) bool { return o.ProbeRan && !probeErrored(o) }

func probeErrored(o Outcome) bool {
	if !o.ProbeRan {
		return false
	}
	if o.Probe.Denied {
		return !errorClassDenial[o.Probe.ErrorClass]
	}
	return o.Probe.ErrorClass != "" && !errorClassAllowedRead[o.Probe.ErrorClass]
}

func enforcementOf(o Outcome) dlpreport.EnforcementOutcome {
	switch {
	case !o.ProbeRan || o.ExecutionError != "":
		return dlpreport.EnforcementUnknown
	case probeErrored(o):
		return dlpreport.EnforcementUnknown
	case o.Probe.Denied:
		return dlpreport.EnforcementBlocked
	default:
		return dlpreport.EnforcementAllowed
	}
}

type graded struct {
	Result RunResult
	Reason string
	Dims   Dimensions
}

// grade implements controller ruling R-R:
//
//	ERROR   execution/evidence failed (ExecutionError, probe error class such
//	        as timeout/canceled, no probe result), or an expected dimension is
//	        unverifiable/incomplete and no other dimension definitely failed.
//	        Ruling R-U: a definite FAIL dimension beats an unverifiable one (a
//	        confirmed failure is not hidden behind an evidence gap); an
//	        unverifiable expectation is still never a pass.
//	SKIPPED the test could not legitimately run (Skipped reason, or a gate
//	        refusal, which is a policy/scope decision rather than a probe result).
//	FAIL    an expected behaviour was observed to be absent.
//	PASS    every expected dimension was positively observed.
//
// A scenario that expects nothing at all is ERROR, never a vacuous PASS.
func grade(s ScenarioMeta, o Outcome) graded {
	g := graded{Dims: Dimensions{DimNotExpected, DimNotExpected, DimNotExpected, DimNotExpected, DimNotExpected}}
	enf := enforcementOf(o)

	switch s.ExpectedPrevention {
	case "deny":
		g.Dims.Prevention = pick(enf, dlpreport.EnforcementBlocked, dlpreport.EnforcementAllowed)
	case "allow":
		g.Dims.Prevention = pick(enf, dlpreport.EnforcementAllowed, dlpreport.EnforcementBlocked)
	case "":
	default:
		// Unrecognised expectation (e.g. "Deny", "block"): never silently
		// treated as "no expectation".
		g.Dims.Prevention = DimUnverifiable
	}
	if s.ExpectDetection {
		g.Dims.Detection = detectionGrade(o.Corr)
	}
	if s.ExpectResponse {
		g.Dims.Response = responseGrade(o.Corr)
	}
	switch o.Classification {
	case dlpreport.ClassificationCorrect:
		g.Dims.Classification = DimPass
	case dlpreport.ClassificationIncorrect:
		g.Dims.Classification = DimFail
	case dlpreport.ClassificationUnsupported, dlpreport.ClassificationUnknown:
		g.Dims.Classification = DimUnverifiable
	}

	g.Dims.Audit, _ = auditGrade(s, o)
	unobs := unobservable(s, o)
	if unobs != "" && g.Dims.Prevention != DimNotExpected {
		// An empty observation proves neither allow nor deny.
		g.Dims.Prevention = DimUnverifiable
	}

	_, cleanupIncident := cleanupState(o)
	switch {
	case cleanupIncident:
		// Fixture cleanup failed or left residual objects (spec section 8, gate
		// 4). Checked first: no other outcome, SKIPPED included, may hide it.
		g.Result, g.Reason = ResultError, "fixture cleanup safety incident: the run cannot be graded as completed"
	case o.ExecutionError != "":
		g.Result, g.Reason = ResultError, "execution error: "+o.ExecutionError
	case o.ProbeRan && (o.Skipped != "" || o.GateRefusal != ""):
		// Inconsistent evidence: a probe ran yet a skip/refusal is recorded.
		// Never hide that a probe ran behind SKIPPED.
		g.Result, g.Reason = ResultError, "probe ran but a skip/gate refusal was also recorded"
	case s.ExpectedPrevention != "" && s.ExpectedPrevention != "deny" && s.ExpectedPrevention != "allow":
		g.Result, g.Reason = ResultError, fmt.Sprintf("unrecognised ExpectedPrevention %q", s.ExpectedPrevention)
	case o.Skipped != "":
		g.Result, g.Reason = ResultSkipped, "skipped: "+o.Skipped
	case o.GateRefusal != "":
		g.Result, g.Reason = ResultSkipped, "gate refusal (policy/scope decision): "+o.GateRefusal
	case !o.ProbeRan:
		g.Result, g.Reason = ResultError, "probe did not run and no skip reason recorded"
	case probeErrored(o):
		g.Result, g.Reason = ResultError, "probe error class "+o.Probe.ErrorClass
	case unobs != "":
		g.Result, g.Reason = ResultError, "unobservable: "+unobs
	default:
		all := []DimensionGrade{g.Dims.Prevention, g.Dims.Detection, g.Dims.Response, g.Dims.Classification, g.Dims.Audit}
		var fail, unver, skipped, pass int
		for _, d := range all {
			switch d {
			case DimFail:
				fail++
			case DimUnverifiable:
				unver++
			case DimSkipped:
				skipped++
			case DimPass:
				pass++
			}
		}
		switch {
		case fail > 0:
			// R-U: a definite failure is never hidden behind an evidence gap
			// in another dimension.
			g.Result, g.Reason = ResultFail, "an expected control behaviour was not observed"
		case unver > 0:
			g.Result, g.Reason = ResultError, "an expected dimension is unverifiable"
		case skipped > 0:
			// Could not legitimately be tested (e.g. no queryable audit
			// source): neither a pass nor a control failure.
			g.Result, g.Reason = ResultSkipped, "an expected dimension could not be tested (skipped)"
		case pass == 0:
			g.Result, g.Reason = ResultError, "scenario declares no expectation to grade"
		default:
			g.Result, g.Reason = ResultPass, "every expected dimension was positively observed"
		}
	}
	return g
}

func pick(got, want, opposite dlpreport.EnforcementOutcome) DimensionGrade {
	switch got {
	case want:
		return DimPass
	case opposite:
		return DimFail
	}
	return DimUnverifiable
}

func detectionGrade(c Correlation) DimensionGrade {
	if !c.Evaluated {
		return DimUnverifiable
	}
	switch c.Telemetry {
	case dlpreport.TelemetryPresent:
		// Only an exact or strong contextual marker match is a positive
		// observation. Ambiguous, none, empty and unrecognised values
		// (including case variants) are unverifiable.
		if c.Match == MatchExactMarker || c.Match == MatchStrongContextual {
			return DimPass
		}
		return DimUnverifiable
	case dlpreport.TelemetryAbsent, dlpreport.TelemetryDelayed:
		return DimFail
	}
	return DimUnverifiable
}

// responseGrade can only return pass or unverifiable: an expected-but-absent
// response grades the run ERROR, never FAIL, because the dlpreport response
// enum has no "no response" value (NotTested is not evidence of absence).
func responseGrade(c Correlation) DimensionGrade {
	if !c.Evaluated {
		return DimUnverifiable
	}
	switch c.Response {
	case dlpreport.ResponseAlerted, dlpreport.ResponseCaseCreated, dlpreport.ResponseEscalated, dlpreport.ResponseRemediated:
		return DimPass
	}
	return DimUnverifiable
}

// ToRunResult returns the PASS|FAIL|ERROR|SKIPPED grade for the outcome.
func ToRunResult(s ScenarioMeta, o Outcome) RunResult { return grade(s, o).Result }

// ToRecord renders the outcome as a dlpreport.Record and calls Validate().
// Enforcement derives only from the probe; Telemetry/Response come only from
// o.Corr.
func ToRecord(s ScenarioMeta, o Outcome) (dlpreport.Record, error) {
	var lims []string
	enf := enforcementOf(o)
	if enf == dlpreport.EnforcementUnknown {
		lims = append(lims, "Enforcement unknown: the probe did not run or did not return a usable result.")
	}

	if o.ProbeRan && (o.Skipped != "" || o.GateRefusal != "") {
		lims = append(lims, "Inconsistent outcome: the probe ran but a skip or gate refusal was also recorded.")
	}

	if st, inc := cleanupState(o); inc {
		lims = append(lims, fmt.Sprintf("Fixture cleanup safety incident (cleanup status %q): synthetic fixture objects may remain in the target database; the run is graded ERROR and must be investigated.", redact(st)))
	}

	tel, resp := dlpreport.TelemetryUnverifiable, dlpreport.ResponseNotTested
	conf := string(MatchNone)
	if o.Corr.Evaluated {
		if o.Corr.Telemetry == "" || o.Corr.Response == "" {
			return dlpreport.Record{}, fmt.Errorf("dbsim: correlation marked evaluated but telemetry/response not set")
		}
		tel, resp = o.Corr.Telemetry, o.Corr.Response
		// Confidence mirrors the grading: only the four known grades are
		// reported; empty/unknown values are "none", never pass-looking.
		switch o.Corr.Match {
		case MatchExactMarker, MatchStrongContextual, MatchAmbiguous, MatchNone:
			conf = string(o.Corr.Match)
		}
		if o.Corr.Limitations != "" {
			lims = append(lims, o.Corr.Limitations)
		}
	} else {
		lims = append(lims, "No telemetry correlation was attempted: detection telemetry is unverifiable and response was not tested.")
	}
	if t2, note, ok := auditTelemetry(s, o, tel, o.Corr.Evaluated); ok {
		tel = t2
		lims = append(lims, note)
		if !o.Corr.Evaluated && t2 == dlpreport.TelemetryPresent && s.ExpectAudit {
			conf = string(MatchExactMarker) // the audit event carries this run's marker
		}
	}
	_, auditLims := auditGrade(s, o)
	lims = append(lims, auditLims...)
	lims = append(lims, o.Limitations...)
	if u := unobservable(s, o); u != "" {
		lims = append(lims, "Observation empty ("+u+"): an empty result is unobservable, so the run is graded ERROR, never PASS.")
	}

	cls := o.Classification
	if cls == "" {
		cls = dlpreport.ClassificationNotEvaluated
	}
	if cls == dlpreport.ClassificationNotEvaluated {
		lims = append(lims, "Classification not evaluated: this scenario does not classify data.")
	}

	src := "dbsim-orchestrator"
	if o.ProbeRan {
		src = "dbsim-agent"
	}
	g := grade(s, o)
	ev := buildEvidence(o)
	hash, err := evidenceHash(ev)
	if err != nil {
		return dlpreport.Record{}, err
	}

	rec := dlpreport.Record{
		ScenarioID:            s.ID,
		ScenarioVersion:       s.Version,
		ControlObjective:      redact(s.ControlObjective),
		Preconditions:         redact(s.Preconditions),
		SyntheticDataManifest: redact(s.SyntheticDataManifest),
		ActionAttempted:       redact(s.ActionAttempted),
		Enforcement:           enf,
		Classification:        cls,
		Telemetry:             tel,
		Response:              resp,
		Provenance: dlpreport.EvidenceProvenance{
			Timestamp:        o.CollectedAt,
			SourceSystem:     src,
			CorrelationID:    o.Marker,
			IntegrityHash:    hash,
			CollectionMethod: "dbsim probe executed by endpoint agent; telemetry correlated by orchestrator (caller-supplied); grade " + string(g.Result),
		},
		Confidence:  conf,
		Limitations: redact(strings.Join(lims, " ")),
	}
	if err := rec.Validate(); err != nil {
		return dlpreport.Record{}, err
	}
	return rec, nil
}

// evidence is the canonical, secret-free evidence set that gets hashed and
// stored. Struct field order is fixed, so json.Marshal is deterministic.
type evidence struct {
	ProbeRan       bool        `json:"probeRan"`
	Denied         bool        `json:"denied"`
	RowsRead       int         `json:"rowsRead"`
	ErrorClass     string      `json:"errorClass"`
	DBTime         string      `json:"dbTime"`
	AgentTime      string      `json:"agentTime"`
	Notes          []string    `json:"notes"`
	GateRefusal    string      `json:"gateRefusal"`
	ExecutionError string      `json:"executionError"`
	Skipped        string      `json:"skipped"`
	Corr           Correlation `json:"correlation"`
	Classification string      `json:"classification"`
	CollectedAt    string      `json:"collectedAt"`
	Principal      string      `json:"principal"`
	Marker         string      `json:"marker"`
	RunID          string      `json:"runId"`
	CleanupStatus  string      `json:"cleanupStatus,omitempty"`
	SafetyIncident bool        `json:"safetyIncident,omitempty"`
	// Audit evidence as accepted by the orchestrator: status, at most
	// MaxStoredAuditEvents events (redacted, bounded), and how many were not
	// kept. Never executed or interpreted.
	AuditStatus        string              `json:"auditStatus,omitempty"`
	AuditEvents        []DBProbeAuditEvent `json:"auditEvents,omitempty"`
	AuditEventsDropped int                 `json:"auditEventsDropped,omitempty"`
}

// Redact is the exported form of the defensive redaction pass, for the wiring
// layer that handles other untrusted text (alert excerpts) before it reaches
// a Record or Outcome.
func Redact(s string) string { return redact(s) }

// sanitizeAlertRefs bounds and redacts the alert references: at most
// MaxAlertRefs, every text field redacted again and cut.
func sanitizeAlertRefs(in []AlertRef) []AlertRef {
	var out []AlertRef
	for i, a := range in {
		if i >= MaxAlertRefs {
			break
		}
		out = append(out, AlertRef{
			ID: cutUTF8(redact(a.ID), 128), Time: a.Time,
			Rule: cutUTF8(redact(a.Rule), 256), Host: cutUTF8(redact(a.Host), 128),
			Excerpt: cutUTF8(redact(cutUTF8(a.Excerpt, 4*MaxAlertExcerptBytes)), MaxAlertExcerptBytes),
		})
	}
	return out
}

func buildEvidence(o Outcome) evidence {
	notes := make([]string, len(o.Probe.Notes))
	for i, n := range o.Probe.Notes {
		notes[i] = redact(n)
	}
	c := o.Corr
	c.Limitations = redact(c.Limitations)
	c.AlertRefs = sanitizeAlertRefs(c.AlertRefs)
	cstatus, cinc := cleanupState(o)
	auditEvents, auditDropped := SanitizeAuditEvents(o.Probe.AuditEvents)
	return evidence{
		AuditStatus: redact(o.Probe.AuditStatus), AuditEvents: auditEvents, AuditEventsDropped: auditDropped,
		CleanupStatus: redact(cstatus), SafetyIncident: cinc,
		ProbeRan: o.ProbeRan, Denied: o.Probe.Denied, RowsRead: o.Probe.RowsRead,
		ErrorClass: redact(o.Probe.ErrorClass),
		DBTime:     ts(o.Probe.DBTime), AgentTime: ts(o.Probe.AgentTime),
		Notes: notes, GateRefusal: redact(o.GateRefusal), ExecutionError: redact(o.ExecutionError),
		Skipped: redact(o.Skipped), Corr: c, Classification: string(o.Classification),
		CollectedAt: ts(o.CollectedAt), Principal: redact(o.Principal),
		Marker: o.Marker, RunID: o.RunID,
	}
}

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func evidenceHash(e evidence) (string, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return "", fmt.Errorf("dbsim: marshal evidence: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// StoredReport is the full JSON persisted in dbsim_runs.report.
type StoredReport struct {
	Schema     int              `json:"schema"`
	Scenario   ScenarioMeta     `json:"scenario"`
	Result     RunResult        `json:"result"`
	Reason     string           `json:"reason"`
	Dimensions Dimensions       `json:"dimensions"`
	Record     dlpreport.Record `json:"record"`
	Evidence   evidence         `json:"evidence"`
}

// BuildReport grades the outcome and assembles the stored report. Validate()
// is enforced through ToRecord.
func BuildReport(s ScenarioMeta, o Outcome) (StoredReport, error) {
	rec, err := ToRecord(s, o)
	if err != nil {
		return StoredReport{}, err
	}
	g := grade(s, o)
	s.ControlObjective = redact(s.ControlObjective)
	s.Preconditions = redact(s.Preconditions)
	s.SyntheticDataManifest = redact(s.SyntheticDataManifest)
	s.ActionAttempted = redact(s.ActionAttempted)
	return StoredReport{
		Schema: 1, Scenario: s, Result: g.Result, Reason: redact(g.Reason),
		Dimensions: g.Dims, Record: rec, Evidence: buildEvidence(o),
	}, nil
}

// JSON returns the report as JSON.
func (r StoredReport) JSON() ([]byte, error) { return json.Marshal(r) }

// Redaction patterns. Go regexp (RE2) is linear-time, so adversarial input
// cannot cause catastrophic backtracking.
//
// Intentionally over-redacted: any "<name containing password/passwd/pwd/
// secret/token/api key/credential> [:=] <value>" is redacted even when
// benign (e.g. "token: bucket"), and any whitespace-preceded "-p<word>" is
// treated as a CLI password flag (e.g. "-prod"). Plain prose without a
// separator ("password policy enforced") is left alone.
var (
	// key (optional closing quote) separator value; values may be
	// single/double quoted (spaces included) or a bare run. No leading word boundary:
	// underscores are word characters (db_password, PGPASSWORD).
	reKV = regexp.MustCompile(`(?i)([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|credential)[A-Za-z0-9_.-]*)(["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s;,&"'}]+)`)
	// URL userinfo password; may itself contain '@' (greedy to the last '@'
	// before the first '/' or whitespace).
	reDSN = regexp.MustCompile(`(://[^/\s:@]*):[^/\s]*@`)
	// Authorization header value and bare bearer tokens.
	reAuth   = regexp.MustCompile(`(?i)(authorization["']?\s*[:=]\s*)(?:(?:bearer|basic|token)\s+)?[^\s;,"']+`)
	reBearer = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+`)
	// mysql-style -p'secret' / -psecret.
	reCLI = regexp.MustCompile(`(^|\s)(-p)('[^']*'|"[^"]*"|[^\s'"-]\S*)`)
)

// redact is a defensive pass stripping credential-looking material; the
// agent never sends secrets, so this only matters if one leaks into a note or
// error string. It is applied to every free-text field that is stored or
// placed in the Record.
func redact(s string) string {
	if s == "" {
		return s
	}
	s = reDSN.ReplaceAllString(s, "$1:[REDACTED]@")
	s = reAuth.ReplaceAllString(s, "$1[REDACTED]")
	s = reBearer.ReplaceAllString(s, "Bearer [REDACTED]")
	s = reKV.ReplaceAllString(s, "$1$2[REDACTED]")
	return reCLI.ReplaceAllString(s, "$1$2[REDACTED]")
}
