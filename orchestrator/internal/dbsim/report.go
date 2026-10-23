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
)

// Dimensions is the separated per-dimension grading.
type Dimensions struct {
	Prevention     DimensionGrade `json:"prevention"`
	Detection      DimensionGrade `json:"detection"`
	Response       DimensionGrade `json:"response"`
	Classification DimensionGrade `json:"classification"`
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
	Principal      string
	Marker         string
	RunID          string
}

// errorClassAllowedRead lists agent error classes that still mean the read
// itself was permitted (the engine let rows flow until our own cap).
var errorClassAllowedRead = map[string]bool{"row_limit_exceeded": true}

func probeErrored(o Outcome) bool {
	return o.ProbeRan && !o.Probe.Denied && o.Probe.ErrorClass != "" && !errorClassAllowedRead[o.Probe.ErrorClass]
}

func enforcementOf(o Outcome) dlpreport.EnforcementOutcome {
	switch {
	case !o.ProbeRan || o.ExecutionError != "":
		return dlpreport.EnforcementUnknown
	case o.Probe.Denied:
		return dlpreport.EnforcementBlocked
	case probeErrored(o):
		return dlpreport.EnforcementUnknown
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
//	        as timeout/canceled, no probe result), or ANY expected dimension is
//	        unverifiable/incomplete. Checked before FAIL: an unverifiable
//	        expectation is never a clean fail and never a pass.
//	SKIPPED the test could not legitimately run (Skipped reason, or a gate
//	        refusal, which is a policy/scope decision rather than a probe result).
//	FAIL    an expected behaviour was observed to be absent.
//	PASS    every expected dimension was positively observed.
//
// A scenario that expects nothing at all is ERROR, never a vacuous PASS.
func grade(s ScenarioMeta, o Outcome) graded {
	g := graded{Dims: Dimensions{DimNotExpected, DimNotExpected, DimNotExpected, DimNotExpected}}
	enf := enforcementOf(o)

	switch s.ExpectedPrevention {
	case "deny":
		g.Dims.Prevention = pick(enf, dlpreport.EnforcementBlocked, dlpreport.EnforcementAllowed)
	case "allow":
		g.Dims.Prevention = pick(enf, dlpreport.EnforcementAllowed, dlpreport.EnforcementBlocked)
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

	switch {
	case o.ExecutionError != "":
		g.Result, g.Reason = ResultError, "execution error: "+o.ExecutionError
	case o.Skipped != "":
		g.Result, g.Reason = ResultSkipped, "skipped: "+o.Skipped
	case o.GateRefusal != "":
		g.Result, g.Reason = ResultSkipped, "gate refusal (policy/scope decision): "+o.GateRefusal
	case !o.ProbeRan:
		g.Result, g.Reason = ResultError, "probe did not run and no skip reason recorded"
	case probeErrored(o):
		g.Result, g.Reason = ResultError, "probe error class "+o.Probe.ErrorClass
	default:
		all := []DimensionGrade{g.Dims.Prevention, g.Dims.Detection, g.Dims.Response, g.Dims.Classification}
		var fail, unver, pass int
		for _, d := range all {
			switch d {
			case DimFail:
				fail++
			case DimUnverifiable:
				unver++
			case DimPass:
				pass++
			}
		}
		switch {
		case unver > 0:
			g.Result, g.Reason = ResultError, "an expected dimension is unverifiable"
		case fail > 0:
			g.Result, g.Reason = ResultFail, "an expected control behaviour was not observed"
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
		// A match that is ambiguous/none is not a positive observation.
		if c.Match == MatchAmbiguous || c.Match == MatchNone {
			return DimUnverifiable
		}
		return DimPass
	case dlpreport.TelemetryAbsent, dlpreport.TelemetryDelayed:
		return DimFail
	}
	return DimUnverifiable
}

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

	tel, resp := dlpreport.TelemetryUnverifiable, dlpreport.ResponseNotTested
	conf := string(MatchNone)
	if o.Corr.Evaluated {
		if o.Corr.Telemetry == "" || o.Corr.Response == "" {
			return dlpreport.Record{}, fmt.Errorf("dbsim: correlation marked evaluated but telemetry/response not set")
		}
		tel, resp = o.Corr.Telemetry, o.Corr.Response
		if o.Corr.Match != "" {
			conf = string(o.Corr.Match)
		}
		if o.Corr.Limitations != "" {
			lims = append(lims, o.Corr.Limitations)
		}
	} else {
		lims = append(lims, "No telemetry correlation was attempted: detection telemetry is unverifiable and response was not tested.")
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
}

func buildEvidence(o Outcome) evidence {
	notes := make([]string, len(o.Probe.Notes))
	for i, n := range o.Probe.Notes {
		notes[i] = redact(n)
	}
	c := o.Corr
	c.Limitations = redact(c.Limitations)
	return evidence{
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

var (
	reKV  = regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|credential)\s*[=:]\s*[^\s;,&"']+`)
	reDSN = regexp.MustCompile(`(://[^/\s:@]+):[^@\s/]+@`)
)

// redact is a defensive pass stripping credential-looking material; the
// agent never sends secrets, so this only matters if one leaks into a note or
// error string.
func redact(s string) string {
	if s == "" {
		return s
	}
	s = reDSN.ReplaceAllString(s, "$1:[REDACTED]@")
	return reKV.ReplaceAllString(s, "$1=[REDACTED]")
}
