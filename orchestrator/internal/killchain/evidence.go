package killchain

import "time"

// Tri is a three-valued fact. The zero value is "" (not established), which
// counts as missing evidence. It is deliberately not "no".
type Tri string

const (
	TriYes     Tri = "yes"
	TriNo      Tri = "no"
	TriUnknown Tri = "unknown"
)

// PreventionValue is the outcome of the control that should have stopped the action.
type PreventionValue string

const (
	PreventionBlocked       PreventionValue = "blocked"
	PreventionAllowed       PreventionValue = "allowed"
	PreventionNotApplicable PreventionValue = "not_applicable"
	PreventionUnknown       PreventionValue = "unknown"
)

// DetectionValue is whether the expected behaviour produced a detection.
type DetectionValue string

const (
	DetectionDetected      DetectionValue = "detected"
	DetectionNotDetected   DetectionValue = "not_detected"
	DetectionInconclusive  DetectionValue = "inconclusive"
	DetectionNotApplicable DetectionValue = "not_applicable"
)

// TelemetryHealth is whether the telemetry source was confirmed operational.
type TelemetryHealth string

const (
	TelemetryHealthy   TelemetryHealth = "healthy"
	TelemetryUnhealthy TelemetryHealth = "unhealthy"
)

// ResponseValue is what happened after detection.
type ResponseValue string

const (
	ResponseIncidentCreated   ResponseValue = "incident_created"
	ResponseContainedVerified ResponseValue = "contained_verified"
	ResponseNotContained      ResponseValue = "not_contained"
	ResponseNotApplicable     ResponseValue = "not_applicable"
	ResponseInconclusive      ResponseValue = "inconclusive"
)

// GroundTruth is what actually happened, from a source independent of the
// security product. A product alert is never ground truth.
type GroundTruth struct {
	Source    string `json:"source"`
	Attempted Tri    `json:"attempted"`
	Executed  Tri    `json:"executed"`
	// Reference points to the record that proved the verdict, such as a host:recordID:eventID.
	Reference string `json:"reference,omitempty"`
}

// PreventionEvidence records the verified control that acted, if any.
type PreventionEvidence struct {
	Value     PreventionValue `json:"value"`
	ControlID string          `json:"controlId,omitempty"`
}

// DetectionEvidence records the detection and the telemetry it depends on.
type DetectionEvidence struct {
	Value           DetectionValue  `json:"value"`
	TelemetryHealth TelemetryHealth `json:"telemetryHealth,omitempty"`
	// WindowComplete: the observation window closed before the verdict. A
	// not-detected result is only meaningful when this is yes.
	WindowComplete  Tri    `json:"windowComplete"`
	AlertID         string `json:"alertId,omitempty"`
	TelemetrySource string `json:"telemetrySource,omitempty"`
}

// ResponseEvidence records whether the detection led to verified containment.
type ResponseEvidence struct {
	Value ResponseValue `json:"value"`
}

// Provenance says where a piece of evidence was read from.
type Provenance struct {
	SourceSystem     string    `json:"sourceSystem"`
	CollectorVersion string    `json:"collectorVersion,omitempty"`
	Reference        string    `json:"reference,omitempty"`
	ReadAt           time.Time `json:"readAt"`
}

// Timestamps keep action, event and ingestion times separate. They are not merged.
type Timestamps struct {
	ActionAt    time.Time `json:"actionAt,omitempty"`
	EventAt     time.Time `json:"eventAt,omitempty"`
	IngestedAt  time.Time `json:"ingestedAt,omitempty"`
	WindowStart time.Time `json:"windowStart,omitempty"`
	WindowEnd   time.Time `json:"windowEnd,omitempty"`
}

// StageEvidence is the full evidence contract for one stage execution.
type StageEvidence struct {
	CampaignID  string `json:"campaignId"`
	StageKey    string `json:"stageKey"`
	ExecutionID string `json:"executionId,omitempty"`
	// CausedBy names the upstream stage whose outcome led to this one. It must
	// be an upstream stage, and the correlator enforces that.
	CausedBy    string             `json:"causedBy,omitempty"`
	GroundTruth GroundTruth        `json:"groundTruth"`
	Prevention  PreventionEvidence `json:"prevention"`
	Detection   DetectionEvidence  `json:"detection"`
	Response    ResponseEvidence   `json:"response"`
	Provenance  Provenance         `json:"provenance"`
	Timestamps  Timestamps         `json:"timestamps"`
	// MissingEvidence is written by the engine, not by the source. It names every
	// required field that could not be established.
	MissingEvidence []string `json:"missingEvidence,omitempty"`
	// SourceGaps are the reasons a source could not prove a field, such as disabled
	// audit policy. They are reported beside the missing fields, so the verdict says
	// why, not only what.
	SourceGaps []string `json:"sourceGaps,omitempty"`
	// Pipeline holds per-stage results when the stage is a pipeline check. Attack verdicts
	// are not derived from it.
	Pipeline []PipelineStageResult `json:"pipeline,omitempty"`
}

// Missing returns the required fields that were not established, in a fixed
// order. Each name is a dotted field path. A required field is missing when it
// is empty, and a missing field is never read as "no".
func (e StageEvidence) Missing() []string {
	var m []string
	if e.GroundTruth.Source == "" {
		m = append(m, "groundTruth.source")
	}
	if e.GroundTruth.Attempted == "" {
		m = append(m, "groundTruth.attempted")
	}
	if e.GroundTruth.Executed == "" {
		m = append(m, "groundTruth.executed")
	}
	if e.Prevention.Value == "" {
		m = append(m, "prevention.value")
	}
	if e.Detection.Value == "" {
		m = append(m, "detection.value")
	}
	if e.Detection.TelemetryHealth == "" {
		m = append(m, "detection.telemetryHealth")
	}
	if e.Detection.Value == DetectionNotDetected && e.Detection.WindowComplete == "" {
		m = append(m, "detection.windowComplete")
	}
	if e.Detection.Value == DetectionDetected && e.Response.Value == "" {
		m = append(m, "response.value")
	}
	return m
}
