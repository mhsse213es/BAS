package api

import (
	"fmt"
	"io"
	"net/http"

	"github.com/audspect/bas/internal/reporting"
)

// avScenarioVectorResponse is one contributing vector's evaluated outcome
// in the JSON shape served by avScenarioJSONHandler -- camelCase field
// names per this package's existing JSON convention. Every independent
// dimension (finding, response, telemetry, configuration, detection
// latency) is carried separately, never collapsed into one verdict field
// -- so a client can never read a single aggregate score that conceals a
// verified prevention failure (av.txt §4).
type avScenarioVectorResponse struct {
	VectorID       string `json:"vectorId"`
	Severity       string `json:"severity"`
	EvidenceSource string `json:"evidenceSource"`

	Finding           string `json:"finding"`
	FindingConfidence string `json:"findingConfidence"`
	FindingReason     string `json:"findingReason"`

	Response           string `json:"response"`
	ResponseConfidence string `json:"responseConfidence"`
	ResponseReason     string `json:"responseReason"`

	Telemetry       string `json:"telemetry"`
	TelemetryReason string `json:"telemetryReason"`

	Configuration       string `json:"configuration"`
	ConfigurationReason string `json:"configurationReason"`

	DetectionLatency       string `json:"detectionLatency"`
	DetectionLatencyReason string `json:"detectionLatencyReason"`
}

// avScenarioResponse is the JSON shape served by avScenarioJSONHandler,
// for any registered efficacy-scenario slug.
type avScenarioResponse struct {
	ScenarioID        string                     `json:"scenarioId"`
	ScenarioName      string                     `json:"scenarioName"`
	Objective         string                     `json:"objective"`
	Outcome           string                     `json:"outcome"`
	Summary           string                     `json:"summary"`
	VectorOutcomes    []avScenarioVectorResponse `json:"vectorOutcomes"`
	UntestedVectorIDs []string                   `json:"untestedVectorIds"`
}

// avScenarioJSONHandler returns a handler serving the efficacy scenario
// registered under slug in internal/avefficacy's scenario registry (via
// internal/reporting.BuildAVScenarioReport). Every new AV/NGAV scenario is
// wired through this one shared handler, parameterized by slug at
// route-registration time -- no dedicated handler function is written per
// scenario, mirroring wafScenarioJSONHandler's own shape exactly. Its
// error branch is structurally unreachable for a slug that is actually
// registered: the one seed loader uses hardcoded, already-tested,
// always-valid data -- documented here rather than left silently
// untested.
func (h *Handler) avScenarioJSONHandler(slug string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rep, err := reporting.BuildAVScenarioReport(slug)
		if err != nil {
			http.Error(w, fmt.Sprintf("building report: %v", err), http.StatusInternalServerError)
			return
		}
		outcomes := make([]avScenarioVectorResponse, 0, len(rep.VectorOutcomes))
		for _, o := range rep.VectorOutcomes {
			outcomes = append(outcomes, avScenarioVectorResponse{
				VectorID:       o.VectorID,
				Severity:       o.Severity,
				EvidenceSource: o.EvidenceSource,

				Finding:           o.Finding,
				FindingConfidence: o.FindingConfidence,
				FindingReason:     o.FindingReason,

				Response:           o.Response,
				ResponseConfidence: o.ResponseConfidence,
				ResponseReason:     o.ResponseReason,

				Telemetry:       o.Telemetry,
				TelemetryReason: o.TelemetryReason,

				Configuration:       o.Configuration,
				ConfigurationReason: o.ConfigurationReason,

				DetectionLatency:       o.DetectionLatency,
				DetectionLatencyReason: o.DetectionLatencyReason,
			})
		}
		respond(w, avScenarioResponse{
			ScenarioID:        rep.ScenarioID,
			ScenarioName:      rep.ScenarioName,
			Objective:         rep.Objective,
			Outcome:           rep.Outcome,
			Summary:           rep.Summary,
			VectorOutcomes:    outcomes,
			UntestedVectorIDs: rep.UntestedVectorIDs,
		})
	}
}

// avScenarioHTMLHandler is avScenarioJSONHandler's HTML counterpart,
// rendered via internal/reporting so it can never drift from the JSON
// response for the same slug.
func (h *Handler) avScenarioHTMLHandler(slug string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rep, err := reporting.BuildAVScenarioReport(slug)
		if err != nil {
			http.Error(w, fmt.Sprintf("building report: %v", err), http.StatusInternalServerError)
			return
		}
		writeBufferedReport(w, "text/html; charset=utf-8", "", "av efficacy scenario html",
			func(out io.Writer) error { return reporting.AVScenarioReportHTML(out, rep) })
	}
}
