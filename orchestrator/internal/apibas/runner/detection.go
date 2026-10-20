package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/detect"
	"github.com/audspect/bas/internal/apibas/grade"
)

// runTagKey carries the run tag on the context, so every request in a run is sent
// with the same X-BAS-Run header and the lab can tie its events to the run.
type runTagKey struct{}

// EventSource returns the lab's access events for one run tag.
type EventSource interface {
	AccessEvents(ctx context.Context, correlationID string) ([]detect.Event, error)
}

// detectionStage grades the detection axis after a run. It never changes the exploitability result.
// Every declared rule is graded against the same delivered events. The primary rule sets the outcome's
// Detection; the additional rules are recorded per rule in DetectionResults. Every result carries the
// provenance of the fixture that produced it.
func (r *Runner) detectionStage(ctx context.Context, s contract.Scenario, tag string, rep Report) Report {
	if s.Detection == nil {
		return rep
	}
	// A run that did not execute has no traffic to judge. Grading it not_detected would count a skipped
	// scenario as a miss, so detection makes no claim and says why.
	if rep.Outcome.Result == grade.SKIPPED || rep.Outcome.Result == grade.ERROR || len(rep.Exchanges) == 0 {
		rep.DetectionProvenance = detect.ProvenanceFor(s.Detection.Source)
		rep.Outcome.Detection = detect.NotEvaluated
		rep.DetectionReason = "run did not execute: " + string(rep.Outcome.Result)
		if rep.Detail != "" {
			rep.DetectionReason += " (" + rep.Detail + ")"
		}
		return rep
	}
	policies := append([]contract.DetectionPolicy{*s.Detection}, s.AdditionalDetections...)
	rep.DetectionProvenance = detect.ProvenanceFor(s.Detection.Source)
	if r.cfg.Events == nil {
		rep.Outcome.Detection = "error:ADAPTER_UNAVAILABLE"
		return rep
	}
	expected := len(rep.Exchanges)
	events, err := r.collectEvents(ctx, tag, expected)
	if err != nil {
		rep.Outcome.Detection = "error:EVENTS_UNAVAILABLE"
		return rep
	}
	for i, p := range policies {
		minSev, ok := detect.ParseSeverity(p.MinSeverity)
		if !ok {
			rep.Outcome.Detection = "error:INVALID_SEVERITY"
			return rep
		}
		alerts, err := detectAlerts(p.Source, events, tag)
		if err != nil {
			rep.Outcome.Detection = "error:INVALID_EVENT"
			return rep
		}
		result := detect.Grade(alerts, p.ExpectRule, minSev, tag)
		// Absence is evidence only when the telemetry was complete. If the SIEM delivered fewer events
		// than the run sent, a missing alert may be a missing event, so the result is inconclusive, never
		// not_detected. A detection from delivered events stands.
		if result == detect.NotDetected && len(events) < expected {
			result = detect.Inconclusive
			rep.DetectionReason = fmt.Sprintf("telemetry incomplete: %d of %d run events delivered", len(events), expected)
		}
		if i == 0 {
			rep.Outcome.Detection = result
			continue
		}
		if rep.DetectionResults == nil {
			rep.DetectionResults = map[string]string{}
		}
		rep.DetectionResults[p.ExpectRule] = result
	}
	return rep
}

// DefaultDetectionWindow is how long the detection stage waits for delivery when the config sets none.
const DefaultDetectionWindow = 2 * time.Second

// collectEvents polls the SIEM until it has delivered the run's expected events, or the window closes.
// Events that arrive after the window are not seen by the detection stage.
func (r *Runner) collectEvents(ctx context.Context, tag string, expected int) ([]detect.Event, error) {
	window := r.cfg.DetectionWindow
	if window <= 0 {
		window = DefaultDetectionWindow
	}
	deadline := time.Now().Add(window)
	for {
		events, err := r.cfg.Events.AccessEvents(ctx, tag)
		if err != nil {
			return nil, err
		}
		if len(events) >= expected || !time.Now().Before(deadline) {
			return events, nil
		}
		select {
		case <-ctx.Done():
			return events, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// detectAlerts feeds one run's events to the fixture the scenario names. The Sentinel
// path goes through row normalisation, so the mapping is exercised on every run.
func detectAlerts(source string, events []detect.Event, tag string) ([]detect.Alert, error) {
	if source == detect.SourceSentinel {
		f := detect.NewSentinelFixture()
		rows := make([]detect.SentinelRecord, 0, len(events))
		for _, e := range events {
			rows = append(rows, detect.ToSentinelRecord(e))
		}
		if err := f.IngestRecords(rows); err != nil {
			return nil, err
		}
		return f.Alerts(tag), nil
	}
	f := detect.NewElasticFixture()
	if err := f.Ingest(events); err != nil {
		return nil, err
	}
	return f.Alerts(tag), nil
}

// reportedArrayLen counts the elements of a JSON array field a response reports.
// Anything that is not a JSON object holding an array under key counts as zero.
func reportedArrayLen(raw []byte, key string) int {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return 0
	}
	var items []json.RawMessage
	if json.Unmarshal(fields[key], &items) != nil {
		return 0
	}
	return len(items)
}
