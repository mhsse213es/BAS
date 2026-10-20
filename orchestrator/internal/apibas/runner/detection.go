package runner

import (
	"context"
	"encoding/json"

	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/detect"
)

// runTagKey carries the run tag on the context, so every request in a run is sent
// with the same X-BAS-Run header and the lab can tie its events to the run.
type runTagKey struct{}

// EventSource returns the lab's access events for one run tag.
type EventSource interface {
	AccessEvents(ctx context.Context, correlationID string) ([]detect.Event, error)
}

// detectionStage grades the detection axis after a run. It never changes the
// exploitability result. The scenario's declared source picks the fixture; every
// result carries that fixture's provenance label.
func (r *Runner) detectionStage(ctx context.Context, s contract.Scenario, tag string, rep Report) Report {
	if s.Detection == nil {
		return rep
	}
	rep.DetectionProvenance = detect.ProvenanceFor(s.Detection.Source)
	minSev, ok := detect.ParseSeverity(s.Detection.MinSeverity)
	if !ok {
		rep.Outcome.Detection = "error:INVALID_SEVERITY"
		return rep
	}
	if r.cfg.Events == nil {
		rep.Outcome.Detection = "error:ADAPTER_UNAVAILABLE"
		return rep
	}
	events, err := r.cfg.Events.AccessEvents(ctx, tag)
	if err != nil {
		rep.Outcome.Detection = "error:EVENTS_UNAVAILABLE"
		return rep
	}
	alerts, err := detectAlerts(s.Detection.Source, events, tag)
	if err != nil {
		rep.Outcome.Detection = "error:INVALID_EVENT"
		return rep
	}
	rep.Outcome.Detection = detect.Grade(alerts, s.Detection.ExpectRule, minSev, tag)
	return rep
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
