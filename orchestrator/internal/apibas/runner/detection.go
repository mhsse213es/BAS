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
// exploitability result. Every detection result is labelled with the fixture
// provenance, so it cannot be read as a live-SIEM result.
func (r *Runner) detectionStage(ctx context.Context, s contract.Scenario, tag string, rep Report) Report {
	if s.Detection == nil {
		return rep
	}
	rep.DetectionProvenance = detect.Provenance
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
	siem := detect.NewElasticFixture()
	if err := siem.Ingest(events); err != nil {
		rep.Outcome.Detection = "error:INVALID_EVENT"
		return rep
	}
	rep.Outcome.Detection = detect.Grade(siem.Alerts(tag), s.Detection.ExpectRule, minSev, tag)
	return rep
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
