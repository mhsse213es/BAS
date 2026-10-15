package emailgwefficacy

import "time"

// MailEvidenceProvider supplies enforcement and detection evidence
// for a message profile and time window. A returned error means
// collection/parsing failed -- distinct from a successful search that
// found nothing (nil error, empty slice). Mirrors
// webgwefficacy.GatewayEvidenceProvider's shape; this package does
// not import it.
type MailEvidenceProvider interface {
	EnforcementEvidenceFor(msg MessageRef, window TimeWindow) ([]EnforcementEvidence, error)
	DetectionEvidenceFor(msg MessageRef, window TimeWindow) ([]DetectionEvidence, error)
}

// inWindow reports whether t falls within window. An inverted window
// (Start after End) contains nothing -- it is never treated as
// unbounded.
func inWindow(t time.Time, window TimeWindow) bool {
	if window.Start.After(window.End) {
		return false
	}
	return !t.Before(window.Start) && !t.After(window.End)
}

// latestByTimestamp returns the record with the latest timestamp, as
// reported by ts. A later event reflects a system's final state more
// faithfully than an earlier one (retries, duplicate log lines, a
// quarantine decision reversed mid-test) -- every evidence-selection
// function in this package uses this same tie-break rule: ties keep
// the first occurrence of the maximum, since a strict After
// comparison never treats an equal timestamp as later. records must
// be non-empty; every caller already returns early when its own
// evidence slice is empty, before this is ever invoked.
func latestByTimestamp[T any](records []T, ts func(T) time.Time) T {
	latest := records[0]
	for _, r := range records {
		if ts(r).After(ts(latest)) {
			latest = r
		}
	}
	return latest
}

// FixtureMailEvidenceProvider wraps in-memory slices of hand-built
// EnforcementEvidence/DetectionEvidence values -- no real vendor API
// call happens in this phase; the live M365 Defender for Office 365
// adapter is Phase 3's deliverable.
type FixtureMailEvidenceProvider struct {
	enforcement []EnforcementEvidence
	detection   []DetectionEvidence
}

func NewFixtureMailEvidenceProvider(enforcement []EnforcementEvidence, detection []DetectionEvidence) *FixtureMailEvidenceProvider {
	return &FixtureMailEvidenceProvider{enforcement: enforcement, detection: detection}
}

func (p *FixtureMailEvidenceProvider) EnforcementEvidenceFor(msg MessageRef, window TimeWindow) ([]EnforcementEvidence, error) {
	var out []EnforcementEvidence
	for _, e := range p.enforcement {
		if e.Message != msg {
			continue
		}
		if !inWindow(e.Timestamp, window) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func (p *FixtureMailEvidenceProvider) DetectionEvidenceFor(msg MessageRef, window TimeWindow) ([]DetectionEvidence, error) {
	var out []DetectionEvidence
	for _, e := range p.detection {
		if e.Message != msg {
			continue
		}
		if !inWindow(e.Timestamp, window) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}
