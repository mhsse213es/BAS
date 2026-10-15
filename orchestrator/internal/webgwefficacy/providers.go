package webgwefficacy

import (
	"strings"
	"time"
)

// GatewayEvidenceProvider supplies gateway evidence for a request
// shape and time window. A returned error means collection/parsing
// failed -- distinct from a successful search that found nothing
// (nil error, empty slice).
type GatewayEvidenceProvider interface {
	GatewayEvidenceFor(req HTTPRequestRef, window TimeWindow) ([]GatewayEvidence, error)
}

// matchesRequest reports whether a concrete evidence record's URL and
// user fall within req's declared scope. User matching is
// case-insensitive; an empty req.User matches any user (the
// expectation did not constrain it).
func matchesRequest(url, user string, req HTTPRequestRef) bool {
	if url != req.URL {
		return false
	}
	if req.User != "" && !strings.EqualFold(user, req.User) {
		return false
	}
	return true
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
// state change mid-test) -- every evidence-selection function in this
// package uses this same tie-break rule: ties keep the first
// occurrence of the maximum, since a strict After comparison never
// treats an equal timestamp as later. records must be non-empty;
// every caller already returns early when its own evidence slice is
// empty, before this is ever invoked.
func latestByTimestamp[T any](records []T, ts func(T) time.Time) T {
	latest := records[0]
	for _, r := range records {
		if ts(r).After(ts(latest)) {
			latest = r
		}
	}
	return latest
}

// FixtureGatewayProvider wraps an in-memory slice of hand-built
// GatewayEvidence values -- no real vendor API call happens in this
// phase; the live Cloudflare Gateway adapter is Phase 2's
// deliverable.
type FixtureGatewayProvider struct {
	events []GatewayEvidence
}

func NewFixtureGatewayProvider(events []GatewayEvidence) *FixtureGatewayProvider {
	return &FixtureGatewayProvider{events: events}
}

func (p *FixtureGatewayProvider) GatewayEvidenceFor(req HTTPRequestRef, window TimeWindow) ([]GatewayEvidence, error) {
	var out []GatewayEvidence
	for _, e := range p.events {
		if !matchesRequest(e.RequestURL, e.User, req) {
			continue
		}
		if !inWindow(e.Timestamp, window) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}
