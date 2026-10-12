package cloudgraph

import "time"

// EventCorrelator finds audit log events matching a scenario step's action
type EventCorrelator interface {
	FindEvents(principal, action, resource string, actionTime time.Time, window time.Duration) *EventSearchResult
}

// SyntheticEventCorrelator uses in-memory synthetic events.
// Phase 2: synthetic fixtures. Phase 3+: real CloudTrail/Activity Log integration.
type SyntheticEventCorrelator struct {
	events []*CloudEvent
}

// FindEvents searches for events matching principal+action+resource within [actionTime-window, actionTime+window].
// Match quality: perfect (all 3 fields match), partial (principal+action match, resource differs), none (no match).
func (c *SyntheticEventCorrelator) FindEvents(principal, action, resource string, actionTime time.Time, window time.Duration) *EventSearchResult {
	result := &EventSearchResult{
		EventsFound:      []*CloudEvent{},
		SearchStatus:     "success",
		WindowStart:      actionTime.Add(-window),
		WindowEnd:        actionTime.Add(window),
		MatchQuality:     "none",
		Confidence:       "low",
		EventsSearched:   len(c.events),
		MissingTelemetry: []string{},
	}

	for _, event := range c.events {
		if event.Timestamp.Before(result.WindowStart) || event.Timestamp.After(result.WindowEnd) {
			continue
		}

		matchScore := 0
		if event.Principal == principal {
			matchScore++
		}
		if event.Action == action {
			matchScore++
		}
		if event.Resource == resource {
			matchScore++
		}

		if matchScore == 0 {
			continue
		}

		result.EventsFound = append(result.EventsFound, event)

		if matchScore == 3 {
			result.MatchQuality = "perfect"
			result.Confidence = "high"
		} else if matchScore >= 2 && result.MatchQuality != "perfect" {
			result.MatchQuality = "partial"
			result.Confidence = "medium"
		}

		result.TelemetryDelay = event.Timestamp.Sub(actionTime)
	}

	return result
}

// addSyntheticEvent adds a synthetic event for testing
func (c *SyntheticEventCorrelator) addSyntheticEvent(event *CloudEvent) {
	c.events = append(c.events, event)
}
