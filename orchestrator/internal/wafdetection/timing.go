package wafdetection

import (
	"fmt"
	"time"
)

// TimingScenario is the claim that an alert surfaces within a declared
// SLA duration of the triggering event.
type TimingScenario struct {
	ID          string
	SLA         time.Duration
	Description string
	Provenance  string
}

// NewTimingScenario validates at construction time, never at render
// time. A zero or negative SLA is rejected here so it can never silently
// make every latency "within SLA" at evaluation time.
func NewTimingScenario(id string, sla time.Duration, description string, provenance string) (TimingScenario, error) {
	if id == "" {
		return TimingScenario{}, fmt.Errorf("id must not be empty")
	}
	if sla <= 0 {
		return TimingScenario{}, fmt.Errorf("sla must be > 0, got %s", sla)
	}
	if description == "" {
		return TimingScenario{}, fmt.Errorf("description must not be empty")
	}
	if provenance == "" {
		return TimingScenario{}, fmt.Errorf("provenance must not be empty")
	}
	return TimingScenario{ID: id, SLA: sla, Description: description, Provenance: provenance}, nil
}

// TimingVerdict is the outcome of comparing an alert's latency against
// the scenario's declared SLA.
type TimingVerdict string

const (
	TimingWithinSLA    TimingVerdict = "within_sla"
	TimingSLABreached  TimingVerdict = "sla_breached"
	TimingInconclusive TimingVerdict = "inconclusive"
)

// EvaluateResponseTiming treats a zero timestamp, or alertObservedAt
// before eventObservedAt (the alert cannot precede the event it is
// about), as Inconclusive rather than computing a negative latency.
func EvaluateResponseTiming(scenario TimingScenario, eventObservedAt, alertObservedAt time.Time) (TimingVerdict, string, error) {
	if eventObservedAt.IsZero() || alertObservedAt.IsZero() {
		return TimingInconclusive, "a required timestamp is missing", nil
	}
	if alertObservedAt.Before(eventObservedAt) {
		return TimingInconclusive, "alertObservedAt precedes eventObservedAt, a nonsensical ordering", nil
	}
	latency := alertObservedAt.Sub(eventObservedAt)
	if latency <= scenario.SLA {
		return TimingWithinSLA, fmt.Sprintf("latency %s is within the %s SLA", latency, scenario.SLA), nil
	}
	return TimingSLABreached, fmt.Sprintf("latency %s exceeds the %s SLA", latency, scenario.SLA), nil
}
