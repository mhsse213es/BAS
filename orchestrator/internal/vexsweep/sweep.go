// Package vexsweep owns server-side orchestration of the Full Variant
// Sweep feature -- dispatching every ART technique for an agent
// sequentially, tracking progress, and surviving browser reloads/crashes.
// See docs/superpowers/specs/2026-07-30-vex-full-sweep-server-orchestration-design.md.
package vexsweep

import "time"

// Sweep is one Full Variant Sweep's persisted state.
type Sweep struct {
	ID                     string
	AgentID                string
	Mode                   string
	IncludeAdvanced        bool
	Techniques             []string
	TechniqueVariantCounts []int
	CurrentIndex           int
	CurrentVariantRunID    string
	CurrentScenarioRunID   string
	// CurrentTechniqueStartedAt is when the current technique was dispatched
	// (nil when no technique is in flight). Dispatcher uses it to detect a
	// technique that has genuinely hung and force-cancel it -- see
	// dispatcher.go's stuckThreshold.
	CurrentTechniqueStartedAt *time.Time
	CompletedVariants      int
	TotalVariants          int
	Status                 string
	Error                  string
	CreatedBy              string
	StartedAt              time.Time
	CompletedAt            *time.Time
}
