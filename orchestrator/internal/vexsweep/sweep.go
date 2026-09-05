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
	// BaseTypes is parallel to Techniques -- BaseTypes[i] ("art" or
	// "caldera") is the source Techniques[i] should be resolved against.
	BaseTypes []string
	// BaseIDs is parallel to Techniques -- BaseIDs[i] is the specific atomic
	// test / ability name (resolveBaseCommand's baseID) Techniques[i] should
	// resolve against, so a technique with multiple atomic tests gets one
	// sweep entry per test rather than always resolving to the first. "" at
	// a slot means "resolve to the first match" -- both the pre-fan-out
	// default and every existing sweep's persisted state (see store.go's
	// backward-compat fill, matching BaseTypes' own precedent).
	BaseIDs              []string
	CurrentIndex         int
	CurrentVariantRunID  string
	CurrentScenarioRunID string
	// CurrentTechniqueStartedAt is when the current technique was dispatched
	// (nil when no technique is in flight). Dispatcher uses it to detect a
	// technique that has genuinely hung and force-cancel it -- see
	// dispatcher.go's stuckThreshold.
	CurrentTechniqueStartedAt *time.Time
	CompletedVariants         int
	TotalVariants             int
	Status                    string
	Error                     string
	CreatedBy                 string
	StartedAt                 time.Time
	CompletedAt               *time.Time
	// DisconnectedAt is when the Dispatcher last detected the agent was
	// unreachable (nil while running normally, or once resumed). See
	// dispatcher.go's advance() disconnect/resume state machine.
	DisconnectedAt *time.Time
}
