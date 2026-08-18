// Package emsweep owns server-side orchestration of the Endpoint Mastery
// Full Sweep feature -- dispatching all 14 EM layers for an agent
// sequentially, tracking progress, and surviving browser reloads/crashes.
// Mirrors internal/vexsweep's pattern, simplified: an EM layer is one plain
// scenario dispatch, not an ART technique fanned into variants, so there is
// no per-layer "variant count" to track -- each layer is worth exactly 1.
// See docs/superpowers/specs/2026-08-13-em-full-sweep-design.md.
package emsweep

import "time"

// Sweep is one Endpoint Mastery Full Sweep's persisted state.
type Sweep struct {
	ID                   string
	AgentID              string
	Layers               []string
	CurrentIndex         int
	CurrentScenarioRunID string
	// CurrentLayerStartedAt is when the current layer was dispatched (nil
	// when no layer is in flight). Dispatcher uses it to detect a layer
	// that has genuinely hung and force-cancel it -- see dispatcher.go's
	// stuckThreshold.
	CurrentLayerStartedAt *time.Time
	CompletedLayers       int
	TotalLayers           int
	Status                string
	Error                 string
	CreatedBy             string
	StartedAt             time.Time
	CompletedAt           *time.Time
	// DisconnectedAt is when the Dispatcher last detected the agent was
	// unreachable (nil while running normally, or once resumed). See
	// dispatcher.go's advance() disconnect/resume state machine.
	DisconnectedAt *time.Time
}
