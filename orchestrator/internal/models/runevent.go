package models

import "time"

// RunEvent is one lifecycle event in a run's append-only stream. Type is one of:
// run_started, queued, started, completed, timeout, killed, run_completed,
// run_cancelled. Run-level events leave TaskID/TechniqueID empty. Payload carries
// type-specific fields (verdict/durationMs/exitCode/reason/stepsTotal) and is
// stored opaquely so the schema never needs migrating for new fields.
type RunEvent struct {
	RunID       string         `json:"runId"`
	Seq         int64          `json:"seq"`
	Type        string         `json:"type"`
	TaskID      string         `json:"taskId,omitempty"`
	TechniqueID string         `json:"techniqueId,omitempty"`
	StepName    string         `json:"stepName,omitempty"`
	Ts          time.Time      `json:"ts"`
	Payload     map[string]any `json:"payload,omitempty"`
}
