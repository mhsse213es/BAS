//go:build windows

package main

import (
	"sync"
	"time"
)

// LocalOperation holds the state of a running or completed simulation.
type LocalOperation struct {
	ScenarioID     string     `json:"scenarioId"`
	ScenarioName   string     `json:"scenarioName"`
	TechniqueID    string     `json:"techniqueId,omitempty"`
	Phase          string     `json:"phase"`                 // Execution | Collection | Upload
	Progress       int        `json:"progress"`              // 0-100
	CurrentStep    string     `json:"currentStep,omitempty"` // label of the step executing right now
	CompletedSteps int        `json:"completedSteps"`
	TotalSteps     int        `json:"totalSteps"`
	StartTime      time.Time  `json:"startTime"`
	Running        bool       `json:"running"`
	Result         string     `json:"result,omitempty"` // Detected | Evaded | Partial | Error
	CompletedAt    *time.Time `json:"completedAt,omitempty"`
	DurationSec    int        `json:"durationSec,omitempty"`
	// SweepLabel identifies which layer of a Full Sweep this operation was
	// ("EM 01", "T1059.001"), so the dashboard can show "Result (EM 01):
	// Evaded" instead of a bare, indistinguishable "Result: Evaded" repeated
	// for every layer. Empty for a plain, non-sweep run.
	SweepLabel string `json:"sweepLabel,omitempty"`
	// SweepAggregateLabel/SweepAggregateResult are set only on the operation
	// that was the sweep's LAST layer -- a rolled-up result across every
	// layer this agent ran in the sweep ("EM Full Sweep" / "Evaded").
	SweepAggregateLabel  string `json:"sweepAggregateLabel,omitempty"`
	SweepAggregateResult string `json:"sweepAggregateResult,omitempty"`
}

// LocalActivity is a timestamped event shown in the Recent Activity list.
type LocalActivity struct {
	Time  time.Time `json:"time"`
	Event string    `json:"event"`
}

// LocalEvidenceStats summarises telemetry collected during the last simulation.
type LocalEvidenceStats struct {
	EventsCollected  int        `json:"eventsCollected"`
	DefenderAlerts   int        `json:"defenderAlerts"`
	SysmonDetections int        `json:"sysmonDetections"`
	LastCollection   *time.Time `json:"lastCollectionTime,omitempty"`
	LastUpload       *time.Time `json:"lastUploadTime,omitempty"`
	QueueSize        int        `json:"uploadQueueSize"`
}

// LocalAgentState is the in-memory store read by the local HTTP status API.
// It has its own RWMutex so the API goroutine never contends with scenario execution.
type LocalAgentState struct {
	mu sync.RWMutex

	startTime       time.Time
	serverConnected bool
	lastHeartbeat   time.Time
	lastUploadOK    bool
	lastUploadTime  time.Time

	currentOp *LocalOperation
	lastOp    *LocalOperation
	activity  []LocalActivity // capped at 50 entries
	evidence  LocalEvidenceStats

	// sweepID/sweepResults accumulate per-layer results across one Full
	// Sweep's sequential runs, purely for the local aggregate line -- reset
	// whenever a command tagged with a different sweepID arrives, so a
	// sweep that never reaches its final layer (cancelled, force-failed)
	// can never bleed its partial results into a later, unrelated sweep.
	sweepID      string
	sweepResults []string
}

func newLocalAgentState() *LocalAgentState {
	return &LocalAgentState{startTime: time.Now()}
}

func (s *LocalAgentState) appendActivity(event string) {
	s.activity = append(s.activity, LocalActivity{Time: time.Now(), Event: event})
	if len(s.activity) > 50 {
		s.activity = s.activity[len(s.activity)-50:]
	}
}

// SetConnected records the heartbeat result. lastHeartbeat is advanced only on a
// SUCCESSFUL round-trip — a heartbeat is by definition a completed exchange, so a
// failed attempt must not refresh it. Otherwise the dashboard's "last heartbeat"
// readout keeps showing a few seconds even while disconnected, contradicting the
// "Disconnected" banner; leaving it stale lets the relative-time display grow and
// honestly corroborate the lost link.
func (s *LocalAgentState) SetConnected(ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.serverConnected = ok
	if ok {
		s.lastHeartbeat = time.Now()
		s.appendActivity("Heartbeat OK")
	}
}

// StartOperation is called when a scenario begins. sweepLabel identifies
// which Full Sweep layer this is ("EM 01"), empty for a plain, non-sweep run.
func (s *LocalAgentState) StartOperation(scenarioID, name, techniqueID, sweepLabel string, totalSteps int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.currentOp = &LocalOperation{
		ScenarioID:   scenarioID,
		ScenarioName: name,
		TechniqueID:  techniqueID,
		SweepLabel:   sweepLabel,
		Phase:        "Execution",
		Progress:     0,
		TotalSteps:   totalSteps,
		StartTime:    time.Now(),
		Running:      true,
	}
	s.appendActivity("Simulation Started: " + name)
}

// UpdateProgress is called after each scenario step completes. currentStep
// labels the step executing right now (empty when there's no single step to
// name, e.g. during upload/collection phases).
func (s *LocalAgentState) UpdateProgress(step, total int, phase, currentStep string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.currentOp == nil {
		return
	}
	s.currentOp.Phase = phase
	s.currentOp.CurrentStep = currentStep
	s.currentOp.CompletedSteps = step
	if total > 0 {
		s.currentOp.Progress = step * 100 / total
	}
}

// CompleteOperation is called when a scenario finishes. sweepID/sweepName/
// sweepFinal are empty/false for a plain, non-sweep run. When sweepID is
// set, this layer's result is folded into the running per-sweep rollup;
// when sweepFinal is also true (this was the sweep's last layer), the
// rollup is finalized onto this operation as SweepAggregateLabel/Result and
// the accumulator is cleared, ready for whatever sweep runs next.
func (s *LocalAgentState) CompleteOperation(result string, ev LocalEvidenceStats, sweepID, sweepName string, sweepFinal bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if s.currentOp != nil {
		op := *s.currentOp
		op.Running = false
		op.Result = result
		op.CompletedAt = &now
		op.DurationSec = int(now.Sub(op.StartTime).Seconds())
		op.Progress = 100
		op.Phase = "Upload"

		if sweepID != "" {
			if s.sweepID != sweepID {
				s.sweepID = sweepID
				s.sweepResults = nil
			}
			s.sweepResults = append(s.sweepResults, result)
			if sweepFinal {
				op.SweepAggregateLabel = sweepName
				op.SweepAggregateResult = rollupSweepResult(s.sweepResults)
				s.sweepID = ""
				s.sweepResults = nil
			}
		}

		s.lastOp = &op
		s.currentOp = nil
	}
	ev.LastCollection = &now
	ev.LastUpload = &now
	s.evidence = ev
	s.lastUploadOK = true
	s.lastUploadTime = now
	s.appendActivity("Evidence Uploaded — " + result)
}

// rollupSweepResult reduces one Full Sweep's per-layer results to a single
// sweep-wide verdict. "Worst finding wins": this is a security-validation
// tool, so a rollup that let a majority of Detected layers bury a single
// Evaded one would hide the exact gap the sweep exists to surface. Error
// (inconclusive) outranks Detected for the same reason -- an unresolved
// layer means there isn't actually a clean result to report.
func rollupSweepResult(results []string) string {
	seen := make(map[string]bool, len(results))
	for _, r := range results {
		seen[r] = true
	}
	switch {
	case seen["Evaded"]:
		return "Evaded"
	case seen["Partial"]:
		return "Partial"
	case seen["Error"]:
		return "Error"
	default:
		return "Detected"
	}
}

// RecordActivity appends a free-text event to the activity log.
func (s *LocalAgentState) RecordActivity(event string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appendActivity(event)
}
