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
	Phase          string     `json:"phase"`    // Execution | Collection | Upload
	Progress       int        `json:"progress"` // 0-100
	CompletedSteps int        `json:"completedSteps"`
	TotalSteps     int        `json:"totalSteps"`
	StartTime      time.Time  `json:"startTime"`
	Running        bool       `json:"running"`
	Result         string     `json:"result,omitempty"` // Detected | Evaded | Partial | Error
	CompletedAt    *time.Time `json:"completedAt,omitempty"`
	DurationSec    int        `json:"durationSec,omitempty"`
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

// StartOperation is called when a scenario begins.
func (s *LocalAgentState) StartOperation(scenarioID, name, techniqueID string, totalSteps int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.currentOp = &LocalOperation{
		ScenarioID:   scenarioID,
		ScenarioName: name,
		TechniqueID:  techniqueID,
		Phase:        "Execution",
		Progress:     0,
		TotalSteps:   totalSteps,
		StartTime:    time.Now(),
		Running:      true,
	}
	s.appendActivity("Simulation Started: " + name)
}

// UpdateProgress is called after each scenario step completes.
func (s *LocalAgentState) UpdateProgress(step, total int, phase string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.currentOp == nil {
		return
	}
	s.currentOp.Phase = phase
	s.currentOp.CompletedSteps = step
	if total > 0 {
		s.currentOp.Progress = step * 100 / total
	}
}

// CompleteOperation is called when a scenario finishes.
func (s *LocalAgentState) CompleteOperation(result string, ev LocalEvidenceStats) {
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

// RecordActivity appends a free-text event to the activity log.
func (s *LocalAgentState) RecordActivity(event string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appendActivity(event)
}
