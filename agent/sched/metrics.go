package sched

import "time"

// Recorder receives per-job scheduler telemetry: how long a job waited for a
// free worker, how long it waited to acquire its resource locks, how long its
// Run actually took, and the two ways a job can end abnormally. All methods
// must be safe for concurrent use -- Run invokes them from worker goroutines,
// potentially many at once.
//
// This is pure observation: nothing in Run or runJob branches on a Recorder's
// behavior, and a nil Recorder disables telemetry with zero effect on
// scheduling. The point of this phase is to measure the existing scheduler
// before any admission/pressure logic is layered on top of it -- see
// docs/superpowers/specs (Phase 2, scheduler observability).
type Recorder interface {
	// QueueWait reports how long a job sat submitted before a worker goroutine
	// picked it up. This is contention for a free worker, not for locks --
	// pause time (Gate.Wait) is deliberately excluded, since that reflects
	// operator action, not scheduler pressure.
	QueueWait(d time.Duration)
	// LockWait reports how long runJob spent in AcquireCtx, whether or not
	// the acquisition ultimately succeeded.
	LockWait(d time.Duration)
	// ExecutionTime reports how long Job.Run took, once its locks were held.
	// Not called if Run panicked (see JobPanic) or was never reached because
	// lock acquisition timed out (see ScheduleTimeout).
	ExecutionTime(d time.Duration)
	// ScheduleTimeout reports a job whose OnScheduleTimeout fired because its
	// locks could not be acquired within its Schedule bound.
	ScheduleTimeout()
	// JobPanic reports a job whose Run panicked. runJob always recovers --
	// this never crashes the agent -- but a panicking step is a scheduler-level
	// failure worth counting distinctly from a step that ran and legitimately
	// scored FAIL.
	JobPanic()
	// AdmissionWait reports how long a job waited at an optional admission
	// gate (see RiskGate) before being admitted -- near-zero when nothing
	// deferred it. Recorded for every job that passed through a configured
	// RiskGate, whether or not it was ever actually deferred, mirroring how
	// QueueWait is recorded for every job regardless of how long it waited.
	AdmissionWait(d time.Duration)
}
