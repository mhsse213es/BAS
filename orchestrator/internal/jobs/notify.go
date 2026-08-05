package jobs

import "context"

// NotifyEvent is internal/jobs's own copy of the notification-event shape.
// internal/jobs must not import internal/notifications (same reason it
// never imports internal/api: DispatchFn/StatusFn/NotifyFn are all
// injected specifically to keep this package a leaf dependency). Type and
// Severity are plain strings here -- they must match
// notifications.EventType / notifications.Severity's string values
// exactly; internal/api's dispatchJobNotify is what connects the two.
type NotifyEvent struct {
	Type     string
	JobID    string
	TargetID string
	AgentID  string
	Severity string
	Message  string
	Metadata map[string]any
}

// NotifyFn is called for every notification-worthy event Tick() produces.
// Unlike DispatchFn/StatusFn, it is optional: SetNotify is not called by
// every test or every Handler construction, so every call site in
// dispatch.go MUST guard with `if d.notify != nil`.
type NotifyFn func(ctx context.Context, evt NotifyEvent)

func (d *Dispatcher) SetNotify(fn NotifyFn) { d.notify = fn }

// internal/jobs's own spelling of the event-type/severity strings it
// emits. Must match notifications.EventType / notifications.Severity's
// string values exactly.
const (
	notifyTypeJobStarted     = "job_started"
	notifyTypeJobCompleted   = "job_completed"
	notifyTypeJobPartial     = "job_partially_completed"
	notifyTypeJobFailed      = "job_failed"
	notifyTypeTargetFailed   = "target_failed"
	notifyTypeTargetDeferred = "target_deferred"

	notifySeverityInfo     = "info"
	notifySeverityWarning  = "warning"
	notifySeverityError    = "error"
	notifySeverityCritical = "critical"
)

// classifyJobTransition maps a Job's new aggregate state to the
// notification event it produces, or ok=false if this transition isn't
// notification-worthy. JobStateRequested never appears as a newState
// (AggregateState only returns it as a starting point, never a
// transition target reached from a different state). JobStateCancelled
// is excluded here because AggregateState never returns it either --
// CancelJob sets it directly via SQL, bypassing Tick() entirely; its
// EventJobCancelled is emitted by the CancelJob handler in internal/api,
// not here.
func classifyJobTransition(newState string) (eventType, severity string, ok bool) {
	switch newState {
	case JobStateRunning:
		return notifyTypeJobStarted, notifySeverityInfo, true
	case JobStateCompleted:
		return notifyTypeJobCompleted, notifySeverityInfo, true
	case JobStatePartial:
		return notifyTypeJobPartial, notifySeverityWarning, true
	case JobStateFailed:
		return notifyTypeJobFailed, notifySeverityCritical, true
	default:
		return "", "", false
	}
}
