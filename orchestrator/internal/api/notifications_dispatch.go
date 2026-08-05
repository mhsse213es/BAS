package api

import (
	"context"

	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/notifications"
)

// WithNotifications attaches the Phase 7 notification service, backed by
// store and pushing live over the Handler's existing WebSocket hub.
func (h *Handler) WithNotifications(store *notifications.Store) *Handler {
	h.notifications = notifications.NewService(store, h.hub)
	return h
}

// dispatchJobNotify adapts a jobs.NotifyEvent (plain strings, defined in
// internal/jobs to avoid that package importing internal/notifications)
// into a typed notifications.Event and emits it. This is the sole place
// the two packages' vocabularies meet -- mirrors dispatchJobTarget /
// statusForJobTarget's role as the internal/jobs <-> internal/api bridge.
// Passed to jobsDispatcher.SetNotify in WithJobsDispatcher (job_dispatch.go).
func (h *Handler) dispatchJobNotify(ctx context.Context, evt jobs.NotifyEvent) {
	if h.notifications == nil {
		return
	}
	h.notifications.Emit(ctx, notifications.Event{
		Type:     notifications.EventType(evt.Type),
		JobID:    evt.JobID,
		TargetID: evt.TargetID,
		AgentID:  evt.AgentID,
		Severity: notifications.Severity(evt.Severity),
		Message:  evt.Message,
		Metadata: evt.Metadata,
	})
}
