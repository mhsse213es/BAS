package notifications

import (
	"context"
	"log"

	"github.com/audspect/bas/internal/models"
)

// Broadcaster is the subset of ws.Hub that Service needs -- keeps this
// package free of a ws import, same reasoning as integrity.TamperBroadcaster.
type Broadcaster interface {
	BroadcastBrowsers(msg models.WSMessage)
}

type Service struct {
	store       *Store
	broadcaster Broadcaster
}

func NewService(store *Store, broadcaster Broadcaster) *Service {
	return &Service{store: store, broadcaster: broadcaster}
}

// Emit persists evt, pushes it live to every connected browser, and fans it
// out (async, best-effort) to every enabled webhook whose min_severity is
// at or below evt.Severity. A storage failure is logged but does not stop
// delivery -- a notification that failed to persist is still worth pushing.
func (s *Service) Emit(ctx context.Context, evt Event) {
	if err := s.store.Insert(ctx, evt); err != nil {
		log.Printf("[notifications] insert failed: %v", err)
	}

	s.broadcaster.BroadcastBrowsers(models.WSMessage{
		Type: models.MsgNotification,
		Data: evt,
	})

	go s.fanOutWebhooks(ctx, evt)
}
