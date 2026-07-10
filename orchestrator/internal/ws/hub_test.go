package ws

import (
	"testing"

	"github.com/audspect/bas/internal/models"
)

// TestSendToAgent_ClosedChannelDoesNotPanic reproduces the exact race
// SendToAgent must survive: the agent's send channel has already been
// closed by readPump's disconnect cleanup, but the agent entry hasn't been
// removed from h.agents yet (that happens separately, slightly later, in
// ServeAgentWS). Sending on a closed channel panics unconditionally — found
// via a flaky fake-agent test in internal/api that hit this window in ~1-2%
// of runs. Reproduced here deterministically by closing the channel directly
// rather than relying on real goroutine-scheduling timing.
func TestSendToAgent_ClosedChannelDoesNotPanic(t *testing.T) {
	h := NewHub()
	c := &conn{send: make(chan []byte, 128)}
	h.agents["agent-race"] = c
	close(c.send)

	var sent bool
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("SendToAgent panicked: %v", r)
			}
		}()
		sent = h.SendToAgent("agent-race", models.WSMessage{Type: "test"})
	}()
	if sent {
		t.Fatal("SendToAgent returned true for a closed channel, want false")
	}
}

func TestSendToAgent_UnknownAgent(t *testing.T) {
	h := NewHub()
	if h.SendToAgent("does-not-exist", models.WSMessage{Type: "test"}) {
		t.Fatal("SendToAgent returned true for an unregistered agent")
	}
}
