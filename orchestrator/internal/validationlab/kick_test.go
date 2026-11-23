package validationlab

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/scenario"
)

// kickDispatcher counts dispatch attempts. It is safe to read from the test goroutine while the loop runs.
type kickDispatcher struct{ calls atomic.Int32 }

func (k *kickDispatcher) DispatchFactoryValidation(ctx context.Context, sc *scenario.Scenario, agentID string) (string, string, error) {
	k.calls.Add(1)
	return "", "", fmt.Errorf("boom")
}

// REQ-055: a draft generated from an advisory should start validating when it lands, not at the next poll.
// The poll interval here is an hour, so only Kick can run the draft inside the test window.
func TestKick_RunsNewDraftBeforeNextPoll(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := newTestRegistry(t, pool)
		mustCreateDraftVersion(t, reg, pool, contentregistry.ActorGenerator, "vl-kick", nonDestructiveArtifact("vl-kick"))

		d := &kickDispatcher{}
		o := NewOrchestrator(pool, reg, d, "lab-agent-1", time.Hour)
		o.Start()
		defer o.Stop()
		o.Kick()

		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if d.calls.Load() > 0 {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("Kick did not run the lab before the poll interval")
	})
}

// A kick must never block the caller, even when no loop is running and kicks pile up.
func TestKick_NeverBlocks(t *testing.T) {
	o := NewOrchestrator(nil, nil, nil, "lab-agent-1", time.Hour)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 5; i++ {
			o.Kick()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Kick blocked with no loop running")
	}
}
