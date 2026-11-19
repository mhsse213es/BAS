package dbjobs

import (
	"context"
	"errors"
	"testing"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/dbsim/dbadmin"
)

// Review finding 5: when the agent is offline AND the job already left pending
// (cancelled during the dispatch), the returned job must report the stored
// state, not a Failed the store never recorded. The error is still
// ErrAgentOffline: the command was not delivered.
func TestDispatchFailureReportsStoredStateWhenJobAlreadyMoved(t *testing.T) {
	r := newRig()
	r.disp.sent = false
	r.disp.onDispatch = func(string) {
		// A cancel lands while the dispatch is in flight.
		for id := range r.store.jobs {
			_, _ = r.store.Transition(context.Background(), id, []dbsim.JobStatus{dbsim.JobPending}, dbsim.JobCancelled, "cancelled", dbadmin.AuditEntry{})
		}
	}
	j, err := r.svc.Start(context.Background(), analyst, labReq())
	if !errors.Is(err, ErrAgentOffline) {
		t.Fatalf("err = %v, want ErrAgentOffline", err)
	}
	stored := r.store.only(t)
	if stored.Status != dbsim.JobCancelled {
		t.Fatalf("stored status = %s, want cancelled", stored.Status)
	}
	if j.Status != stored.Status {
		t.Errorf("returned status = %s, want the stored %s", j.Status, stored.Status)
	}
}

// lockProbe records whether the service mutex is held when an audit row is
// written. Review finding 6: refusal audit writes must not run under s.mu.
type lockProbe struct {
	svc  *Service
	held *bool
}

func (p lockProbe) Log(dbadmin.AuditEntry) error {
	if p.svc.mu.TryLock() {
		p.svc.mu.Unlock()
	} else {
		*p.held = true
	}
	return nil
}

// Review finding 6: a refused start (here: the activity check fails) writes its
// refusal audit row with the service lock released.
func TestRefusalAuditIsWrittenWithoutServiceLock(t *testing.T) {
	r := newRig()
	held := false
	r.svc.Audit = lockProbe{svc: r.svc, held: &held}
	r.svc.Activity = fakeActivity{err: errors.New("activity store down")}
	if _, err := r.svc.Start(context.Background(), analyst, labReq()); err == nil {
		t.Fatal("start must be refused when the activity check fails")
	}
	if held {
		t.Error("refusal audit row was written while the service lock was held")
	}
}
