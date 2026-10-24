package dbjobs

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/dbsim/dbadmin"
)

// reapStore adds Expired and Running to the shared fake store.
type reapStore struct {
	*fakeStore
	failFor map[string]bool // job ids whose Transition errors
}

func (r *reapStore) Expired(_ context.Context, now time.Time) ([]dbsim.RunJob, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []dbsim.RunJob
	for _, j := range r.jobs {
		if j.Status.Active() && j.Deadline.Before(now) {
			out = append(out, j)
		}
	}
	return out, nil
}

func (r *reapStore) Running(context.Context) ([]dbsim.RunJob, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []dbsim.RunJob
	for _, j := range r.jobs {
		if j.Status == dbsim.JobRunning {
			out = append(out, j)
		}
	}
	return out, nil
}

func (r *reapStore) Transition(ctx context.Context, id string, from []dbsim.JobStatus, to dbsim.JobStatus, reason string, a dbadmin.AuditEntry) (bool, error) {
	if r.failFor[id] {
		return false, errors.New("db down password=hunter2")
	}
	return r.fakeStore.Transition(ctx, id, from, to, reason, a)
}

type presence map[string]bool

func (p presence) Online(id string) bool { return p[id] }

type reapRig struct {
	store *reapStore
	sink  *fakeSink
	svc   *Service
}

func newReapRig(p AgentPresence) *reapRig {
	st := &reapStore{fakeStore: newStore(), failFor: map[string]bool{}}
	sk := newSink()
	return &reapRig{st, sk, &Service{Jobs: st, Sink: sk, Presence: p}}
}

func (r *reapRig) add(id string, kind dbsim.JobKind, status dbsim.JobStatus, agent, target string, nScen int, deadline time.Time) {
	ids := make([]string, nScen)
	for i := range ids {
		ids[i] = "DB-0" + string(rune('1'+i))
	}
	r.store.jobs[id] = dbsim.RunJob{ID: id, Kind: kind, TargetID: target, AgentID: agent, ScenarioIDs: ids, Status: status, Deadline: deadline}
}

func (r *reapRig) saveRows(runID string, n int) {
	for i := 0; i < n; i++ {
		_, _ = r.sink.Save(context.Background(), RunRecord{RunID: runID, ScenarioID: "DB-0" + string(rune('1'+i))})
	}
}

var past, future = t0.Add(-time.Minute), t0.Add(time.Hour)

func TestReapExpiredPendingBecomesFailed(t *testing.T) {
	r := newReapRig(nil)
	r.add("j1", dbsim.JobKindRun, dbsim.JobPending, agentA, "t1", 2, past)
	n, err := r.svc.Reap(context.Background(), t0)
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	j := r.store.jobs["j1"]
	if j.Status != dbsim.JobFailed || j.Reason != "deadline exceeded: no results received" {
		t.Fatalf("job = %s %q", j.Status, j.Reason)
	}
}

func TestReapExpiredRunningWithRowsBecomesPartial(t *testing.T) {
	r := newReapRig(nil)
	r.add("j1", dbsim.JobKindRun, dbsim.JobRunning, agentA, "t1", 3, past)
	r.saveRows("j1", 2)
	n, err := r.svc.Reap(context.Background(), t0)
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	j := r.store.jobs["j1"]
	if j.Status != dbsim.JobPartial || !strings.Contains(j.Reason, "2 of 3") {
		t.Fatalf("job = %s %q", j.Status, j.Reason)
	}
}

func TestReapDoesNotTouchFinishedJob(t *testing.T) {
	r := newReapRig(nil)
	r.add("j1", dbsim.JobKindRun, dbsim.JobCompleted, agentA, "t1", 1, past)
	// Expired() lists a stale snapshot; the guarded transition must refuse.
	stale := &staleExpired{reapStore: r.store, job: dbsim.RunJob{ID: "j1", Kind: dbsim.JobKindRun, AgentID: agentA, Status: dbsim.JobRunning, Deadline: past}}
	r.svc.Jobs = stale
	n, err := r.svc.Reap(context.Background(), t0)
	if err != nil || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if r.store.jobs["j1"].Status != dbsim.JobCompleted || len(r.store.audits) != 0 {
		t.Fatalf("finished job was touched: %s %v", r.store.jobs["j1"].Status, r.store.actions())
	}
}

type staleExpired struct {
	*reapStore
	job dbsim.RunJob
}

func (s *staleExpired) Expired(context.Context, time.Time) ([]dbsim.RunJob, error) {
	return []dbsim.RunJob{s.job}, nil
}

func TestReapOfflineAgentBeforeDeadlineBecomesPartialOrFailed(t *testing.T) {
	r := newReapRig(presence{agentA: false})
	r.add("j1", dbsim.JobKindRun, dbsim.JobRunning, agentA, "t1", 2, future)
	r.add("j2", dbsim.JobKindRun, dbsim.JobRunning, "bbbbbbbbbbbbbbbb", "t2", 2, future)
	r.saveRows("j2", 1)
	r.svc.Presence = presence{}
	n, err := r.svc.Reap(context.Background(), t0)
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if j := r.store.jobs["j1"]; j.Status != dbsim.JobFailed && j.Status != dbsim.JobPartial || j.Reason == "" {
		t.Fatalf("j1 = %s %q", j.Status, j.Reason)
	}
	if j := r.store.jobs["j1"]; j.Status != dbsim.JobFailed || j.Reason != "agent went offline" {
		t.Fatalf("j1 = %s %q", j.Status, j.Reason)
	}
	if j := r.store.jobs["j2"]; j.Status != dbsim.JobPartial || !strings.HasPrefix(j.Reason, "agent went offline") {
		t.Fatalf("j2 = %s %q", j.Status, j.Reason)
	}
}

func TestReapWritesAudit(t *testing.T) {
	r := newReapRig(nil)
	r.add("j1", dbsim.JobKindRun, dbsim.JobPending, agentA, "t1", 1, past)
	if _, err := r.svc.Reap(context.Background(), t0); err != nil {
		t.Fatal(err)
	}
	if len(r.store.audits) != 1 {
		t.Fatalf("audits = %v", r.store.actions())
	}
	e := r.store.audits[0].Entry
	if e.ActorID != "system:dbsim-reaper" || e.Action != "dbsim.run_failed" || e.Resource != "dbsim-run:j1" || e.Outcome != "ok" {
		t.Fatalf("audit = %+v", e)
	}
}

func TestReapIdentityCheckExpiresFailedAndRecordsNothing(t *testing.T) {
	r := newReapRig(nil)
	r.add("c1", dbsim.JobKindIdentityCheck, dbsim.JobRunning, agentA, "t1", 0, past)
	r.saveRows("c1", 3) // must not matter: identity checks never become partial
	n, err := r.svc.Reap(context.Background(), t0)
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if j := r.store.jobs["c1"]; j.Status != dbsim.JobFailed {
		t.Fatalf("status = %s", j.Status)
	}
	if free, _ := r.store.ActiveForTarget(context.Background(), "t1"); free {
		t.Fatal("target still busy")
	}
}

func TestReapNilPresenceSkipsOfflineRule(t *testing.T) {
	r := newReapRig(nil)
	r.add("j1", dbsim.JobKindRun, dbsim.JobRunning, agentA, "t1", 1, future)
	n, err := r.svc.Reap(context.Background(), t0)
	if err != nil || n != 0 || r.store.jobs["j1"].Status != dbsim.JobRunning {
		t.Fatalf("n=%d err=%v status=%s", n, err, r.store.jobs["j1"].Status)
	}
}

func TestReapNilSinkFailsClosed(t *testing.T) {
	r := newReapRig(nil)
	r.svc.Sink = nil
	r.add("j1", dbsim.JobKindRun, dbsim.JobPending, agentA, "t1", 1, past)
	n, err := r.svc.Reap(context.Background(), t0)
	if err == nil || n != 0 || r.store.jobs["j1"].Status != dbsim.JobPending {
		t.Fatalf("n=%d err=%v status=%s", n, err, r.store.jobs["j1"].Status)
	}
}

func TestReapStoreErrorDoesNotStopOthers(t *testing.T) {
	r := newReapRig(nil)
	r.add("j1", dbsim.JobKindRun, dbsim.JobPending, agentA, "t1", 1, past)
	r.add("j2", dbsim.JobKindRun, dbsim.JobPending, "bbbbbbbbbbbbbbbb", "t2", 1, past)
	r.store.failFor["j1"] = true
	n, err := r.svc.Reap(context.Background(), t0)
	if n != 1 || err == nil {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("error not redacted: %v", err)
	}
	if r.store.jobs["j2"].Status != dbsim.JobFailed || r.store.jobs["j1"].Status != dbsim.JobPending {
		t.Fatalf("j1=%s j2=%s", r.store.jobs["j1"].Status, r.store.jobs["j2"].Status)
	}
}

func TestReapRunningJobWithOnlineAgentNotExpiredIsUntouched(t *testing.T) {
	r := newReapRig(presence{agentA: true})
	r.add("j1", dbsim.JobKindRun, dbsim.JobRunning, agentA, "t1", 1, future)
	n, err := r.svc.Reap(context.Background(), t0)
	if err != nil || n != 0 || r.store.jobs["j1"].Status != dbsim.JobRunning {
		t.Fatalf("n=%d err=%v status=%s", n, err, r.store.jobs["j1"].Status)
	}
	// idempotent
	n, _ = r.svc.Reap(context.Background(), t0)
	if n != 0 {
		t.Fatalf("second reap n=%d", n)
	}
}
