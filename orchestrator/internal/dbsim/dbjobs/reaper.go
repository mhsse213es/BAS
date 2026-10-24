package dbjobs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/dbsim/dbadmin"
)

// DefaultOfflineGrace is how long an agent must be continuously offline before
// its running job is reaped (rides out reconnect blips).
const DefaultOfflineGrace = 60 * time.Second

// reaperActor is the audit actor of every reaper transition.
const reaperActor = "system:dbsim-reaper"

// AgentPresence says whether an agent is currently connected. The reaper never
// reaps on unknown: a nil Service.Presence skips the offline rule.
type AgentPresence interface {
	Online(agentID string) bool
}

// Reap settles jobs that can no longer finish and returns how many it moved.
//
// A job past its deadline, or a running job whose agent went offline, becomes
// failed when no result row was saved for it and partial when some were. An
// identity check has no run rows: it becomes failed and nothing else changes
// (the target's previous check is untouched; the target is simply free again).
//
// Every move is a guarded transition from pending or running, so a job that
// finished meanwhile is never touched (not counted, not an error). One job's
// store error does not stop the others; errors are redacted and joined. It is
// idempotent. A nil Sink fails closed: nothing is reaped and an error returns.
func (s *Service) Reap(ctx context.Context, now time.Time) (int, error) {
	if s.Jobs == nil {
		return 0, errors.New("dbsim: job store unavailable")
	}
	if s.Sink == nil {
		return 0, errors.New("dbsim: result sink unavailable: not reaping")
	}
	var errs []error
	seen := map[string]bool{}
	moved := 0
	reap := func(job dbsim.RunJob, cause string) {
		if seen[job.ID] {
			return
		}
		seen[job.ID] = true
		ok, err := s.reapOne(ctx, job, cause)
		if err != nil {
			errs = append(errs, redactErr(err))
			return
		}
		if ok {
			moved++
		}
	}

	expired, err := s.Jobs.Expired(ctx, now)
	if err != nil {
		errs = append(errs, redactf("dbsim: list expired jobs: %v", err))
	}
	for _, j := range expired {
		reap(j, "deadline")
	}

	if s.Presence != nil {
		running, err := s.Jobs.Running(ctx)
		if err != nil {
			errs = append(errs, redactf("dbsim: list running jobs: %v", err))
		} else {
			for _, j := range s.offlineDue(running, now) {
				reap(j, "offline")
			}
		}
	}
	return moved, errors.Join(errs...)
}

// offlineDue applies the offline grace: a running job whose agent is offline is
// due only once the agent has been seen offline continuously for OfflineGrace
// (first observation is recorded, not acted on). An online agent clears the
// entry; entries of jobs no longer in the running list are dropped (no leak).
func (s *Service) offlineDue(running []dbsim.RunJob, now time.Time) []dbsim.RunJob {
	grace := s.OfflineGrace
	if grace <= 0 {
		grace = DefaultOfflineGrace
	}
	s.offMu.Lock()
	defer s.offMu.Unlock()
	if s.offlineSince == nil {
		s.offlineSince = map[string]time.Time{}
	}
	live := make(map[string]bool, len(running))
	var due []dbsim.RunJob
	for _, j := range running {
		if j.Status != dbsim.JobRunning {
			continue
		}
		live[j.ID] = true
		if s.Presence.Online(j.AgentID) {
			delete(s.offlineSince, j.ID)
			continue
		}
		first, seen := s.offlineSince[j.ID]
		if !seen {
			s.offlineSince[j.ID] = now
			continue
		}
		if now.Sub(first) >= grace {
			due = append(due, j)
		}
	}
	for id := range s.offlineSince {
		if !live[id] {
			delete(s.offlineSince, id)
		}
	}
	return due
}

func (s *Service) reapOne(ctx context.Context, job dbsim.RunJob, cause string) (bool, error) {
	to, rows := dbsim.JobFailed, 0
	if job.Kind != dbsim.JobKindIdentityCheck {
		n, err := s.Sink.Count(ctx, job.ID)
		if err != nil {
			return false, fmt.Errorf("dbsim: count rows of %s: %w", job.ID, err)
		}
		rows = n
		if rows == 0 {
			// Re-count immediately before the transition so rows an Ingest saved
			// meanwhile make this partial, not failed. A residual window between
			// this count and the UPDATE is closed only by a store-level guard and
			// is tolerated.
			n2, err := s.Sink.Count(ctx, job.ID)
			if err != nil {
				return false, fmt.Errorf("dbsim: recount rows of %s: %w", job.ID, err)
			}
			rows = n2
		}
		if rows > 0 {
			to = dbsim.JobPartial
		}
	}
	reason := reapReason(cause, rows, len(job.ScenarioIDs))
	detail := map[string]any{
		"runId": job.ID, "targetId": job.TargetID, "agentId": job.AgentID,
		"was": string(job.Status), "kind": string(job.Kind), "cause": cause,
		"rowsSaved": rows, "scenariosPlanned": len(job.ScenarioIDs), "reason": dbsim.Redact(reason),
	}
	e := dbadmin.AuditEntry{ActorID: reaperActor, Action: "dbsim.run_" + string(to), Resource: "dbsim-run:" + job.ID, Detail: detail, Outcome: "ok"}
	ok, err := s.Jobs.Transition(ctx, job.ID, []dbsim.JobStatus{dbsim.JobPending, dbsim.JobRunning}, to, dbsim.Redact(reason), e)
	if err != nil {
		return false, fmt.Errorf("dbsim: reap %s: %w", job.ID, err)
	}
	return ok, nil
}

func reapReason(cause string, rows, planned int) string {
	if cause == "offline" {
		if rows == 0 {
			return "agent went offline"
		}
		return fmt.Sprintf("agent went offline: %d of %d scenarios saved", rows, planned)
	}
	if rows == 0 {
		return "deadline exceeded: no results received"
	}
	return fmt.Sprintf("deadline exceeded: %d of %d scenarios saved", rows, planned)
}
