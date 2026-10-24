// Package dbjobs is the start/cancel logic of database security simulation run
// jobs. A job is the pending-run record of one dispatched command_scenario (or of
// one read-only identity check): this package decides whether it may start,
// compiles and stores its plan, dispatches it to the target's bound agent and
// cancels it. The gates themselves (dbsim.Authorize, the client mode setting and
// the fresh passed identity check) stay in dbsim and dbbuild and are applied by
// dbbuild.BuildSteps; nothing here re-implements them.
//
// Every dependency is a small interface so the logic is testable without a
// database, a hub or Docker. Import rule R-AG: internal/dbsim, internal/db and
// internal/testutil never import this package.
package dbjobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/dbsim/dbadmin"
	"github.com/audspect/bas/internal/dbsim/dbbuild"
	"github.com/audspect/bas/internal/scenario"
)

// Sentinel errors. The HTTP layer maps them: ErrBusy 409, ErrNotPermitted 403,
// ErrAgentOffline 503, ErrTargetNotReady 409, ErrInvalidRequest and
// ErrConfirmationRequired 400, ErrNotActive 409.
var (
	// ErrBusy aliases dbsim.ErrJobBusy so the store (which cannot import this
	// package) and the service return the same error.
	ErrBusy                 = dbsim.ErrJobBusy
	ErrNotPermitted         = errors.New("dbsim: not permitted")
	ErrAgentOffline         = errors.New("dbsim: the target's agent is offline")
	ErrTargetNotReady       = errors.New("dbsim: target is not ready to run")
	ErrInvalidRequest       = errors.New("dbsim: invalid run request")
	ErrConfirmationRequired = errors.New("dbsim: lab run requires the target name typed as confirmation")
	ErrNotActive            = errors.New("dbsim: job is not active")
)

// JobStore persists jobs. Every mutation writes its audit row in the SAME
// transaction: if the audit row cannot be written the change does not happen.
type JobStore interface {
	// Create stores a new pending job; ErrBusy when the target or its agent
	// already has an active job (the store's partial unique indexes).
	Create(ctx context.Context, j dbsim.RunJob, audit dbadmin.AuditEntry) error
	// Get returns the job; dbsim.ErrJobNotFound when absent.
	Get(ctx context.Context, id string) (dbsim.RunJob, error)
	// Transition moves the job to `to` only if its status is one of `from`
	// (a guarded UPDATE) and reports whether a row changed.
	Transition(ctx context.Context, id string, from []dbsim.JobStatus, to dbsim.JobStatus, reason string, audit dbadmin.AuditEntry) (bool, error)
	ActiveForTarget(ctx context.Context, targetID string) (bool, error)
	ActiveForAgent(ctx context.Context, agentID string) (bool, error)
	// Expired lists active jobs whose deadline is before now.
	Expired(ctx context.Context, now time.Time) ([]dbsim.RunJob, error)
}

// Dispatcher sends a signed command_scenario to an agent. It reports whether the
// message was handed to a connected agent.
type Dispatcher interface {
	Dispatch(ctx context.Context, agentID string, cmd scenario.ScenarioCommand) (sent bool)
}

// Canceller sends command_cancel for a run to an agent (best effort).
type Canceller interface {
	Cancel(ctx context.Context, agentID, runID string) (sent bool)
}

// AgentActivity says whether an agent is running a normal scenario. The agent
// cancels its in-flight scenario on EVERY command_scenario, so a dbsim start
// must not interrupt one. The reverse (a normal run during a dbsim job) is not
// guarded here.
type AgentActivity interface {
	HasRunningScenario(ctx context.Context, agentID string) (bool, error)
}

// TargetReader reads registered targets (satisfied by dbadmin.TargetStore).
type TargetReader interface {
	Get(ctx context.Context, id string) (dbsim.TargetRecord, error)
}

// ScenarioSource looks up a loaded scenario (satisfied by *scenario.Engine).
type ScenarioSource interface {
	Get(id string) (*scenario.Scenario, bool)
}

// StartRequest is the run request. It deliberately has no mode: the mode is the
// target's.
type StartRequest struct {
	TargetID    string
	ScenarioIDs []string
	// LabConfirmation is the typed target name; it must equal the target id
	// exactly. Meaningful only for lab targets.
	LabConfirmation string
}

// Service starts and cancels jobs.
type Service struct {
	Targets    TargetReader
	Scenarios  ScenarioSource
	Jobs       JobStore
	Dispatcher Dispatcher
	Canceller  Canceller
	// Activity is required: nil refuses every start (fail closed).
	Activity AgentActivity
	// Gate is the Admin client mode setting (dbadmin.Service.Gate()). Nil is off.
	Gate dbsim.ClientModeGate
	// Audit receives best-effort rows for refusals (no state change).
	Audit dbadmin.Auditor
	// Now is the clock (default time.Now); MaxAge the identity check validity
	// (default dbsim.DefaultIdentityCheckMaxAge).
	Now    func() time.Time
	MaxAge time.Duration

	mu sync.Mutex // serialises check-then-create within this process
}

// maxScenariosPerRun bounds one request.
const maxScenariosPerRun = 25

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) maxAge() time.Duration {
	if s.MaxAge > 0 {
		return s.MaxAge
	}
	return dbsim.DefaultIdentityCheckMaxAge
}

func allowed(a dbadmin.Actor, p auth.Permission) bool {
	return a.ID != "" && auth.HasPermission(a.Role, p)
}

func entry(a dbadmin.Actor, action, resource string, detail map[string]any, outcome string) dbadmin.AuditEntry {
	return dbadmin.AuditEntry{ActorID: a.ID, Action: action, Resource: resource, Detail: detail, Outcome: outcome, IP: a.IP}
}

func (s *Service) refuse(a dbadmin.Actor, action, resource string, detail map[string]any, outcome string) {
	if s.Audit != nil {
		_ = s.Audit.Log(entry(a, action, resource, detail, outcome))
	}
}

func trunc(v string, n int) string {
	if len(v) > n {
		return v[:n]
	}
	return v
}

func newRunID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("dbjobs: random: %w", err)
	}
	return dbbuild.RunIDPrefix + hex.EncodeToString(b), nil
}

// loadTarget returns the record; an unknown target is "not ready".
func (s *Service) loadTarget(ctx context.Context, id string) (dbsim.TargetRecord, error) {
	if s.Targets == nil {
		return dbsim.TargetRecord{}, errors.New("dbsim: target store unavailable")
	}
	rec, err := s.Targets.Get(ctx, id)
	if err != nil {
		if errors.Is(err, dbsim.ErrTargetNotFound) {
			return dbsim.TargetRecord{}, fmt.Errorf("%w: target not found", ErrTargetNotReady)
		}
		return dbsim.TargetRecord{}, err
	}
	return rec, nil
}

// checkIdle refuses (ErrBusy) when the target or agent has an active job or the
// agent runs a normal scenario. Every uncertainty refuses. Caller holds s.mu.
func (s *Service) checkIdle(ctx context.Context, rec dbsim.TargetRecord) error {
	if s.Jobs == nil {
		return errors.New("dbsim: job store unavailable")
	}
	if busy, err := s.Jobs.ActiveForTarget(ctx, rec.ID); err != nil {
		return fmt.Errorf("dbsim: job lookup: %w", err)
	} else if busy {
		return fmt.Errorf("%w: target %q has an active job", ErrBusy, rec.ID)
	}
	if busy, err := s.Jobs.ActiveForAgent(ctx, rec.AgentID); err != nil {
		return fmt.Errorf("dbsim: job lookup: %w", err)
	} else if busy {
		return fmt.Errorf("%w: the target's agent has an active job", ErrBusy)
	}
	if s.Activity == nil {
		return fmt.Errorf("%w: agent activity is unknown", ErrBusy)
	}
	running, err := s.Activity.HasRunningScenario(ctx, rec.AgentID)
	if err != nil {
		return fmt.Errorf("%w: agent activity could not be read", ErrBusy)
	}
	if running {
		return fmt.Errorf("%w: the target's agent is running a scenario (starting would cancel it)", ErrBusy)
	}
	return nil
}

// Start validates, stores and dispatches a run job. Mode comes from the target.
//
// Lab target: CanRunScenario plus the typed target name. Client target: Admin
// only, plus the client mode setting and a fresh passed identity check (both
// enforced by dbbuild.BuildSteps through dbsim.Authorize).
func (s *Service) Start(ctx context.Context, a dbadmin.Actor, req StartRequest) (dbsim.RunJob, error) {
	const action = "dbsim.run_started"
	resource := "dbsim-target:" + trunc(req.TargetID, 64)
	if !allowed(a, auth.CanRunScenario) {
		s.refuse(a, action, resource, nil, "denied")
		return dbsim.RunJob{}, ErrNotPermitted
	}
	fail := func(err error) (dbsim.RunJob, error) {
		s.refuse(a, action, resource, map[string]any{"error": err.Error()}, "error")
		return dbsim.RunJob{}, err
	}
	if req.TargetID == "" {
		return fail(fmt.Errorf("%w: targetId is required", ErrInvalidRequest))
	}
	if n := len(req.ScenarioIDs); n == 0 || n > maxScenariosPerRun {
		return fail(fmt.Errorf("%w: select between 1 and %d scenarios", ErrInvalidRequest, maxScenariosPerRun))
	}
	if s.Scenarios == nil {
		return dbsim.RunJob{}, errors.New("dbsim: scenario source unavailable")
	}
	scs := make([]*scenario.Scenario, 0, len(req.ScenarioIDs))
	seen := map[string]bool{}
	for _, id := range req.ScenarioIDs {
		if seen[id] {
			return fail(fmt.Errorf("%w: scenario %q is selected twice", ErrInvalidRequest, trunc(id, 64)))
		}
		seen[id] = true
		sc, ok := s.Scenarios.Get(id)
		if !ok || sc == nil || sc.ProductLine != scenario.ProductLineDBSim {
			return fail(fmt.Errorf("%w: %q is not an available dbsim scenario", ErrInvalidRequest, trunc(id, 64)))
		}
		scs = append(scs, sc)
	}

	rec, err := s.loadTarget(ctx, req.TargetID)
	if err != nil {
		return fail(err)
	}
	// Mode comes from the target, never the request.
	switch rec.Mode {
	case dbsim.ModeClient:
		if !allowed(a, auth.CanManageDBSimTargets) || !allowed(a, auth.CanSetDBSimClientMode) {
			s.refuse(a, action, resource, map[string]any{"mode": string(rec.Mode)}, "denied")
			return dbsim.RunJob{}, ErrNotPermitted
		}
	case dbsim.ModeLab:
		if req.LabConfirmation != rec.ID {
			return fail(ErrConfirmationRequired)
		}
	default:
		return fail(fmt.Errorf("%w: target has an invalid mode", ErrTargetNotReady))
	}

	s.mu.Lock()
	unlock := sync.OnceFunc(s.mu.Unlock)
	defer unlock()
	if err := s.checkIdle(ctx, rec); err != nil {
		return fail(err)
	}

	now := s.now()
	runID, err := newRunID()
	if err != nil {
		return dbsim.RunJob{}, err
	}
	deadline := dbsim.DeadlineFor(now, len(scs))
	target := rec.ToTargetAt(now, s.maxAge())
	opt := dbbuild.Options{
		Resolver: dbsim.NewMemoryResolver(target), ClientGate: s.Gate,
		// The typed target name is the operator's approval of a lab run's
		// bounded_synthetic probes; Authorize still needs the target's own
		// LabConfirmed. A client run never carries it.
		MutationApproved: rec.Mode == dbsim.ModeLab,
		RunExpiry:        deadline, Now: s.now, RunID: runID,
	}

	var (
		plan  []dbsim.PlannedStep
		steps []scenario.ScenarioStep
		tasks = map[string]bool{}
	)
	for _, orig := range scs {
		cp := *orig
		cp.Steps = append([]scenario.Step(nil), orig.Steps...)
		for i := range cp.Steps {
			cp.Steps[i].DBTarget = rec.ID // the target is the request's, whatever the YAML named
		}
		built, err := dbbuild.BuildSteps(ctx, &cp, opt)
		if err != nil {
			return fail(fmt.Errorf("%w: scenario %q: %v", ErrTargetNotReady, trunc(orig.ID, 64), err))
		}
		for i, st := range built {
			var spec dbsim.DBProbeSpec
			if err := json.Unmarshal(st.DBProbe, &spec); err != nil {
				return fail(fmt.Errorf("dbsim: compiled step is not a probe spec: %w", err))
			}
			if _, err := dbbuild.MetaFor(orig, spec); err != nil {
				return fail(fmt.Errorf("%w: scenario %q has no grading expectations", ErrInvalidRequest, trunc(orig.ID, 64)))
			}
			if tasks[st.TaskID] {
				return fail(fmt.Errorf("%w: scenarios share a step (%q); select them in separate runs", ErrInvalidRequest, trunc(st.Name, 64)))
			}
			tasks[st.TaskID] = true
			plan = append(plan, dbsim.PlannedStep{ScenarioID: orig.ID, Index: i, TaskID: st.TaskID, Spec: spec})
		}
		steps = append(steps, built...)
	}

	job := dbsim.RunJob{
		ID: runID, Kind: dbsim.JobKindRun, TargetID: rec.ID, AgentID: rec.AgentID, Mode: rec.Mode,
		ScenarioIDs: append([]string(nil), req.ScenarioIDs...), Plan: plan, Status: dbsim.JobPending,
		CreatedBy: a.ID, CreatedAt: now, Deadline: deadline,
	}
	if rec.Mode == dbsim.ModeLab {
		job.LabConfirmation = req.LabConfirmation
	}
	name, scID := "Database security simulation", "dbsim-run"
	if len(scs) == 1 {
		name, scID = scs[0].Name, scs[0].ID
	}
	detail := map[string]any{
		"runId": runID, "targetId": rec.ID, "agentId": rec.AgentID, "mode": string(rec.Mode),
		"scenarioIds": job.ScenarioIDs, "deadline": deadline.Format(time.RFC3339),
	}
	if job.LabConfirmation != "" {
		detail["labConfirmation"] = job.LabConfirmation
	}
	return s.createAndDispatch(ctx, a, job, entry(a, action, "dbsim-run:"+runID, detail, "ok"),
		scenario.ScenarioCommand{RunID: runID, ScenarioID: scID, Name: name, Steps: steps}, unlock)
}

// StartIdentityCheck runs the read-only check_readonly_identity probe on the
// target's bound agent as a job. Admin only; the one-active-job rule applies.
// The result is recorded by the ingest (Task 5), not here.
func (s *Service) StartIdentityCheck(ctx context.Context, a dbadmin.Actor, targetID string) (dbsim.RunJob, error) {
	const action = "dbsim.identity_check_started"
	resource := "dbsim-target:" + trunc(targetID, 64)
	if !allowed(a, auth.CanManageDBSimTargets) {
		s.refuse(a, action, resource, nil, "denied")
		return dbsim.RunJob{}, ErrNotPermitted
	}
	fail := func(err error) (dbsim.RunJob, error) {
		s.refuse(a, action, resource, map[string]any{"error": err.Error()}, "error")
		return dbsim.RunJob{}, err
	}
	rec, err := s.loadTarget(ctx, targetID)
	if err != nil {
		return fail(err)
	}
	s.mu.Lock()
	unlock := sync.OnceFunc(s.mu.Unlock)
	defer unlock()
	if err := s.checkIdle(ctx, rec); err != nil {
		return fail(err)
	}
	now := s.now()
	runID, err := newRunID()
	if err != nil {
		return dbsim.RunJob{}, err
	}
	deadline := dbsim.DeadlineFor(now, 1)
	step, spec, err := dbbuild.BuildIdentityCheckStep(ctx, rec.ToTargetAt(now, s.maxAge()),
		dbbuild.Options{RunExpiry: deadline, Now: s.now, RunID: runID})
	if err != nil {
		return fail(fmt.Errorf("%w: %v", ErrTargetNotReady, err))
	}
	job := dbsim.RunJob{
		ID: runID, Kind: dbsim.JobKindIdentityCheck, TargetID: rec.ID, AgentID: rec.AgentID, Mode: rec.Mode,
		ScenarioIDs: []string{}, Plan: []dbsim.PlannedStep{{Index: 0, TaskID: step.TaskID, Spec: spec}}, Status: dbsim.JobPending,
		CreatedBy: a.ID, CreatedAt: now, Deadline: deadline,
	}
	detail := map[string]any{"runId": runID, "targetId": rec.ID, "agentId": rec.AgentID, "mode": string(rec.Mode),
		"deadline": deadline.Format(time.RFC3339)}
	return s.createAndDispatch(ctx, a, job, entry(a, action, "dbsim-run:"+runID, detail, "ok"),
		scenario.ScenarioCommand{RunID: runID, ScenarioID: "dbsim-identity-check", Name: step.Name, Steps: []scenario.ScenarioStep{step}}, unlock)
}

// createAndDispatch stores the pending job with its audit row, sends the
// command and moves the job: running when delivered, failed (ErrAgentOffline)
// when not. The caller holds s.mu; unlock is called as soon as the job row
// exists (the row is what refuses a concurrent start) so the mutex is never held
// across Dispatch.
func (s *Service) createAndDispatch(ctx context.Context, a dbadmin.Actor, job dbsim.RunJob, created dbadmin.AuditEntry, cmd scenario.ScenarioCommand, unlock func()) (dbsim.RunJob, error) {
	err := s.Jobs.Create(ctx, job, created)
	unlock()
	if err != nil {
		if errors.Is(err, dbsim.ErrJobBusy) {
			s.refuse(a, created.Action, created.Resource, map[string]any{"error": "store: an active job exists"}, "error")
			return dbsim.RunJob{}, fmt.Errorf("%w: another job became active", ErrBusy)
		}
		return dbsim.RunJob{}, fmt.Errorf("dbsim: store job: %w", err)
	}
	resource := "dbsim-run:" + job.ID
	if s.Dispatcher == nil || !s.Dispatcher.Dispatch(ctx, job.AgentID, cmd) {
		reason := "agent is offline: the command was not delivered"
		fa := entry(a, "dbsim.run_failed", resource, map[string]any{"runId": job.ID, "reason": reason}, "error")
		if _, err := s.Jobs.Transition(ctx, job.ID, []dbsim.JobStatus{dbsim.JobPending}, dbsim.JobFailed, reason, fa); err != nil {
			return job, errors.Join(ErrAgentOffline, fmt.Errorf("dbsim: mark job failed: %w", err))
		}
		job.Status, job.Reason = dbsim.JobFailed, reason
		return job, ErrAgentOffline
	}
	ra := entry(a, "dbsim.run_dispatched", resource, map[string]any{"runId": job.ID, "agentId": job.AgentID}, "ok")
	moved, err := s.Jobs.Transition(ctx, job.ID, []dbsim.JobStatus{dbsim.JobPending}, dbsim.JobRunning, "", ra)
	if err != nil {
		// The command WAS sent, so the start succeeded. The record stays pending
		// and the deadline reaper settles it (or the agent's result does).
		log.Printf("dbsim: job %s dispatched but could not be marked running (left pending for the reaper): %v", job.ID, err)
		return job, nil
	}
	if moved {
		job.Status, job.StartedAt = dbsim.JobRunning, s.now()
		return job, nil
	}
	// Zero rows: the job already left pending (the agent's result, a cancel or
	// the reaper got there first). The guarded UPDATE did not resurrect it;
	// report the stored state.
	if cur, gerr := s.Jobs.Get(ctx, job.ID); gerr == nil {
		return cur, nil
	}
	return job, nil
}

// Cancel cancels an active job. It uses the permission that starts a run. The
// record is moved first (so a late result cannot revive it), then command_cancel
// is sent best effort; an unreachable agent still leaves the job cancelled.
func (s *Service) Cancel(ctx context.Context, a dbadmin.Actor, runID string) error {
	const action = "dbsim.run_cancelled"
	resource := "dbsim-run:" + trunc(runID, 80)
	if !allowed(a, auth.CanRunScenario) {
		s.refuse(a, action, resource, nil, "denied")
		return ErrNotPermitted
	}
	if s.Jobs == nil {
		return errors.New("dbsim: job store unavailable")
	}
	job, err := s.Jobs.Get(ctx, runID)
	if err != nil {
		return err
	}
	if !job.Status.Active() {
		return ErrNotActive
	}
	ca := entry(a, action, resource, map[string]any{"runId": job.ID, "targetId": job.TargetID, "agentId": job.AgentID, "was": string(job.Status)}, "ok")
	moved, err := s.Jobs.Transition(ctx, job.ID, []dbsim.JobStatus{dbsim.JobPending, dbsim.JobRunning}, dbsim.JobCancelled, "cancelled by "+a.ID, ca)
	if err != nil {
		return fmt.Errorf("dbsim: cancel job: %w", err)
	}
	if !moved {
		return ErrNotActive
	}
	if s.Canceller != nil {
		_ = s.Canceller.Cancel(ctx, job.AgentID, job.ID)
	}
	return nil
}
