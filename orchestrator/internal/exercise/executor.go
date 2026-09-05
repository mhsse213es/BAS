package exercise

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/audspect/bas/internal/detect"
	"github.com/audspect/bas/internal/observability"
	"github.com/audspect/bas/internal/verification"
)

// cryptoRandRead is a package-level alias so tests can stub it.
var cryptoRandRead = crand.Read

// Executor is the DAG runtime for exercise executions.
// It advances step state machines and fires registered step handlers.
// The polling cadence is controlled by the injected Scheduler.
type Executor struct {
	store        *Store
	evidence     *EvidenceChain
	registry     *Registry
	triggers     *TriggerRegistry
	scheduler    Scheduler
	dispatch     AgentDispatchFn
	verification VerificationReader
	metrics      *observability.MetricsRegistry
}

// VerificationReader is the narrow read interface the detection bridge
// needs from internal/verification.Store — kept narrow so internal/exercise
// does not take a hard dependency on the whole verification package
// surface. *verification.Store satisfies it.
type VerificationReader interface {
	CurrentApprovedForRun(ctx context.Context, runID string) ([]verification.Record, error)
}

// NewExecutor builds an Executor with a pluggable Registry and Scheduler.
// Call RegisterBuiltins() and RegisterBuiltinTriggers() afterwards.
func NewExecutor(store *Store, evidence *EvidenceChain, registry *Registry, scheduler Scheduler, dispatch AgentDispatchFn) *Executor {
	return &Executor{
		store:     store,
		evidence:  evidence,
		registry:  registry,
		triggers:  NewTriggerRegistry(),
		scheduler: scheduler,
		dispatch:  dispatch,
	}
}

// WithMetrics attaches a metrics registry for observability instrumentation.
func (e *Executor) WithMetrics(reg *observability.MetricsRegistry) *Executor {
	e.metrics = reg
	return e
}

// SetDispatch wires the BAS run dispatch function after construction.
// Call this after the API handler is created (avoids import cycle).
func (e *Executor) SetDispatch(fn AgentDispatchFn) { e.dispatch = fn }

// WithTriggers replaces the trigger registry (useful in tests).
func (e *Executor) WithTriggers(t *TriggerRegistry) *Executor {
	e.triggers = t
	return e
}

// WithVerification wires the verification-store reader the detection bridge
// uses. Nil-safe: a wait_for_detection step with ExecutionStepID set but no
// verification reader configured behaves as if ExecutionStepID were empty.
func (e *Executor) WithVerification(v VerificationReader) *Executor {
	e.verification = v
	return e
}

// Start begins the scheduler loop.
func (e *Executor) Start() {
	e.scheduler.Start(func(ctx context.Context) {
		if err := e.tick(ctx); err != nil {
			log.Printf("[exercise] tick: %v", err)
		}
	})
}

// Stop shuts down the scheduler.
func (e *Executor) Stop() { e.scheduler.Stop() }

// RegisterBuiltins wires the standard step handlers into the registry.
func (e *Executor) RegisterBuiltins(smtp *SMTPInjector, sms *SMSInjector, slack *SlackInjector, teams *TeamsInjector) {
	e.registry.Register(StepTypeSendEmail, StepHandlerFunc(e.handleSendEmail(smtp)))
	e.registry.Register(StepTypeSendSMS, StepHandlerFunc(e.handleSendSMS(sms)))
	e.registry.Register(StepTypeAgentTask, StepHandlerFunc(e.handleAgentTask))
	e.registry.Register(StepTypeWait, StepHandlerFunc(e.handleWait))
	e.registry.Register(StepTypeApproval, StepHandlerFunc(e.handleApproval))
	e.registry.Register(StepTypeWebhook, StepHandlerFunc(e.handleWebhook))
	e.registry.Register(StepTypeNotify, StepHandlerFunc(e.handleNotify))
	e.registry.Register(StepTypeSlack, StepHandlerFunc(e.handleSlack(slack)))
	e.registry.Register(StepTypeTeams, StepHandlerFunc(e.handleTeams(teams)))
	// Event-based wait steps: enter StepWaiting immediately, then the
	// trigger registry fires them when the condition is satisfied.
	e.registry.Register(StepTypeWaitForAgent, StepHandlerFunc(e.handleWaitForAgent))
	e.registry.Register(StepTypeWaitForDetection, StepHandlerFunc(e.handleWaitForDetection))
	e.registry.Register(StepTypeWaitForWebhook, StepHandlerFunc(e.handleWaitForWebhook))
}

// RegisterBuiltinTriggers wires the event-driven trigger functions.
func (e *Executor) RegisterBuiltinTriggers() {
	e.triggers.Register(StepTypeWaitForAgent, e.triggerWaitForAgent)
	e.triggers.Register(StepTypeWaitForDetection, e.triggerWaitForDetection)
	e.triggers.Register(StepTypeWaitForWebhook, e.triggerWaitForWebhook)
	e.triggers.Register(StepTypeAgentTask, e.triggerWaitForBASDetection)
}

func (e *Executor) tick(ctx context.Context) error {
	execs, err := e.store.ListRunningExecutions(ctx)
	if err != nil {
		return err
	}
	for i := range execs {
		if execs[i].Status == ExecPaused {
			continue
		}
		if err := e.advance(ctx, &execs[i]); err != nil {
			log.Printf("[exercise] advance exec %s: %v", execs[i].ID, err)
		}
	}
	return nil
}

func (e *Executor) advance(ctx context.Context, ex *Execution) error {
	plan, err := e.store.GetPlan(ctx, ex.PlanID)
	if err != nil {
		return err
	}
	stepExecs, err := e.store.ListStepExecutions(ctx, ex.ID)
	if err != nil {
		return err
	}

	byID := make(map[string]*StepExecution, len(stepExecs))
	for i := range stepExecs {
		byID[stepExecs[i].StepID] = &stepExecs[i]
	}

	done := map[string]bool{}
	for _, se := range stepExecs {
		if se.Status == StepCompleted || se.Status == StepSkipped ||
			se.Status == StepFailed || se.Status == StepCancelled {
			done[se.StepID] = true
		}
	}

	// Fire triggers and advance timeout-expired wait steps.
	now := time.Now()
	for i := range plan.Steps {
		ps := &plan.Steps[i]
		se, ok := byID[ps.ID]
		if !ok || se.Status != StepWaiting {
			continue
		}

		// Check registered trigger (wait_for_agent, wait_for_detection, wait_for_webhook).
		if e.triggers.Has(ps.Type) {
			triggered, payload, trigErr := e.triggers.Check(ctx, ex, ps, se)
			if trigErr != nil {
				log.Printf("[exercise] trigger %s/%s: %v", ex.ID, ps.ID, trigErr)
			} else if triggered {
				merged := mergeMaps(se.Result, payload)
				_ = e.store.SetStepResult(ctx, ex.ID, ps.ID, merged)
				_ = e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepCompleted, "")
				_, _ = e.evidence.Append(ctx, ex.ID, se.ID, "trigger_fired", "system", "trigger_registry",
					map[string]any{"step_type": string(ps.Type), "payload": payload})
				_ = e.store.RecordEvent(ctx, ex.ID, ps.ID, "step_completed", "system", payload)
				if e.metrics != nil && se.StartedAt != nil {
					duration := time.Since(*se.StartedAt).Seconds()
					e.metrics.ExecutionDuration.WithLabelValues(string(ps.Type)).Observe(duration)
				}
				done[ps.ID] = true
				continue
			}
		}

		// Timeout for generic wait steps.
		if ps.Type == StepTypeWait && se.ScheduledAt != nil && now.After(*se.ScheduledAt) {
			_ = e.store.SetStepResult(ctx, ex.ID, ps.ID, map[string]any{"timed_out": true})
			_ = e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepCompleted, "")
			_ = e.store.RecordEvent(ctx, ex.ID, ps.ID, "timeout", "system", nil)
			if e.metrics != nil && se.StartedAt != nil {
				duration := time.Since(*se.StartedAt).Seconds()
				e.metrics.ExecutionDuration.WithLabelValues(string(ps.Type)).Observe(duration)
			}
			done[ps.ID] = true
		}

		// Timeout for approval steps.
		if ps.Type == StepTypeApproval && ps.TimeoutSecs > 0 && se.StartedAt != nil {
			if now.After(se.StartedAt.Add(time.Duration(ps.TimeoutSecs) * time.Second)) {
				_ = e.store.SetStepResult(ctx, ex.ID, ps.ID, map[string]any{"timed_out": true, "approved": false})
				_ = e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepCompleted, "timeout")
				_ = e.store.RecordEvent(ctx, ex.ID, ps.ID, "timeout", "system", nil)
				done[ps.ID] = true
			}
		}

		// Global timeout for event-based waits (wait_for_*).
		if ps.TimeoutSecs > 0 && se.StartedAt != nil &&
			now.After(se.StartedAt.Add(time.Duration(ps.TimeoutSecs)*time.Second)) {
			switch ps.Type {
			case StepTypeWaitForAgent, StepTypeWaitForDetection, StepTypeWaitForWebhook:
				_ = e.store.SetStepResult(ctx, ex.ID, ps.ID, mergeMaps(se.Result, map[string]any{"timed_out": true}))
				_ = e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepCompleted, "timeout")
				_ = e.store.RecordEvent(ctx, ex.ID, ps.ID, "timeout", "system", nil)
				done[ps.ID] = true
			}
		}
	}

	// Track 2: score exercise-native detection (phishing_reported) for
	// completed send_email steps not yet scored. Separate pass from the
	// trigger loop above -- this operates on already-StepCompleted steps
	// (an enrichment pass), not StepWaiting ones.
	planStepByID := make(map[string]*PlanStep, len(plan.Steps))
	for i := range plan.Steps {
		planStepByID[plan.Steps[i].ID] = &plan.Steps[i]
	}
	for i := range stepExecs {
		se := &stepExecs[i]
		if se.StepType != StepTypeSendEmail || se.Status != StepCompleted {
			continue
		}
		if _, scored := se.Result["detection_verdict"]; scored {
			continue
		}
		matchedStep, ok := planStepByID[se.StepID]
		if !ok {
			continue
		}
		if err := e.scoreExerciseNativeDetection(ctx, ex, matchedStep, se); err != nil {
			log.Printf("[exercise] score detection %s/%s: %v", ex.ID, se.StepID, err)
		}
	}

	// Check completion.
	allDone := true
	for _, ps := range plan.Steps {
		se, ok := byID[ps.ID]
		if !ok || (se.Status != StepCompleted && se.Status != StepSkipped &&
			se.Status != StepFailed && se.Status != StepCancelled) {
			allDone = false
			break
		}
	}
	if allDone {
		score := e.computeScore(ctx, ex)
		_ = e.store.UpdateExecutionScore(ctx, ex.ID, score)
		_ = e.store.RecordEvent(ctx, ex.ID, "", "completed", "system", nil)
		return e.store.UpdateExecutionStatus(ctx, ex.ID, ExecCompleted)
	}

	// Dispatch ready pending steps.
	for _, ps := range plan.Steps {
		se := byID[ps.ID]
		if se != nil && se.Status != StepPending {
			continue
		}
		ready := true
		for _, dep := range ps.DependsOn {
			if !done[dep] {
				ready = false
				break
			}
		}
		if !ready {
			continue
		}
		stepAgentID := ""
		if ps.Config.AgentTask != nil {
			stepAgentID = ps.Config.AgentTask.AgentID
		}
		if !e.evalCondition(ctx, ps.Condition, ex.ID, byID, stepAgentID) {
			_ = e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepSkipped, "condition false")
			_ = e.store.RecordEvent(ctx, ex.ID, ps.ID, "skipped", "system", map[string]any{"reason": "condition false"})
			if e.metrics != nil && se != nil && se.StartedAt != nil {
				duration := time.Since(*se.StartedAt).Seconds()
				e.metrics.ExecutionDuration.WithLabelValues(string(ps.Type)).Observe(duration)
			}
			continue
		}
		if se == nil {
			newSE := &StepExecution{ExecutionID: ex.ID, StepID: ps.ID, StepType: ps.Type, Status: StepPending}
			if err := e.store.UpsertStepExecution(ctx, newSE); err != nil {
				log.Printf("[exercise] create step_exec %s/%s: %v", ex.ID, ps.ID, err)
				continue
			}
			if err := e.store.UpsertExecutionAttempt(ctx, newSE); err != nil {
				log.Printf("[phase0b] upsert execution_attempt for step %s: %v", newSE.ID, err)
			}
			se = newSE
		}
		// Phase 0A: Record when this step was selected for dispatch
		now := time.Now()
		se.PollSelectedAt = &now
		log.Printf("[perf] execution_id=%s poll_selected_at=%s", se.ExecutionID, now.Format(time.RFC3339Nano))
		if err := e.dispatchStep(ctx, ex, &ps, se); err != nil {
			log.Printf("[exercise] dispatch %s/%s: %v", ex.ID, ps.ID, err)
			_ = e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepFailed, err.Error())
			_ = e.store.RecordEvent(ctx, ex.ID, ps.ID, "failed", "system", map[string]any{"error": err.Error()})
			if e.metrics != nil && se.StartedAt != nil {
				duration := time.Since(*se.StartedAt).Seconds()
				e.metrics.ExecutionDuration.WithLabelValues(string(ps.Type)).Observe(duration)
				e.metrics.ExecutionErrors.WithLabelValues(string(ps.Type), "dispatch_error").Inc()
			}
		}
	}
	return nil
}

func (e *Executor) dispatchStep(ctx context.Context, ex *Execution, ps *PlanStep, se *StepExecution) error {
	_ = e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepRunning, "")
	_ = e.store.RecordEvent(ctx, ex.ID, ps.ID, "step_running", "system", nil)

	// Resolve ${VarName} in the step config before handing to the registry.
	resolved := *ps
	if len(ex.Variables) > 0 {
		if plan, perr := e.store.GetPlan(ctx, ex.PlanID); perr == nil {
			r := NewResolver(plan.Variables, ex.Variables, ex.ID, ex.InitiatedBy)
			if cfg, rerr := r.ResolveStepConfig(ps.Config); rerr == nil {
				resolved.Config = cfg
			}
		}
	}
	return e.registry.Dispatch(ctx, ex, &resolved, se)
}

// ── Built-in step handlers ────────────────────────────────────────────────────

func (e *Executor) handleSendEmail(smtp *SMTPInjector) func(context.Context, *Execution, *PlanStep, *StepExecution) error {
	return func(ctx context.Context, ex *Execution, ps *PlanStep, se *StepExecution) error {
		if smtp == nil {
			_ = e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepFailed, "SMTP not configured")
			return nil
		}
		cfg := ps.Config.Email
		if cfg == nil {
			_ = e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepFailed, "missing email config")
			return nil
		}
		go func() {
			bctx := context.Background()
			result, err := smtp.Send(bctx, se.ID, ex.ID, cfg, ex.Targets)
			if err != nil {
				_ = e.store.SetStepStatus(bctx, ex.ID, ps.ID, StepFailed, err.Error())
				return
			}
			_ = e.store.SetStepResult(bctx, ex.ID, ps.ID, result)
			_ = e.store.SetStepStatus(bctx, ex.ID, ps.ID, StepCompleted, "")
			_, _ = e.evidence.Append(bctx, ex.ID, se.ID, "email_sent", "system", "smtp_injector", result)
			_ = e.store.RecordEvent(bctx, ex.ID, ps.ID, "step_completed", "system", result)
		}()
		return nil
	}
}

func (e *Executor) handleSendSMS(sms *SMSInjector) func(context.Context, *Execution, *PlanStep, *StepExecution) error {
	return func(ctx context.Context, ex *Execution, ps *PlanStep, se *StepExecution) error {
		if sms == nil {
			return e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepFailed, "SMS gateway not configured")
		}
		cfg := ps.Config.SMS
		if cfg == nil {
			return e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepFailed, "missing sms config")
		}
		go func() {
			bctx := context.Background()
			result, err := sms.Send(bctx, cfg.To, cfg.Body)
			if err != nil {
				_ = e.store.SetStepStatus(bctx, ex.ID, ps.ID, StepFailed, err.Error())
				return
			}
			_ = e.store.SetStepResult(bctx, ex.ID, ps.ID, result)
			_ = e.store.SetStepStatus(bctx, ex.ID, ps.ID, StepCompleted, "")
			_, _ = e.evidence.Append(bctx, ex.ID, se.ID, "sms_sent", "system", "sms_injector", result)
			_ = e.store.RecordEvent(bctx, ex.ID, ps.ID, "step_completed", "system", result)
		}()
		return nil
	}
}

func (e *Executor) handleSlack(slack *SlackInjector) func(context.Context, *Execution, *PlanStep, *StepExecution) error {
	return func(ctx context.Context, ex *Execution, ps *PlanStep, se *StepExecution) error {
		if slack == nil {
			return e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepFailed, "Slack not configured")
		}
		cfg := ps.Config.Slack
		if cfg == nil {
			return e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepFailed, "missing slack config")
		}
		go func() {
			bctx := context.Background()
			result, err := slack.Send(bctx, cfg.Text)
			if err != nil {
				_ = e.store.SetStepStatus(bctx, ex.ID, ps.ID, StepFailed, err.Error())
				return
			}
			_ = e.store.SetStepResult(bctx, ex.ID, ps.ID, result)
			_ = e.store.SetStepStatus(bctx, ex.ID, ps.ID, StepCompleted, "")
			_, _ = e.evidence.Append(bctx, ex.ID, se.ID, "slack_sent", "system", "slack_injector", result)
			_ = e.store.RecordEvent(bctx, ex.ID, ps.ID, "step_completed", "system", result)
		}()
		return nil
	}
}

func (e *Executor) handleTeams(teams *TeamsInjector) func(context.Context, *Execution, *PlanStep, *StepExecution) error {
	return func(ctx context.Context, ex *Execution, ps *PlanStep, se *StepExecution) error {
		if teams == nil {
			return e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepFailed, "Teams not configured")
		}
		cfg := ps.Config.Teams
		if cfg == nil {
			return e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepFailed, "missing teams config")
		}
		go func() {
			bctx := context.Background()
			result, err := teams.Send(bctx, cfg.Text)
			if err != nil {
				_ = e.store.SetStepStatus(bctx, ex.ID, ps.ID, StepFailed, err.Error())
				return
			}
			_ = e.store.SetStepResult(bctx, ex.ID, ps.ID, result)
			_ = e.store.SetStepStatus(bctx, ex.ID, ps.ID, StepCompleted, "")
			_, _ = e.evidence.Append(bctx, ex.ID, se.ID, "teams_sent", "system", "teams_injector", result)
			_ = e.store.RecordEvent(bctx, ex.ID, ps.ID, "step_completed", "system", result)
		}()
		return nil
	}
}

func (e *Executor) handleAgentTask(ctx context.Context, ex *Execution, ps *PlanStep, se *StepExecution) error {
	cfg := ps.Config.AgentTask
	if cfg == nil || (cfg.ScenarioID == "" && cfg.TechniqueID == "") {
		return e.store.SetStepStatus(context.Background(), ex.ID, ps.ID, StepFailed, "missing agent_task config")
	}
	if e.dispatch == nil {
		return e.store.SetStepStatus(context.Background(), ex.ID, ps.ID, StepFailed, "agent dispatch not configured")
	}
	go func() {
		bctx := context.Background()
		// Add correlation IDs for observability
		bctx = observability.WithRunID(bctx, ex.ID)
		bctx = observability.WithTaskID(bctx, ps.ID)
		if cfg.AgentID != "" {
			bctx = observability.WithAgentID(bctx, cfg.AgentID)
		}
		// Record dispatch latency
		start := time.Now()
		runID, err := e.dispatch(cfg.AgentID, cfg.ScenarioID, cfg.TechniqueID, ex.ExecutionPolicy)
		dispatchDuration := time.Since(start)
		if e.metrics != nil {
			e.metrics.AgentDispatchLatency.WithLabelValues(cfg.AgentID).Observe(dispatchDuration.Seconds())
		}
		if err != nil {
			_ = e.store.SetStepStatus(bctx, ex.ID, ps.ID, StepFailed, err.Error())
			return
		}
		// Phase 0A: Record when dispatch was sent
		dispatchSentTime := time.Now()
		se.DispatchSentAt = &dispatchSentTime
		log.Printf("[perf] execution_id=%s dispatch_sent_at=%s", se.ExecutionID, dispatchSentTime.Format(time.RFC3339Nano))
		// Phase 1: wait for detection (Track 1) instead of completing
		// immediately -- see triggerWaitForBASDetection, registered against
		// this same StepTypeAgentTask in RegisterBuiltinTriggers.
		se.Status = StepWaiting
		se.StartedAt = &dispatchSentTime
		se.Result = map[string]any{"bas_run_id": runID}
		if err := e.store.UpsertStepExecution(bctx, se); err != nil {
			log.Printf("[exercise] agent_task %s/%s: upsert waiting state: %v", ex.ID, ps.ID, err)
			return
		}
		// UpsertStepExecution (unlike SetStepStatus) does not itself mirror
		// ExecutionAttempt -- every other raw-upsert transition into
		// StepWaiting (handleWait, handleApproval, handleWaitForAgent) makes
		// this same explicit call afterward.
		if err := e.store.UpsertExecutionAttempt(bctx, se); err != nil {
			log.Printf("[phase0b] upsert execution_attempt for step %s: %v", se.ID, err)
		}
		_, _ = e.evidence.Append(bctx, ex.ID, se.ID, "agent_task_dispatched", "system", "bas_engine",
			map[string]any{"run_id": runID, "agent_id": cfg.AgentID})
		_ = e.store.RecordEvent(bctx, ex.ID, ps.ID, "step_waiting", "system", map[string]any{"waiting_for": "bas_run_detection", "bas_run_id": runID})
	}()
	return nil
}

func (e *Executor) handleWait(_ context.Context, ex *Execution, ps *PlanStep, se *StepExecution) error {
	d, err := time.ParseDuration(ps.Config.WaitDuration)
	if err != nil || d <= 0 {
		d = time.Hour
	}
	deadline := time.Now().Add(d)
	se.ScheduledAt = &deadline
	se.Status = StepWaiting
	_ = e.store.RecordEvent(context.Background(), ex.ID, ps.ID, "step_waiting",
		"system", map[string]any{"wait_until": deadline})
	if err := e.store.UpsertStepExecution(context.Background(), se); err != nil {
		return err
	}
	if err := e.store.UpsertExecutionAttempt(context.Background(), se); err != nil {
		log.Printf("[phase0b] upsert execution_attempt for step %s: %v", se.ID, err)
	}
	return nil
}

func (e *Executor) handleApproval(_ context.Context, ex *Execution, ps *PlanStep, se *StepExecution) error {
	se.Status = StepWaiting
	now := time.Now()
	se.StartedAt = &now
	_, _ = e.evidence.Append(context.Background(), ex.ID, se.ID, "approval_requested", "system", "exercise_engine",
		map[string]any{"prompt": ps.Config.ApprovalPrompt, "approver_roles": ps.Config.ApproverRoles})
	_ = e.store.RecordEvent(context.Background(), ex.ID, ps.ID, "step_waiting", "system",
		map[string]any{"prompt": ps.Config.ApprovalPrompt})
	if err := e.store.UpsertStepExecution(context.Background(), se); err != nil {
		return err
	}
	if err := e.store.UpsertExecutionAttempt(context.Background(), se); err != nil {
		log.Printf("[phase0b] upsert execution_attempt for step %s: %v", se.ID, err)
	}
	return nil
}

func (e *Executor) handleWebhook(_ context.Context, ex *Execution, ps *PlanStep, _ *StepExecution) error {
	go func() {
		err := fireWebhook(context.Background(), ps.Config.WebhookMethod, ps.Config.WebhookURL,
			ps.Config.WebhookHeaders, ps.Config.WebhookBody)
		if err != nil {
			_ = e.store.SetStepStatus(context.Background(), ex.ID, ps.ID, StepFailed, err.Error())
			return
		}
		_ = e.store.SetStepStatus(context.Background(), ex.ID, ps.ID, StepCompleted, "")
	}()
	return nil
}

func (e *Executor) handleNotify(_ context.Context, ex *Execution, ps *PlanStep, _ *StepExecution) error {
	log.Printf("[exercise] NOTIFY [%s] %s: %s", ex.ID, ps.Label, ps.Config.NotifyMsg)
	return e.store.SetStepStatus(context.Background(), ex.ID, ps.ID, StepCompleted, "")
}

// handleWaitForAgent enters StepWaiting immediately; the trigger fires once the
// BAS run (from a previous agent_task step) reaches a terminal status.
func (e *Executor) handleWaitForAgent(_ context.Context, ex *Execution, ps *PlanStep, se *StepExecution) error {
	cfg := ps.Config.WaitForAgent
	now := time.Now()
	se.Status = StepWaiting
	se.StartedAt = &now
	// Copy bas_run_id from the referenced agent_task step into this step's result
	// so the trigger can find it without needing to re-query the dependent step.
	if cfg != nil && cfg.AgentTaskStepID != "" {
		if ref, err := e.store.GetStepExecByStepID(context.Background(), ex.ID, cfg.AgentTaskStepID); err == nil {
			if runID, ok := ref.Result["bas_run_id"].(string); ok {
				se.Result = map[string]any{"bas_run_id": runID}
			}
		}
	}
	_ = e.store.RecordEvent(context.Background(), ex.ID, ps.ID, "step_waiting", "system",
		map[string]any{"waiting_for": "bas_run_complete"})
	if err := e.store.UpsertStepExecution(context.Background(), se); err != nil {
		return err
	}
	if err := e.store.UpsertExecutionAttempt(context.Background(), se); err != nil {
		log.Printf("[phase0b] upsert execution_attempt for step %s: %v", se.ID, err)
	}
	return nil
}

// handleWaitForDetection enters StepWaiting; trigger fires when edr_detected or
// siem_alerted evidence appears in the exercise evidence chain.
func (e *Executor) handleWaitForDetection(_ context.Context, ex *Execution, ps *PlanStep, se *StepExecution) error {
	now := time.Now()
	se.Status = StepWaiting
	se.StartedAt = &now
	_ = e.store.RecordEvent(context.Background(), ex.ID, ps.ID, "step_waiting", "system",
		map[string]any{"waiting_for": "detection_evidence"})
	if err := e.store.UpsertStepExecution(context.Background(), se); err != nil {
		return err
	}
	if err := e.store.UpsertExecutionAttempt(context.Background(), se); err != nil {
		log.Printf("[phase0b] upsert execution_attempt for step %s: %v", se.ID, err)
	}
	return nil
}

// handleWaitForWebhook mints a hook token, enters StepWaiting, and stores the
// callback URL in the step result so the operator can configure the external system.
func (e *Executor) handleWaitForWebhook(_ context.Context, ex *Execution, ps *PlanStep, se *StepExecution) error {
	// Re-use the tracker token infrastructure for the webhook token.
	token, err := mintHookToken()
	if err != nil {
		return e.store.SetStepStatus(context.Background(), ex.ID, ps.ID, StepFailed, err.Error())
	}
	if err := e.store.InsertTrackToken(context.Background(), token, ex.ID, se.ID, "",
		"webhook", map[string]any{"step_id": ps.ID}); err != nil {
		return e.store.SetStepStatus(context.Background(), ex.ID, ps.ID, StepFailed, err.Error())
	}
	now := time.Now()
	se.Status = StepWaiting
	se.StartedAt = &now
	se.Result = map[string]any{"hook_token": token, "hook_path": "/x/hook/" + token}
	_ = e.store.RecordEvent(context.Background(), ex.ID, ps.ID, "step_waiting", "system",
		map[string]any{"hook_token": token})
	if err := e.store.UpsertStepExecution(context.Background(), se); err != nil {
		return err
	}
	if err := e.store.UpsertExecutionAttempt(context.Background(), se); err != nil {
		log.Printf("[phase0b] upsert execution_attempt for step %s: %v", se.ID, err)
	}
	return nil
}

// ── Trigger functions ─────────────────────────────────────────────────────────

func (e *Executor) triggerWaitForAgent(ctx context.Context, _ *Execution, _ *PlanStep, se *StepExecution) (bool, map[string]any, error) {
	runID, _ := se.Result["bas_run_id"].(string)
	if runID == "" {
		return false, nil, nil
	}
	status, err := e.store.BASRunStatus(ctx, runID)
	if err != nil || status == "" {
		return false, nil, err
	}
	if status == "completed" || status == "failed" || status == "cancelled" || status == "partial" {
		return true, map[string]any{"bas_run_id": runID, "bas_run_status": status}, nil
	}
	return false, nil, nil
}

// basDetectionGraceSecs bounds how long a dispatched agent_task step waits,
// after its underlying scenario_run goes terminal, for detection data that
// may simply never arrive -- the agent only calls the detections endpoint at
// all when its post-run alert sweep finds something (agent/agent.go's
// collectAndSubmitDetections, graceWait=90s then returns early on zero
// alerts). 120s covers that 90s plus sweep/network margin without asserting
// this number is final -- evidence-adjustable later the same way this
// codebase's timeout budgets already are (see project memory
// project_timeout_scored_as_pass.md).
const basDetectionGraceSecs = 120

func (e *Executor) triggerWaitForBASDetection(ctx context.Context, _ *Execution, ps *PlanStep, se *StepExecution) (bool, map[string]any, error) {
	runID, _ := se.Result["bas_run_id"].(string)
	if runID == "" {
		return false, nil, nil
	}
	status, err := e.store.BASRunStatus(ctx, runID)
	if err != nil {
		return false, nil, err
	}
	if status != "completed" && status != "failed" && status != "cancelled" && status != "partial" {
		return false, nil, nil // still running -- keep waiting
	}

	techniqueID := ""
	if ps.Config.AgentTask != nil {
		techniqueID = ps.Config.AgentTask.TechniqueID
	}
	payload := map[string]any{"bas_run_id": runID, "bas_run_status": status}
	// Phase 0A: both breadcrumbs land together here -- the underlying run's
	// terminal status (the "result") is only known once this trigger has
	// already decided the step is done, unlike the synchronous
	// pre-Phase-1 handleAgentTask which logged them inline moments apart.
	complete := func() (bool, map[string]any, error) {
		now := time.Now()
		se.ResultReceivedAt = &now
		se.ScoringCompletedAt = &now
		log.Printf("[perf] execution_id=%s result_received_at=%s scoring_completed_at=%s", se.ExecutionID, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
		return true, payload, nil
	}
	if techniqueID == "" {
		// Whole-scenario dispatch (no single TechniqueID) -- Phase 1 scopes
		// Track 1 to the single-technique case; complete without a detection
		// verdict rather than guessing which of a multi-technique run's
		// results applies.
		return complete()
	}

	verdict, confidence, provider, mttdMs, ok, err := e.store.BASRunDetection(ctx, runID, techniqueID)
	if err != nil {
		return false, nil, err
	}
	if ok {
		payload["detection_verdict"] = verdict
		if confidence != "" {
			payload["detection_confidence"] = confidence
		}
		if mttdMs > 0 {
			payload["detection_mttd_ms"] = mttdMs
		}
		if provider != "" {
			payload["detection_alert_provider"] = provider
		}
		return complete()
	}

	// Not yet scored. If the run only just went terminal, the agent's 90s
	// grace + sweep may still be in flight -- keep waiting up to the bound.
	if se.StartedAt != nil && time.Since(*se.StartedAt) < basDetectionGraceSecs*time.Second {
		return false, nil, nil
	}
	// Grace window elapsed with nothing scored -- most likely the agent found
	// zero alerts and never called the detections endpoint at all. Complete
	// with no detection_verdict key rather than waiting forever or
	// fabricating a verdict.
	return complete()
}

// scoreExerciseNativeDetection is Track 2: normalizes phishing_reported
// evidence into a synthetic detect.AlertRecord and scores it through
// detect.Correlate -- the same attribution engine (via the new userReported
// signal, internal/detect/attribution.go) the ART/Caldera path uses, not a
// second interpretation. detect.Score is deliberately NOT called here: it
// aggregates DetectionRate/MTTDMs/etc. ACROSS a run's many techniques,
// which has nothing to add at single-step granularity -- every per-detection
// field this function needs (Verdict, Confidence, TimeToDetectMs) already
// lives on Correlate's own per-technique detect.TechniqueDetection result.
// Phase 1 scope: send_email steps only. A step with no phishing_reported
// evidence is left unscored (no detection_verdict key) -- absence of a
// report is not itself a verdict.
func (e *Executor) scoreExerciseNativeDetection(ctx context.Context, ex *Execution, ps *PlanStep, se *StepExecution) error {
	reportedAt, err := e.store.EarliestEvidenceTimestamp(ctx, se.ID, "phishing_reported")
	if err != nil {
		return err
	}
	if reportedAt == nil {
		return nil
	}

	techniqueID := "T1566.001" // simulated phishing attachment/link -- the one technique this track scores in Phase 1
	sentAt := se.StartedAt
	if sentAt == nil {
		sentAt = se.CompletedAt
	}
	if sentAt == nil {
		sentAt = &ex.CreatedAt
	}
	// Verdict must be "fail" (not "completed") -- detect.go's isExecuted/
	// isPrevented only recognize "pass"|"blocked"|"fail" ("pass"/"blocked"
	// mean the control PREVENTED the technique; "fail" means it executed and
	// needs alert-correlation, which is exactly this case: the phishing email
	// was not blocked, it reached the recipient, who then reported it).
	steps := []detect.ExecutedStep{{TechniqueID: techniqueID, Verdict: "fail", ExecutedAt: *sentAt}}
	alerts := []detect.AlertRecord{{
		Channel: "exercise-report", Provider: "exercise-tracking", Timestamp: *reportedAt,
		Message: "recipient reported the simulated phishing email",
	}}
	// Window wide enough to never be the limiting factor -- a phishing report
	// can legitimately arrive hours or days after send, unlike an EDR alert's
	// tight post-execution window. detectIDs is nil (irrelevant here; only
	// meaningful for the Windows-Defender-specific signal).
	dets := detect.Correlate(steps, alerts, 30*24*time.Hour, nil)

	for _, d := range dets {
		if d.TechniqueID != techniqueID || d.Verdict == "" {
			continue
		}
		payload := map[string]any{"detection_verdict": d.Verdict}
		if d.Confidence != "" {
			payload["detection_confidence"] = d.Confidence
		}
		if d.TimeToDetectMs > 0 {
			payload["detection_mttd_ms"] = d.TimeToDetectMs
		}
		merged := mergeMaps(se.Result, payload)
		return e.store.SetStepResult(ctx, ex.ID, ps.ID, merged)
	}
	return nil
}

func (e *Executor) triggerWaitForDetection(ctx context.Context, ex *Execution, ps *PlanStep, se *StepExecution) (bool, map[string]any, error) {
	cfg := ps.Config.WaitForDetection
	if cfg != nil && cfg.ExecutionStepID != "" && e.verification != nil {
		if err := e.bridgeVerifiedDetections(ctx, ex, ps, se, cfg.ExecutionStepID); err != nil {
			return false, nil, err
		}
	}

	var types []string
	minCount := 1
	if cfg != nil {
		types = cfg.DetectionTypes
		if cfg.MinCount > 0 {
			minCount = cfg.MinCount
		}
	}
	n, err := e.store.CountEvidenceForExec(ctx, ex.ID, types)
	if err != nil {
		return false, nil, err
	}
	if n >= minCount {
		return true, map[string]any{"detection_count": n}, nil
	}
	return false, nil, nil
}

// bridgeVerifiedDetections resolves executionStepID's BAS run, reads its
// approved verification records, translates them into exercise evidence via
// ResolveDetectionEvidence, and appends any new evidence. A permanent
// misconfiguration (bad executionStepID, or a completed step with no
// bas_run_id) fails the step visibly via SetStepStatus rather than
// returning a bare error — triggers.Check's caller only log.Printf's a
// returned error and retries forever, which would leave the step silently
// stuck. A run that simply hasn't produced results yet is not an error.
func (e *Executor) bridgeVerifiedDetections(ctx context.Context, ex *Execution, ps *PlanStep, se *StepExecution, executionStepID string) error {
	plan, err := e.store.GetPlan(ctx, ex.PlanID)
	if err != nil {
		return err
	}
	found := false
	for _, s := range plan.Steps {
		if s.ID == executionStepID {
			found = true
			break
		}
	}
	if !found {
		return e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepFailed,
			fmt.Sprintf("wait_for_detection: execution_step_id %q does not reference a valid plan step", executionStepID))
	}

	srcSE, err := e.store.GetStepExecByStepID(ctx, ex.ID, executionStepID)
	if err != nil {
		// Referenced step is valid but hasn't started/produced a
		// StepExecution row yet — not an error, just not ready.
		return nil
	}
	if srcSE.Status != StepCompleted {
		return nil // still running — not an error, just not ready.
	}
	runID, _ := srcSE.Result["bas_run_id"].(string)
	if runID == "" {
		return e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepFailed,
			fmt.Sprintf("wait_for_detection: execution step %q completed but produced no bas_run_id", executionStepID))
	}

	records, err := e.verification.CurrentApprovedForRun(ctx, runID)
	if err != nil {
		return err
	}
	existing, err := e.store.ListEvidence(ctx, ex.ID)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, ev := range existing {
		if ev.StepExecutionID != se.ID {
			continue
		}
		if id, _ := ev.Payload["expectation_id"].(string); id != "" {
			seen[id] = true
		}
	}
	for _, p := range ResolveDetectionEvidence(records, seen) {
		if _, err := e.evidence.Append(ctx, ex.ID, se.ID, p.EvidenceType, "system", "verification_bridge", p.Payload); err != nil {
			return err
		}
	}
	return nil
}

func (e *Executor) triggerWaitForWebhook(ctx context.Context, _ *Execution, _ *PlanStep, se *StepExecution) (bool, map[string]any, error) {
	token, _ := se.Result["hook_token"].(string)
	if token == "" {
		return false, nil, nil
	}
	n, err := e.store.WebhookCallCount(ctx, token)
	if err != nil {
		return false, nil, err
	}
	if n > 0 {
		return true, map[string]any{"hook_token": token, "call_count": n}, nil
	}
	return false, nil, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// mergeMaps returns a new map with all keys from both a and b (b wins on conflict).
func mergeMaps(a, b map[string]any) map[string]any {
	out := make(map[string]any, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// mintHookToken generates a random 16-byte hex token for webhook callbacks.
func mintHookToken() (string, error) {
	b := make([]byte, 16)
	if _, err := cryptoRandRead(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ── Condition evaluator ───────────────────────────────────────────────────────

func (e *Executor) evalCondition(ctx context.Context, cond, execID string, byID map[string]*StepExecution, agentID string) bool {
	cond = strings.TrimSpace(cond)
	if cond == "" || cond == "always" || cond == "true" {
		return true
	}
	if cond == "false" || cond == "never" {
		return false
	}
	parts := strings.SplitN(cond, ":", 3)
	if len(parts) == 3 && parts[0] == "agent" {
		return e.agentFact(ctx, agentID, parts[1], parts[2])
	}
	if len(parts) != 3 || parts[0] != "step" {
		log.Printf("[exercise] unknown condition: %q", cond)
		return true
	}
	stepID, predicate := parts[1], parts[2]
	se := byID[stepID]

	switch predicate {
	case "clicked":
		if se == nil {
			return false
		}
		ok, _ := e.store.hasEvidenceType(ctx, se.ID, "link_clicked")
		return ok
	case "not_clicked":
		if se == nil {
			return true
		}
		ok, _ := e.store.hasEvidenceType(ctx, se.ID, "link_clicked")
		return !ok
	case "reported":
		if se == nil {
			return false
		}
		ok, _ := e.store.hasEvidenceType(ctx, se.ID, "phishing_reported")
		return ok
	case "timeout":
		if se == nil {
			return false
		}
		v, _ := se.Result["timed_out"].(bool)
		return v
	case "no_timeout":
		if se == nil {
			return true
		}
		v, _ := se.Result["timed_out"].(bool)
		return !v
	case "succeeded":
		return se != nil && se.Status == StepCompleted && se.Error == ""
	case "failed":
		return se != nil && se.Status == StepFailed
	default:
		log.Printf("[exercise] unknown predicate %q in condition %q", predicate, cond)
		return true
	}
}

// agentFact evaluates an "agent:<fact>:<expected>" condition against the
// current step's target agent. agentID == "" (a step type with no
// AgentTaskConfig, e.g. send_email/wait/approval) or an unrecognised fact
// name fails open (true) -- structurally inapplicable is not "unsatisfied,"
// same philosophy as evalCondition's own unknown-predicate default. A nil
// (never-reported) domain_joined value also fails open, per the Phase 0C
// spec's Error-handling contract: unknown facts never gate.
func (e *Executor) agentFact(ctx context.Context, agentID, fact, expected string) bool {
	if agentID == "" {
		log.Printf("[exercise] agent: condition on a step with no target agent")
		return true
	}
	if fact != "domain_joined" {
		log.Printf("[exercise] unknown agent fact %q", fact)
		return true
	}
	domainJoined, err := e.store.AgentDomainJoined(ctx, agentID)
	if err != nil || domainJoined == nil {
		return true
	}
	want := expected == "true"
	return *domainJoined == want
}

// ── Lifecycle helpers ─────────────────────────────────────────────────────────

func (e *Executor) LaunchExecution(ctx context.Context, execID string) error {
	ex, err := e.store.GetExecution(ctx, execID)
	if err != nil {
		return err
	}
	if ex.Status != ExecDraft && ex.Status != ExecScheduled {
		return nil
	}
	plan, err := e.store.GetPlan(ctx, ex.PlanID)
	if err != nil {
		return err
	}
	for _, ps := range plan.Steps {
		se := &StepExecution{ExecutionID: execID, StepID: ps.ID, StepType: ps.Type, Status: StepPending}
		if err := e.store.UpsertStepExecution(ctx, se); err != nil {
			return err
		}
		if err := e.store.UpsertExecutionAttempt(ctx, se); err != nil {
			log.Printf("[phase0b] upsert execution_attempt for step %s: %v", se.ID, err)
		}
	}
	_ = e.store.RecordEvent(ctx, execID, "", "started", "system", nil)
	return e.store.UpdateExecutionStatus(ctx, execID, ExecRunning)
}

func (e *Executor) ApproveStep(ctx context.Context, execID, stepID, approver string) error {
	_ = e.store.SetStepResult(ctx, execID, stepID, map[string]any{"approved": true, "approver": approver})
	stepExecID, _ := e.store.stepExecIDForStep(ctx, execID, stepID)
	_, _ = e.evidence.Append(ctx, execID, stepExecID, "step_approved", approver, "manual",
		map[string]any{"step_id": stepID})
	_ = e.store.RecordEvent(ctx, execID, stepID, "approved", approver, map[string]any{"approver": approver})
	return e.store.SetStepStatus(ctx, execID, stepID, StepCompleted, "")
}

func (e *Executor) AbortExecution(ctx context.Context, execID string) error {
	steps, err := e.store.ListStepExecutions(ctx, execID)
	if err != nil {
		return err
	}
	for _, se := range steps {
		if se.Status == StepPending || se.Status == StepWaiting {
			_ = e.store.SetStepStatus(ctx, execID, se.StepID, StepCancelled, "aborted")
		}
	}
	_ = e.store.RecordEvent(ctx, execID, "", "aborted", "system", nil)
	return e.store.UpdateExecutionStatus(ctx, execID, ExecAborted)
}

// ── Score computation ─────────────────────────────────────────────────────────

func (e *Executor) computeScore(ctx context.Context, ex *Execution) *ExerciseScore {
	counts, err := e.store.CountEvidenceByType(ctx, ex.ID)
	if err != nil {
		log.Printf("[exercise] score evidence count: %v", err)
	}
	h := HumanScore{
		Sent:               counts["email_sent"],
		Opened:             counts["email_opened"],
		Clicked:            counts["link_clicked"],
		AttachmentOpened:   counts["attachment_opened"],
		CredentialsEntered: counts["credentials_submitted"],
		Reported:           counts["phishing_reported"],
	}
	if h.Sent > 0 {
		h.ClickRate = float64(h.Clicked) / float64(h.Sent)
		h.ReportRate = float64(h.Reported) / float64(h.Sent)
	}
	mttd, _ := e.store.SumDurationByType(ctx, ex.ID, "email_sent", "edr_detected")
	mttr, _ := e.store.SumDurationByType(ctx, ex.ID, "email_sent", "incident_resolved")
	t := TechnicalScore{
		EDRDetected:   counts["edr_detected"] > 0,
		EDRBlocked:    counts["edr_blocked"] > 0,
		SIEMAlerted:   counts["siem_alerted"] > 0,
		TicketCreated: counts["ticket_created"] > 0,
		MTTDSeconds:   mttd,
		MTTRSeconds:   mttr,
	}
	detBonus := 0.0
	if t.EDRDetected {
		detBonus += 0.5
	}
	if t.SIEMAlerted {
		detBonus += 0.5
	}
	score := &ExerciseScore{
		Human:      h,
		Technical:  t,
		Overall:    (1-h.ClickRate)*60 + detBonus*40,
		ComputedAt: time.Now(),
	}
	// An exercise that sent nothing and detected nothing has no measurable
	// result -- Overall above would be a misleading 60 (see the Measurable
	// field's doc comment). Flag it so consumers render "not measurable"
	// instead of a confident-looking number. Overall is left as-computed
	// rather than zeroed: a 0 would read as "scored terribly", which is a
	// different and equally wrong claim.
	score.Measurable = score.measurable()
	return score
}
