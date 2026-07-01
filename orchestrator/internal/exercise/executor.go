package exercise

import (
	"context"
	"log"
	"strings"
	"time"
)

// Executor is the DAG runtime for exercise executions.
// It advances step state machines and fires registered step handlers.
// The polling cadence is controlled by the injected Scheduler.
type Executor struct {
	store     *Store
	evidence  *EvidenceChain
	registry  *Registry
	scheduler Scheduler
	dispatch  AgentDispatchFn
}

// NewExecutor builds an Executor with a pluggable Registry and Scheduler.
// Call RegisterBuiltins() afterwards to wire the standard step types.
func NewExecutor(store *Store, evidence *EvidenceChain, registry *Registry, scheduler Scheduler, dispatch AgentDispatchFn) *Executor {
	return &Executor{
		store:     store,
		evidence:  evidence,
		registry:  registry,
		scheduler: scheduler,
		dispatch:  dispatch,
	}
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
func (e *Executor) RegisterBuiltins(smtp *SMTPInjector) {
	e.registry.Register(StepTypeSendEmail, StepHandlerFunc(e.handleSendEmail(smtp)))
	e.registry.Register(StepTypeSendSMS, StepHandlerFunc(e.handleSendSMS))
	e.registry.Register(StepTypeAgentTask, StepHandlerFunc(e.handleAgentTask))
	e.registry.Register(StepTypeWait, StepHandlerFunc(e.handleWait))
	e.registry.Register(StepTypeApproval, StepHandlerFunc(e.handleApproval))
	e.registry.Register(StepTypeWebhook, StepHandlerFunc(e.handleWebhook))
	e.registry.Register(StepTypeNotify, StepHandlerFunc(e.handleNotify))
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

	// Advance timeout-expired wait/approval steps.
	now := time.Now()
	for _, ps := range plan.Steps {
		se, ok := byID[ps.ID]
		if !ok || se.Status != StepWaiting {
			continue
		}
		if ps.Type == StepTypeWait && se.ScheduledAt != nil && now.After(*se.ScheduledAt) {
			_ = e.store.SetStepResult(ctx, ex.ID, ps.ID, map[string]any{"timed_out": true})
			_ = e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepCompleted, "")
			_ = e.store.RecordEvent(ctx, ex.ID, ps.ID, "timeout", "system", nil)
			done[ps.ID] = true
		}
		if ps.Type == StepTypeApproval && ps.TimeoutSecs > 0 && se.StartedAt != nil {
			if now.After(se.StartedAt.Add(time.Duration(ps.TimeoutSecs) * time.Second)) {
				_ = e.store.SetStepResult(ctx, ex.ID, ps.ID, map[string]any{"timed_out": true, "approved": false})
				_ = e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepCompleted, "timeout")
				_ = e.store.RecordEvent(ctx, ex.ID, ps.ID, "timeout", "system", nil)
				done[ps.ID] = true
			}
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
		if !e.evalCondition(ctx, ps.Condition, ex.ID, byID) {
			_ = e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepSkipped, "condition false")
			_ = e.store.RecordEvent(ctx, ex.ID, ps.ID, "skipped", "system", map[string]any{"reason": "condition false"})
			continue
		}
		if se == nil {
			newSE := &StepExecution{ExecutionID: ex.ID, StepID: ps.ID, StepType: ps.Type, Status: StepPending}
			if err := e.store.UpsertStepExecution(ctx, newSE); err != nil {
				log.Printf("[exercise] create step_exec %s/%s: %v", ex.ID, ps.ID, err)
				continue
			}
			se = newSE
		}
		if err := e.dispatchStep(ctx, ex, &ps, se); err != nil {
			log.Printf("[exercise] dispatch %s/%s: %v", ex.ID, ps.ID, err)
			_ = e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepFailed, err.Error())
			_ = e.store.RecordEvent(ctx, ex.ID, ps.ID, "failed", "system", map[string]any{"error": err.Error()})
		}
	}
	return nil
}

func (e *Executor) dispatchStep(ctx context.Context, ex *Execution, ps *PlanStep, se *StepExecution) error {
	_ = e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepRunning, "")
	_ = e.store.RecordEvent(ctx, ex.ID, ps.ID, "step_running", "system", nil)
	return e.registry.Dispatch(ctx, ex, ps, se)
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

func (e *Executor) handleSendSMS(_ context.Context, ex *Execution, ps *PlanStep, _ *StepExecution) error {
	log.Printf("[exercise] SMS step %s/%s — no gateway configured (stub)", ex.ID, ps.ID)
	return e.store.SetStepStatus(context.Background(), ex.ID, ps.ID, StepCompleted, "")
}

func (e *Executor) handleAgentTask(_ context.Context, ex *Execution, ps *PlanStep, se *StepExecution) error {
	cfg := ps.Config.AgentTask
	if cfg == nil || (cfg.ScenarioID == "" && cfg.TechniqueID == "") {
		return e.store.SetStepStatus(context.Background(), ex.ID, ps.ID, StepFailed, "missing agent_task config")
	}
	if e.dispatch == nil {
		return e.store.SetStepStatus(context.Background(), ex.ID, ps.ID, StepFailed, "agent dispatch not configured")
	}
	go func() {
		bctx := context.Background()
		runID, err := e.dispatch(cfg.AgentID, cfg.ScenarioID, cfg.TechniqueID)
		if err != nil {
			_ = e.store.SetStepStatus(bctx, ex.ID, ps.ID, StepFailed, err.Error())
			return
		}
		result := map[string]any{"bas_run_id": runID}
		_ = e.store.SetStepResult(bctx, ex.ID, ps.ID, result)
		_ = e.store.SetStepStatus(bctx, ex.ID, ps.ID, StepCompleted, "")
		_, _ = e.evidence.Append(bctx, ex.ID, se.ID, "agent_task_dispatched", "system", "bas_engine",
			map[string]any{"run_id": runID, "agent_id": cfg.AgentID})
		_ = e.store.RecordEvent(bctx, ex.ID, ps.ID, "step_completed", "system", result)
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
	return e.store.UpsertStepExecution(context.Background(), se)
}

func (e *Executor) handleApproval(_ context.Context, ex *Execution, ps *PlanStep, se *StepExecution) error {
	se.Status = StepWaiting
	now := time.Now()
	se.StartedAt = &now
	_, _ = e.evidence.Append(context.Background(), ex.ID, se.ID, "approval_requested", "system", "exercise_engine",
		map[string]any{"prompt": ps.Config.ApprovalPrompt, "approver_roles": ps.Config.ApproverRoles})
	_ = e.store.RecordEvent(context.Background(), ex.ID, ps.ID, "step_waiting", "system",
		map[string]any{"prompt": ps.Config.ApprovalPrompt})
	return e.store.UpsertStepExecution(context.Background(), se)
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

// ── Condition evaluator ───────────────────────────────────────────────────────

func (e *Executor) evalCondition(ctx context.Context, cond, execID string, byID map[string]*StepExecution) bool {
	cond = strings.TrimSpace(cond)
	if cond == "" || cond == "always" || cond == "true" {
		return true
	}
	if cond == "false" || cond == "never" {
		return false
	}
	parts := strings.SplitN(cond, ":", 3)
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
	return &ExerciseScore{
		Human:      h,
		Technical:  t,
		Overall:    (1-h.ClickRate)*60 + detBonus*40,
		ComputedAt: time.Now(),
	}
}
