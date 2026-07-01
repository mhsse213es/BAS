package exercise

import (
	"context"
	"log"
	"strings"
	"time"
)

// Executor is the DAG executor for exercise runs.
// It polls Postgres every 5 seconds, advances step state machines, fires
// injectors, and evaluates branch conditions.
type Executor struct {
	store    *Store
	evidence *EvidenceChain
	smtp     *SMTPInjector
	dispatch AgentDispatchFn // may be nil if agent dispatch not configured
	stop     chan struct{}
}

func NewExecutor(store *Store, evidence *EvidenceChain, smtp *SMTPInjector, dispatch AgentDispatchFn) *Executor {
	return &Executor{
		store:    store,
		evidence: evidence,
		smtp:     smtp,
		dispatch: dispatch,
		stop:     make(chan struct{}),
	}
}

func (e *Executor) Start() {
	go e.loop()
}

func (e *Executor) Stop() {
	close(e.stop)
}

func (e *Executor) loop() {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-tick.C:
			if err := e.tick(context.Background()); err != nil {
				log.Printf("[exercise] executor tick: %v", err)
			}
		}
	}
}

func (e *Executor) tick(ctx context.Context) error {
	execs, err := e.store.ListRunningExecutions(ctx)
	if err != nil {
		return err
	}
	for _, ex := range execs {
		if ex.Status == ExecPaused {
			continue
		}
		if err := e.advance(ctx, &ex); err != nil {
			log.Printf("[exercise] advance exec %s: %v", ex.ID, err)
		}
	}
	return nil
}

// advance evaluates and dispatches ready steps for one execution.
func (e *Executor) advance(ctx context.Context, ex *Execution) error {
	plan, err := e.store.GetPlan(ctx, ex.PlanID)
	if err != nil {
		return err
	}

	stepExecs, err := e.store.ListStepExecutions(ctx, ex.ID)
	if err != nil {
		return err
	}

	// Build fast-lookup maps.
	byID := make(map[string]*StepExecution, len(stepExecs))
	for i := range stepExecs {
		byID[stepExecs[i].StepID] = &stepExecs[i]
	}

	// Build set of completed step IDs (completed / skipped / cancelled all unblock dependents).
	done := map[string]bool{}
	for _, se := range stepExecs {
		if se.Status == StepCompleted || se.Status == StepSkipped || se.Status == StepFailed {
			done[se.StepID] = true
		}
	}

	// Check if the entire execution is finished (all steps terminal).
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
		return e.store.UpdateExecutionStatus(ctx, ex.ID, ExecCompleted)
	}

	// Handle wait steps whose deadline has passed.
	now := time.Now()
	for _, ps := range plan.Steps {
		se, ok := byID[ps.ID]
		if !ok || se.Status != StepWaiting {
			continue
		}
		if ps.Type == StepTypeWait && se.ScheduledAt != nil && now.After(*se.ScheduledAt) {
			result := map[string]interface{}{"timed_out": true}
			_ = e.store.SetStepResult(ctx, ex.ID, ps.ID, result)
			_ = e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepCompleted, "")
			done[ps.ID] = true
		}
		// Approval steps timeout if configured.
		if ps.Type == StepTypeApproval && ps.TimeoutSecs > 0 && se.StartedAt != nil {
			deadline := se.StartedAt.Add(time.Duration(ps.TimeoutSecs) * time.Second)
			if now.After(deadline) {
				result := map[string]interface{}{"timed_out": true, "approved": false}
				_ = e.store.SetStepResult(ctx, ex.ID, ps.ID, result)
				_ = e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepCompleted, "timeout")
				done[ps.ID] = true
			}
		}
	}

	// Find and dispatch ready pending steps.
	for _, ps := range plan.Steps {
		se := byID[ps.ID]
		if se != nil && se.Status != StepPending {
			continue
		}

		// All depends_on must be terminal.
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

		// Evaluate branch condition.
		if !e.evalCondition(ctx, ps.Condition, ex.ID, byID) {
			_ = e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepSkipped, "condition false")
			continue
		}

		// Ensure the StepExecution row exists before dispatching.
		if se == nil {
			newSE := &StepExecution{
				ExecutionID: ex.ID,
				StepID:      ps.ID,
				StepType:    ps.Type,
				Status:      StepPending,
			}
			if err := e.store.UpsertStepExecution(ctx, newSE); err != nil {
				log.Printf("[exercise] create step_exec %s/%s: %v", ex.ID, ps.ID, err)
				continue
			}
			se = newSE
		}

		if err := e.dispatchStep(ctx, ex, &ps, se); err != nil {
			log.Printf("[exercise] dispatch step %s/%s: %v", ex.ID, ps.ID, err)
			_ = e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepFailed, err.Error())
		}
	}
	return nil
}

// dispatchStep fires the appropriate injector or sets the step to waiting.
func (e *Executor) dispatchStep(ctx context.Context, ex *Execution, ps *PlanStep, se *StepExecution) error {
	_ = e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepRunning, "")

	switch ps.Type {

	case StepTypeSendEmail:
		if e.smtp == nil {
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
			result, err := e.smtp.Send(bctx, se.ID, ex.ID, cfg, ex.Targets)
			if err != nil {
				_ = e.store.SetStepStatus(bctx, ex.ID, ps.ID, StepFailed, err.Error())
				return
			}
			_ = e.store.SetStepResult(bctx, ex.ID, ps.ID, result)
			_ = e.store.SetStepStatus(bctx, ex.ID, ps.ID, StepCompleted, "")
			_, _ = e.evidence.Append(bctx, ex.ID, se.ID, "email_sent", "system", "smtp_injector", result)
		}()

	case StepTypeSendSMS:
		// SMS injector stubbed — logs and marks completed. Implement
		// by adding an SMSInjector to Executor and calling it here.
		log.Printf("[exercise] SMS step %s (stub — no gateway configured)", ps.ID)
		_ = e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepCompleted, "")

	case StepTypeAgentTask:
		cfg := ps.Config.AgentTask
		if cfg == nil || (cfg.ScenarioID == "" && cfg.TechniqueID == "") {
			_ = e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepFailed, "missing agent_task config")
			return nil
		}
		if e.dispatch == nil {
			_ = e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepFailed, "agent dispatch not configured")
			return nil
		}
		go func() {
			bctx := context.Background()
			runID, err := e.dispatch(cfg.AgentID, cfg.ScenarioID, cfg.TechniqueID)
			if err != nil {
				_ = e.store.SetStepStatus(bctx, ex.ID, ps.ID, StepFailed, err.Error())
				return
			}
			result := map[string]interface{}{"bas_run_id": runID}
			_ = e.store.SetStepResult(bctx, ex.ID, ps.ID, result)
			_ = e.store.SetStepStatus(bctx, ex.ID, ps.ID, StepCompleted, "")
			_, _ = e.evidence.Append(bctx, ex.ID, se.ID, "agent_task_dispatched", "system", "bas_engine",
				map[string]interface{}{"run_id": runID, "agent_id": cfg.AgentID})
		}()

	case StepTypeWait:
		d, err := time.ParseDuration(ps.Config.WaitDuration)
		if err != nil || d <= 0 {
			d = time.Hour // default 1h if misconfigured
		}
		deadline := time.Now().Add(d)
		se.ScheduledAt = &deadline
		se.Status = StepWaiting
		if uErr := e.store.UpsertStepExecution(ctx, se); uErr != nil {
			return uErr
		}

	case StepTypeApproval:
		se.Status = StepWaiting
		now := time.Now()
		se.StartedAt = &now
		if uErr := e.store.UpsertStepExecution(ctx, se); uErr != nil {
			return uErr
		}
		_, _ = e.evidence.Append(ctx, ex.ID, se.ID, "approval_requested", "system", "exercise_engine",
			map[string]interface{}{
				"prompt":          ps.Config.ApprovalPrompt,
				"approver_roles":  ps.Config.ApproverRoles,
			})

	case StepTypeWebhook:
		go func() {
			bctx := context.Background()
			err := fireWebhook(bctx, ps.Config.WebhookMethod, ps.Config.WebhookURL,
				ps.Config.WebhookHeaders, ps.Config.WebhookBody)
			if err != nil {
				_ = e.store.SetStepStatus(bctx, ex.ID, ps.ID, StepFailed, err.Error())
				return
			}
			_ = e.store.SetStepStatus(bctx, ex.ID, ps.ID, StepCompleted, "")
		}()

	case StepTypeNotify:
		// Operator notification — log for now; extend with email/Slack.
		log.Printf("[exercise] NOTIFY [%s] %s: %s", ex.ID, ps.Label, ps.Config.NotifyMsg)
		_ = e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepCompleted, "")

	default:
		_ = e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepFailed, "unknown step type: "+string(ps.Type))
	}
	return nil
}

// evalCondition evaluates a branch condition against the current step results.
//
// Supported forms:
//
//	""                       → always true
//	"step:{id}:clicked"      → evidence "link_clicked" exists for that step
//	"step:{id}:not_clicked"  → no "link_clicked" evidence for that step
//	"step:{id}:reported"     → evidence "phishing_reported" exists
//	"step:{id}:timeout"      → step result["timed_out"] == true
//	"step:{id}:no_timeout"   → step result["timed_out"] != true
//	"step:{id}:succeeded"    → step completed without error
//	"step:{id}:failed"       → step failed
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
		log.Printf("[exercise] unrecognised condition: %q", cond)
		return true // default open
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
		log.Printf("[exercise] unknown predicate: %q", predicate)
		return true
	}
}

// computeScore builds an ExerciseScore from the evidence chain.
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
	// Overall score: (1 - click_rate) * 60 + detection_bonus * 40
	detBonus := 0.0
	if t.EDRDetected {
		detBonus += 0.5
	}
	if t.SIEMAlerted {
		detBonus += 0.5
	}
	overall := (1-h.ClickRate)*60 + detBonus*40
	return &ExerciseScore{
		Human:      h,
		Technical:  t,
		Overall:    overall,
		ComputedAt: time.Now(),
	}
}

// LaunchExecution transitions an execution from draft/scheduled → running and
// creates pending StepExecution rows for all plan steps.
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
	// Pre-create StepExecution rows for all steps.
	for _, ps := range plan.Steps {
		se := &StepExecution{
			ExecutionID: execID,
			StepID:      ps.ID,
			StepType:    ps.Type,
			Status:      StepPending,
		}
		if err := e.store.UpsertStepExecution(ctx, se); err != nil {
			return err
		}
	}
	return e.store.UpdateExecutionStatus(ctx, execID, ExecRunning)
}

// ApproveStep resolves a waiting approval step.
func (e *Executor) ApproveStep(ctx context.Context, execID, stepID, approver string) error {
	result := map[string]interface{}{"approved": true, "approver": approver}
	_ = e.store.SetStepResult(ctx, execID, stepID, result)
	stepExecID, _ := e.store.stepExecIDForStep(ctx, execID, stepID)
	_, _ = e.evidence.Append(ctx, execID, stepExecID, "step_approved", approver, "manual",
		map[string]interface{}{"step_id": stepID})
	return e.store.SetStepStatus(ctx, execID, stepID, StepCompleted, "")
}

// AbortExecution cancels a running execution and marks all pending steps skipped.
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
	return e.store.UpdateExecutionStatus(ctx, execID, ExecAborted)
}
