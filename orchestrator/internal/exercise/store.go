package exercise

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/exercise/tracker"
)

// Store handles all DB operations for the exercise engine.
type Store struct {
	db *pgxpool.Pool
}

func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

// ── Plans ─────────────────────────────────────────────────────────────────────

func (s *Store) CreatePlan(ctx context.Context, p *Plan) error {
	steps, _ := json.Marshal(p.Steps)
	vars, _ := json.Marshal(p.Variables)
	return s.db.QueryRow(ctx,
		`INSERT INTO exercise_plans (name, description, steps_json, variables_json, template_id, version, created_by)
		 VALUES ($1,$2,$3,$4,NULLIF($5,''),$6,$7) RETURNING id, created_at, updated_at`,
		p.Name, p.Description, steps, vars, p.TemplateID, max1(p.Version), p.CreatedBy,
	).Scan(&p.ID, &p.CreatedAt, &p.UpdatedAt)
}

func (s *Store) UpdatePlan(ctx context.Context, p *Plan) error {
	steps, _ := json.Marshal(p.Steps)
	vars, _ := json.Marshal(p.Variables)
	_, err := s.db.Exec(ctx,
		`UPDATE exercise_plans SET name=$1, description=$2, steps_json=$3, variables_json=$4, updated_at=NOW()
		 WHERE id=$5`,
		p.Name, p.Description, steps, vars, p.ID)
	return err
}

func (s *Store) GetPlan(ctx context.Context, id string) (*Plan, error) {
	var p Plan
	var stepsRaw, varsRaw []byte
	var templateID *string
	err := s.db.QueryRow(ctx,
		`SELECT id, name, description, steps_json, variables_json, template_id, version, created_by, created_at, updated_at
		 FROM exercise_plans WHERE id=$1`, id,
	).Scan(&p.ID, &p.Name, &p.Description, &stepsRaw, &varsRaw, &templateID, &p.Version, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(stepsRaw, &p.Steps)
	_ = json.Unmarshal(varsRaw, &p.Variables)
	if templateID != nil {
		p.TemplateID = *templateID
	}
	return &p, nil
}

func (s *Store) ListPlans(ctx context.Context) ([]Plan, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, name, description, steps_json, variables_json, template_id, version, created_by, created_at, updated_at
		 FROM exercise_plans ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Plan
	for rows.Next() {
		var p Plan
		var stepsRaw, varsRaw []byte
		var templateID *string
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &stepsRaw, &varsRaw,
			&templateID, &p.Version, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(stepsRaw, &p.Steps)
		_ = json.Unmarshal(varsRaw, &p.Variables)
		if templateID != nil {
			p.TemplateID = *templateID
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func max1(v int) int {
	if v < 1 {
		return 1
	}
	return v
}

func (s *Store) DeletePlan(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM exercise_plans WHERE id=$1`, id)
	return err
}

// ── Executions ────────────────────────────────────────────────────────────────

func (s *Store) CreateExecution(ctx context.Context, e *Execution) error {
	targets, _ := json.Marshal(e.Targets)
	meta, _ := json.Marshal(e.Metadata)
	vars, _ := json.Marshal(e.Variables)
	policy, _ := json.Marshal(e.ExecutionPolicy)
	return s.db.QueryRow(ctx,
		`INSERT INTO exercise_executions (plan_id, name, status, initiated_by, targets_json, metadata_json, variables_json, plan_version, execution_policy_json)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id, created_at, updated_at`,
		e.PlanID, e.Name, e.Status, e.InitiatedBy, targets, meta, vars, max1(e.PlanVersion), policy,
	).Scan(&e.ID, &e.CreatedAt, &e.UpdatedAt)
}

func (s *Store) UpdateExecutionStatus(ctx context.Context, id string, status ExecStatus) error {
	var q string
	switch status {
	case ExecRunning:
		q = `UPDATE exercise_executions SET status=$1, started_at=NOW(), updated_at=NOW() WHERE id=$2`
	case ExecCompleted, ExecAborted:
		q = `UPDATE exercise_executions SET status=$1, completed_at=NOW(), updated_at=NOW() WHERE id=$2`
	default:
		q = `UPDATE exercise_executions SET status=$1, updated_at=NOW() WHERE id=$2`
	}
	_, err := s.db.Exec(ctx, q, string(status), id)
	return err
}

func (s *Store) UpdateExecutionScore(ctx context.Context, id string, score *ExerciseScore) error {
	raw, _ := json.Marshal(score)
	_, err := s.db.Exec(ctx,
		`UPDATE exercise_executions SET score_json=$1, updated_at=NOW() WHERE id=$2`, raw, id)
	return err
}

func (s *Store) GetExecution(ctx context.Context, id string) (*Execution, error) {
	var e Execution
	var targetsRaw, metaRaw, varsRaw, scoreRaw, policyRaw []byte
	err := s.db.QueryRow(ctx,
		`SELECT id, plan_id, name, status, initiated_by, targets_json, metadata_json,
		        variables_json, plan_version, score_json, started_at, completed_at, created_at, updated_at,
		        execution_policy_json
		 FROM exercise_executions WHERE id=$1`, id,
	).Scan(&e.ID, &e.PlanID, &e.Name, &e.Status, &e.InitiatedBy,
		&targetsRaw, &metaRaw, &varsRaw, &e.PlanVersion, &scoreRaw,
		&e.StartedAt, &e.CompletedAt, &e.CreatedAt, &e.UpdatedAt, &policyRaw)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(targetsRaw, &e.Targets)
	_ = json.Unmarshal(metaRaw, &e.Metadata)
	_ = json.Unmarshal(varsRaw, &e.Variables)
	_ = json.Unmarshal(policyRaw, &e.ExecutionPolicy)
	if len(scoreRaw) > 0 {
		var sc ExerciseScore
		if err := json.Unmarshal(scoreRaw, &sc); err == nil {
			e.Score = &sc
		}
	}
	return &e, nil
}

func (s *Store) ListExecutions(ctx context.Context, limit int) ([]Execution, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(ctx,
		`SELECT id, plan_id, name, status, initiated_by, targets_json, metadata_json,
		        variables_json, plan_version, score_json, started_at, completed_at, created_at, updated_at,
		        execution_policy_json
		 FROM exercise_executions ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Execution
	for rows.Next() {
		var e Execution
		var targetsRaw, metaRaw, varsRaw, scoreRaw, policyRaw []byte
		if err := rows.Scan(&e.ID, &e.PlanID, &e.Name, &e.Status, &e.InitiatedBy,
			&targetsRaw, &metaRaw, &varsRaw, &e.PlanVersion, &scoreRaw,
			&e.StartedAt, &e.CompletedAt, &e.CreatedAt, &e.UpdatedAt, &policyRaw); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(targetsRaw, &e.Targets)
		_ = json.Unmarshal(metaRaw, &e.Metadata)
		_ = json.Unmarshal(policyRaw, &e.ExecutionPolicy)
		if len(scoreRaw) > 0 {
			var sc ExerciseScore
			if json.Unmarshal(scoreRaw, &sc) == nil {
				e.Score = &sc
			}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) ListRunningExecutions(ctx context.Context) ([]Execution, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, plan_id, name, status, initiated_by, targets_json, metadata_json,
		        variables_json, plan_version, score_json, started_at, completed_at, created_at, updated_at,
		        execution_policy_json
		 FROM exercise_executions WHERE status IN ('running','paused')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Execution
	for rows.Next() {
		var e Execution
		var targetsRaw, metaRaw, varsRaw, scoreRaw, policyRaw []byte
		if err := rows.Scan(&e.ID, &e.PlanID, &e.Name, &e.Status, &e.InitiatedBy,
			&targetsRaw, &metaRaw, &varsRaw, &e.PlanVersion, &scoreRaw,
			&e.StartedAt, &e.CompletedAt, &e.CreatedAt, &e.UpdatedAt, &policyRaw); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(targetsRaw, &e.Targets)
		_ = json.Unmarshal(metaRaw, &e.Metadata)
		_ = json.Unmarshal(varsRaw, &e.Variables)
		_ = json.Unmarshal(policyRaw, &e.ExecutionPolicy)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ── Templates ─────────────────────────────────────────────────────────────────

func (s *Store) UpsertTemplate(ctx context.Context, t *Template) error {
	vars, _ := json.Marshal(t.Variables)
	steps, _ := json.Marshal(t.Steps)
	_, err := s.db.Exec(ctx,
		`INSERT INTO exercise_templates (id, name, version, category, description, variables_json, steps_json, built_in, author)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		 ON CONFLICT (id) DO UPDATE SET
		   name=$2, version=$3, category=$4, description=$5,
		   variables_json=$6, steps_json=$7, author=$9, updated_at=NOW()`,
		t.ID, t.Name, t.Version, t.Category, t.Description,
		vars, steps, t.BuiltIn, t.Author)
	return err
}

func (s *Store) GetTemplate(ctx context.Context, id string) (*Template, error) {
	var t Template
	var varsRaw, stepsRaw []byte
	err := s.db.QueryRow(ctx,
		`SELECT id, name, version, category, description, variables_json, steps_json,
		        built_in, author, created_at, updated_at
		 FROM exercise_templates WHERE id=$1`, id,
	).Scan(&t.ID, &t.Name, &t.Version, &t.Category, &t.Description,
		&varsRaw, &stepsRaw, &t.BuiltIn, &t.Author, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(varsRaw, &t.Variables)
	_ = json.Unmarshal(stepsRaw, &t.Steps)
	return &t, nil
}

func (s *Store) ListTemplates(ctx context.Context) ([]Template, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, name, version, category, description, variables_json, steps_json,
		        built_in, author, created_at, updated_at
		 FROM exercise_templates ORDER BY built_in DESC, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Template
	for rows.Next() {
		var t Template
		var varsRaw, stepsRaw []byte
		if err := rows.Scan(&t.ID, &t.Name, &t.Version, &t.Category, &t.Description,
			&varsRaw, &stepsRaw, &t.BuiltIn, &t.Author, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(varsRaw, &t.Variables)
		_ = json.Unmarshal(stepsRaw, &t.Steps)
		out = append(out, t)
	}
	return out, rows.Err()
}

// SeedBuiltinTemplates upserts all BuiltinTemplates into the DB.
// Safe to call on every startup — built_in rows are never deleted.
func (s *Store) SeedBuiltinTemplates(ctx context.Context) error {
	for i := range BuiltinTemplates {
		if err := s.UpsertTemplate(ctx, &BuiltinTemplates[i]); err != nil {
			return fmt.Errorf("seed template %q: %w", BuiltinTemplates[i].ID, err)
		}
	}
	return nil
}

// ── Step Executions ───────────────────────────────────────────────────────────

func (s *Store) UpsertStepExecution(ctx context.Context, se *StepExecution) error {
	result, _ := json.Marshal(se.Result)
	return s.db.QueryRow(ctx,
		`INSERT INTO exercise_step_executions
		 (execution_id, step_id, step_type, status, attempt, scheduled_at, result_json, error_msg)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		 ON CONFLICT (execution_id, step_id) DO UPDATE
		   SET status=$4, attempt=$5, scheduled_at=$6, result_json=$7, error_msg=$8, started_at=
		       CASE WHEN exercise_step_executions.started_at IS NULL AND $4='running'
		            THEN NOW() ELSE exercise_step_executions.started_at END,
		       completed_at=
		       CASE WHEN $4 IN ('completed','failed','skipped','cancelled')
		            THEN NOW() ELSE exercise_step_executions.completed_at END
		 RETURNING id, created_at`,
		se.ExecutionID, se.StepID, string(se.StepType), string(se.Status),
		se.Attempt, se.ScheduledAt, result, se.Error,
	).Scan(&se.ID, &se.CreatedAt)
}

func (s *Store) SetStepStatus(ctx context.Context, execID, stepID string, status StepStatus, errMsg string) error {
	q := `UPDATE exercise_step_executions SET status=$1, error_msg=$2`
	args := []interface{}{string(status), errMsg, execID, stepID}
	if status == StepRunning {
		q += `, started_at=NOW()`
	} else if status == StepCompleted || status == StepFailed || status == StepSkipped {
		q += `, completed_at=NOW()`
	}
	q += ` WHERE execution_id=$3 AND step_id=$4`
	_, err := s.db.Exec(ctx, q, args...)
	return err
}

func (s *Store) SetStepResult(ctx context.Context, execID, stepID string, result map[string]interface{}) error {
	raw, _ := json.Marshal(result)
	_, err := s.db.Exec(ctx,
		`UPDATE exercise_step_executions SET result_json=$1 WHERE execution_id=$2 AND step_id=$3`,
		raw, execID, stepID)
	return err
}

func (s *Store) ListStepExecutions(ctx context.Context, execID string) ([]StepExecution, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, execution_id, step_id, step_type, status, attempt,
		        scheduled_at, started_at, completed_at, result_json, error_msg, created_at
		 FROM exercise_step_executions WHERE execution_id=$1 ORDER BY created_at`, execID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StepExecution
	for rows.Next() {
		var se StepExecution
		var resultRaw []byte
		if err := rows.Scan(&se.ID, &se.ExecutionID, &se.StepID, &se.StepType,
			&se.Status, &se.Attempt, &se.ScheduledAt, &se.StartedAt, &se.CompletedAt,
			&resultRaw, &se.Error, &se.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(resultRaw, &se.Result)
		out = append(out, se)
	}
	return out, rows.Err()
}

// ── Tracking Tokens ───────────────────────────────────────────────────────────

// InsertTrackToken satisfies tracker.TokenStore.
func (s *Store) InsertTrackToken(ctx context.Context, token, execID, stepExecID, targetID, tokenType string, payload map[string]any) error {
	raw, _ := json.Marshal(payload)
	_, err := s.db.Exec(ctx,
		`INSERT INTO exercise_track_tokens (token, execution_id, step_exec_id, target_id, token_type, payload_json)
		 VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
		token, execID, stepExecID, targetID, tokenType, raw)
	return err
}

// GetTrackToken satisfies tracker.TokenStore.
func (s *Store) GetTrackToken(ctx context.Context, token string) (*tracker.TrackToken, error) {
	var t tracker.TrackToken
	var payRaw []byte
	err := s.db.QueryRow(ctx,
		`SELECT token, execution_id, step_exec_id, target_id, token_type, payload_json, used_count, used_at
		 FROM exercise_track_tokens WHERE token=$1`, token,
	).Scan(&t.Token, &t.ExecutionID, &t.StepExecID, &t.TargetID,
		&t.TokenType, &payRaw, &t.UsedCount, &t.UsedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(payRaw, &t.Payload)
	return &t, nil
}

func (s *Store) RecordTokenUse(ctx context.Context, token string) error {
	_, err := s.db.Exec(ctx,
		`UPDATE exercise_track_tokens
		 SET used_count=used_count+1, used_at=COALESCE(used_at,NOW())
		 WHERE token=$1`, token)
	return err
}

// ── Exercise Events ───────────────────────────────────────────────────────────

// RecordEvent appends a state-transition event. Fire-and-forget safe to call
// from goroutines; errors are logged by the caller but never fatal.
func (s *Store) RecordEvent(ctx context.Context, execID, stepID, eventType, actor string, detail map[string]any) error {
	raw, _ := json.Marshal(detail)
	_, err := s.db.Exec(ctx,
		`INSERT INTO exercise_events (execution_id, step_id, event_type, actor, detail_json)
		 VALUES ($1,$2,$3,$4,$5)`,
		execID, stepID, eventType, actor, raw)
	return err
}

func (s *Store) ListEvents(ctx context.Context, execID string) ([]map[string]any, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, execution_id, step_id, event_type, actor, detail_json, ts
		 FROM exercise_events WHERE execution_id=$1 ORDER BY ts`, execID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, eid, stepID, evType, actor string
		var detRaw []byte
		var ts interface{}
		if err := rows.Scan(&id, &eid, &stepID, &evType, &actor, &detRaw, &ts); err != nil {
			return nil, err
		}
		var detail map[string]any
		_ = json.Unmarshal(detRaw, &detail)
		out = append(out, map[string]any{
			"id": id, "execution_id": eid, "step_id": stepID,
			"event_type": evType, "actor": actor, "detail": detail, "ts": ts,
		})
	}
	return out, rows.Err()
}

// ── Evidence (used by evidence.go) ───────────────────────────────────────────

func (s *Store) insertEvidence(ctx context.Context, ev *Evidence) error {
	payload, _ := json.Marshal(ev.Payload)
	return s.db.QueryRow(ctx,
		`INSERT INTO exercise_evidence
		 (execution_id, step_execution_id, seq, evidence_type, actor, source,
		  payload_json, sha256, prev_hash, signature, retention_policy)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		 RETURNING id, created_at`,
		ev.ExecutionID, ev.StepExecutionID, ev.Seq, ev.EvidenceType,
		ev.Actor, ev.Source, payload, ev.SHA256, ev.PrevHash, ev.Signature, ev.RetentionPolicy,
	).Scan(&ev.ID, &ev.CreatedAt)
}

func (s *Store) lastEvidenceHash(ctx context.Context, execID string) (seq int64, hash string, err error) {
	err = s.db.QueryRow(ctx,
		`SELECT COALESCE(MAX(seq),0), COALESCE((SELECT sha256 FROM exercise_evidence
		  WHERE execution_id=$1 ORDER BY seq DESC LIMIT 1),'')
		 FROM exercise_evidence WHERE execution_id=$1`, execID,
	).Scan(&seq, &hash)
	return
}

func (s *Store) ListEvidence(ctx context.Context, execID string) ([]Evidence, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, execution_id, step_execution_id, seq, evidence_type, actor, source,
		        payload_json, sha256, prev_hash, signature, retention_policy, created_at
		 FROM exercise_evidence WHERE execution_id=$1 ORDER BY seq`, execID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Evidence
	for rows.Next() {
		var ev Evidence
		var payRaw []byte
		if err := rows.Scan(&ev.ID, &ev.ExecutionID, &ev.StepExecutionID, &ev.Seq,
			&ev.EvidenceType, &ev.Actor, &ev.Source, &payRaw,
			&ev.SHA256, &ev.PrevHash, &ev.Signature, &ev.RetentionPolicy, &ev.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(payRaw, &ev.Payload)
		out = append(out, ev)
	}
	return out, rows.Err()
}

// NextSeq atomically reserves the next evidence sequence number for an execution.
func (s *Store) NextSeq(ctx context.Context, execID string) (int64, error) {
	var seq int64
	err := s.db.QueryRow(ctx,
		`SELECT COALESCE(MAX(seq),0)+1 FROM exercise_evidence WHERE execution_id=$1`, execID,
	).Scan(&seq)
	return seq, err
}

// hasEvidenceType checks whether evidence of the given type exists for a step execution.
func (s *Store) hasEvidenceType(ctx context.Context, stepExecID, evType string) (bool, error) {
	var n int
	err := s.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM exercise_evidence
		 WHERE step_execution_id=$1 AND evidence_type=$2`, stepExecID, evType,
	).Scan(&n)
	return n > 0, err
}

// CountEvidenceByType returns a map[evidence_type]count for an execution.
func (s *Store) CountEvidenceByType(ctx context.Context, execID string) (map[string]int, error) {
	rows, err := s.db.Query(ctx,
		`SELECT evidence_type, COUNT(*) FROM exercise_evidence
		 WHERE execution_id=$1 GROUP BY evidence_type`, execID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var t string
		var n int
		if err := rows.Scan(&t, &n); err != nil {
			return nil, err
		}
		out[t] = n
	}
	return out, rows.Err()
}

// stepExecIDForStep returns the step_execution id for a given (execID, stepID) pair.
func (s *Store) stepExecIDForStep(ctx context.Context, execID, stepID string) (string, error) {
	var id string
	err := s.db.QueryRow(ctx,
		`SELECT id FROM exercise_step_executions WHERE execution_id=$1 AND step_id=$2`,
		execID, stepID).Scan(&id)
	return id, err
}

// ── Trigger support ───────────────────────────────────────────────────────────

// BASRunStatus returns the status of a BAS scenario_run by run ID.
// Returns ("", nil) when the run is not found.
func (s *Store) BASRunStatus(ctx context.Context, runID string) (string, error) {
	var status string
	err := s.db.QueryRow(ctx,
		`SELECT status FROM scenario_runs WHERE id = $1`, runID).Scan(&status)
	if err != nil {
		return "", nil // not found — not an error for trigger polling
	}
	return status, nil
}

// CountEvidenceForExec counts evidence records of the given types in an
// execution. Used by the wait_for_detection trigger.
func (s *Store) CountEvidenceForExec(ctx context.Context, execID string, evTypes []string) (int, error) {
	if len(evTypes) == 0 {
		evTypes = []string{"edr_detected", "siem_alerted"}
	}
	// Build a parameterized IN list.
	params := make([]any, 0, len(evTypes)+1)
	params = append(params, execID)
	placeholders := make([]string, len(evTypes))
	for i, t := range evTypes {
		params = append(params, t)
		placeholders[i] = fmt.Sprintf("$%d", i+2)
	}
	var n int
	err := s.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM exercise_evidence
		 WHERE execution_id = $1 AND evidence_type IN (`+strings.Join(placeholders, ",")+`)`,
		params...).Scan(&n)
	return n, err
}

// WebhookCallCount returns the number of inbound hook POSTs received for token.
func (s *Store) WebhookCallCount(ctx context.Context, token string) (int, error) {
	var n int
	err := s.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM exercise_webhook_calls WHERE token = $1`, token).Scan(&n)
	return n, err
}

// InsertWebhookCall records one inbound /x/hook/{token} POST.
func (s *Store) InsertWebhookCall(ctx context.Context, token, execID, stepExecID string, body []byte) error {
	_, err := s.db.Exec(ctx,
		`INSERT INTO exercise_webhook_calls (token, execution_id, step_exec_id, body)
		 VALUES ($1, $2, $3, $4)`,
		token, execID, stepExecID, body)
	return err
}

// GetStepExecByStepID returns the StepExecution for a specific step within an execution.
func (s *Store) GetStepExecByStepID(ctx context.Context, execID, stepID string) (*StepExecution, error) {
	var se StepExecution
	var resultRaw []byte
	err := s.db.QueryRow(ctx,
		`SELECT id, execution_id, step_id, step_type, status, attempt,
		        scheduled_at, started_at, completed_at, result_json, error_msg, created_at
		 FROM exercise_step_executions
		 WHERE execution_id=$1 AND step_id=$2`, execID, stepID,
	).Scan(&se.ID, &se.ExecutionID, &se.StepID, &se.StepType,
		&se.Status, &se.Attempt, &se.ScheduledAt, &se.StartedAt, &se.CompletedAt,
		&resultRaw, &se.Error, &se.CreatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(resultRaw, &se.Result)
	return &se, nil
}

// SumDurationByType returns the total time (seconds) between the first and last
// evidence record of the given type for a given execution. Used for MTTD/MTTR.
func (s *Store) SumDurationByType(ctx context.Context, execID, fromType, toType string) (int, error) {
	var secs float64
	err := s.db.QueryRow(ctx,
		`SELECT EXTRACT(EPOCH FROM (
		    (SELECT MIN(created_at) FROM exercise_evidence WHERE execution_id=$1 AND evidence_type=$3)
		  - (SELECT MIN(created_at) FROM exercise_evidence WHERE execution_id=$1 AND evidence_type=$2)
		 ))`, execID, fromType, toType).Scan(&secs)
	if err != nil {
		return 0, fmt.Errorf("duration: %w", err)
	}
	return int(secs), nil
}
