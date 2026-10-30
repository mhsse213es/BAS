package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/emailgwrun"
	"github.com/audspect/bas/internal/phishingrun"
	"github.com/audspect/bas/internal/phishval"
)

// phishDispatchTimeout bounds how long a dispatched EmailGW run may stay open. A run
// still open after this is marked failed, with the reason, and is never left pending
// forever. It is a product default. A longer bound needs a design decision.
const phishDispatchTimeout = 24 * time.Hour

// dispatchRecord is the correlation a dispatched phishing run keeps. It links the
// phishing execution to the exact EmailGW run that carries its evidence.
type dispatchRecord struct {
	IdempotencyKey    string    `json:"idempotencyKey"`
	EmailGWRunID      string    `json:"emailGwRunId,omitempty"`
	EmailGWScenarioID string    `json:"emailGwScenarioId"`
	Environment       string    `json:"environment"`
	Recipient         string    `json:"recipient"`
	CampaignID        string    `json:"campaignId,omitempty"`
	TestWindowEnd     time.Time `json:"testWindowEnd,omitempty"`
	DispatchedAt      time.Time `json:"dispatchedAt,omitempty"`
}

type dispatchResultEnvelope struct {
	Dispatch dispatchRecord `json:"dispatch"`
}

// dispatchTestWindow reads the operator's test window: the time the EmailGW run's
// observation should end. It is an explicit RFC 3339 instant. The length from now must
// fall inside the EmailGW dwell bounds. An out-of-bounds window is refused, never clamped
// silently, so the operator sees the window they actually get.
func dispatchTestWindow(params map[string]any, now time.Time) (time.Duration, time.Time, error) {
	raw, _ := params["testWindowEnd"].(string)
	if raw == "" {
		return 0, time.Time{}, errors.New("phishingrun: dispatch requires testWindowEnd (RFC 3339) for the test window")
	}
	end, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("phishingrun: testWindowEnd must be RFC 3339: %w", err)
	}
	dwell := end.Sub(now)
	if dwell < MinEmailGWDwellWindow || dwell > MaxEmailGWDwellWindow {
		return 0, time.Time{}, fmt.Errorf("phishingrun: test window of %s is outside the EmailGW bounds of %s to %s",
			dwell.Round(time.Second), MinEmailGWDwellWindow, MaxEmailGWDwellWindow)
	}
	return dwell, end.UTC(), nil
}

// preflightDispatch checks an operator's dispatch request before anything is sent. It
// refuses on any gap, so no run row is created and no mail leaves.
func preflightDispatch(scenarioID string, params map[string]any, env PhishingRunExecutorEnv) (string, emailgwefficacy.MailExpectation, string, []string, error) {
	egID, ok := emailGWExpectationFor(scenarioID)
	if !ok {
		return "", emailgwefficacy.MailExpectation{}, "", nil,
			fmt.Errorf("phishingrun: %s is not EmailGW-backed, so it cannot be dispatched", scenarioID)
	}
	exp, ok := emailgwefficacy.ExpectationByID(egID)
	if !ok {
		return "", emailgwefficacy.MailExpectation{}, "", nil,
			fmt.Errorf("phishingrun: EmailGW expectation %s is missing", egID)
	}
	key, _ := params["idempotencyKey"].(string)
	if strings.TrimSpace(key) == "" {
		return "", exp, "", nil, errors.New("phishingrun: dispatch requires a non-empty idempotencyKey, so a retry cannot send twice")
	}
	recipients := requestedTargets(params, "recipients")
	if len(recipients) == 0 {
		return "", exp, "", nil, errors.New("phishingrun: dispatch requires the recipients to be named")
	}
	if exp.Recipient == "" {
		return "", exp, "", nil, fmt.Errorf("phishingrun: %s has no defined test recipient, so nothing can be dispatched to it", egID)
	}
	for _, r := range recipients {
		if !strings.EqualFold(r, exp.Recipient) {
			return "", exp, "", nil, fmt.Errorf("phishingrun: recipient %q is not the test recipient for %s; dispatch refused", r, egID)
		}
	}
	if env.EmailGWProvider == nil {
		return "", exp, "", nil, errors.New("phishingrun: the EmailGW real-run connector is not configured on this deployment")
	}
	return egID, exp, key, recipients, nil
}

// startPhishingDispatch creates the phishing run and dispatches its EmailGW run.
//
// The pending row is written first, with the idempotency key, and the unique index
// makes that insert the duplicate check. A retry with the same key returns the run
// that already exists, and sends nothing. The EmailGW run's ID is stored as soon as
// it exists. The phishing run then stays running until refreshPhishingDispatch
// finds the EmailGW run finished.
func startPhishingDispatch(ctx context.Context, pool *pgxpool.Pool, env PhishingRunExecutorEnv, req PhishingRunRequest) (*phishingrun.PhishingRun, error) {
	egID, _, key, recipients, err := preflightDispatch(req.ScenarioID, req.Parameters, env)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	dwell, testEnd, err := dispatchTestWindow(req.Parameters, now)
	if err != nil {
		return nil, err
	}
	campaignID, _ := req.Parameters["campaignId"].(string)
	environment := env.EmailGWEnvironment
	if environment == "" {
		environment = emailgwrun.EnvironmentLab
	}

	pending, err := json.Marshal(dispatchResultEnvelope{Dispatch: dispatchRecord{
		IdempotencyKey: key, EmailGWScenarioID: egID, Environment: string(environment), Recipient: recipients[0],
		CampaignID: campaignID, TestWindowEnd: testEnd,
	}})
	if err != nil {
		return nil, fmt.Errorf("phishingrun: marshal dispatch record: %w", err)
	}
	run := &phishingrun.PhishingRun{
		ID: newID(), ScenarioID: req.ScenarioID, Status: phishingrun.StatusPending,
		Result: pending, InitiatedBy: req.InitiatedBy, StartedAt: time.Now().UTC(),
		ExecutionID: executionIDFromParams(req.Parameters),
	}
	if err := db.InsertPhishingRun(ctx, pool, run); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return existingDispatchRun(ctx, pool, key)
		}
		return nil, fmt.Errorf("phishingrun: insert dispatch run: %w", err)
	}

	egRun, err := ExecuteEmailGWRun(ctx, pool, env.EmailGWProvider, env.EmailGWTarget, env.EmailGWOutbound,
		environment, EmailGWRunRequest{ScenarioID: egID, InitiatedBy: req.InitiatedBy, DwellWindowSeconds: int(dwell.Seconds())})
	if err != nil || egRun == nil {
		msg := "EmailGW dispatch returned no run"
		if err != nil {
			msg = err.Error()
		}
		run.Status = phishingrun.StatusFailed
		run.Error = msg
		_ = db.UpdatePhishingRunStatus(ctx, pool, run.ID, run.Status, pending, msg)
		return run, fmt.Errorf("phishingrun: dispatch %s: %s", req.ScenarioID, msg)
	}

	record := dispatchRecord{
		IdempotencyKey: key, EmailGWRunID: egRun.ID, EmailGWScenarioID: egID,
		Environment: string(environment), Recipient: recipients[0], CampaignID: campaignID, TestWindowEnd: testEnd,
		DispatchedAt: time.Now().UTC(),
	}
	result, err := json.Marshal(dispatchResultEnvelope{Dispatch: record})
	if err != nil {
		return nil, fmt.Errorf("phishingrun: marshal dispatch record: %w", err)
	}
	run.Status = phishingrun.StatusRunning
	run.Result = result
	if err := db.UpdatePhishingRunStatus(ctx, pool, run.ID, run.Status, result, ""); err != nil {
		return nil, fmt.Errorf("phishingrun: correlate EmailGW run %s: %w", egRun.ID, err)
	}

	return run, nil
}

// existingDispatchRun returns the run already created for an idempotency key.
func existingDispatchRun(ctx context.Context, pool *pgxpool.Pool, key string) (*phishingrun.PhishingRun, error) {
	var id string
	if err := pool.QueryRow(ctx,
		`SELECT id FROM phishing_runs WHERE result->'dispatch'->>'idempotencyKey' = $1`, key,
	).Scan(&id); err != nil {
		return nil, fmt.Errorf("phishingrun: idempotency key %q already used, but its run could not be read: %w", key, err)
	}
	return db.GetPhishingRun(ctx, pool, id)
}

// refreshPhishingDispatch moves a dispatched run to its final state when its EmailGW
// run has finished. A completed EmailGW run is graded through the same read-back as
// any existing run. A failed or partial EmailGW run fails the phishing run. A run
// still open past phishDispatchTimeout fails with that reason. Anything else is left
// running.
func refreshPhishingDispatch(ctx context.Context, pool *pgxpool.Pool, env PhishingRunExecutorEnv, run *phishingrun.PhishingRun) (*phishingrun.PhishingRun, error) {
	if run == nil || run.Status != phishingrun.StatusRunning {
		return run, nil
	}
	var env2 dispatchResultEnvelope
	if err := json.Unmarshal(run.Result, &env2); err != nil || env2.Dispatch.EmailGWRunID == "" {
		return run, nil
	}
	egRunID := env2.Dispatch.EmailGWRunID
	rec := env2.Dispatch

	var egStatus string
	if err := pool.QueryRow(ctx, `SELECT status FROM email_gw_runs WHERE id = $1`, egRunID).Scan(&egStatus); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return settleDispatch(ctx, pool, run, rec, run.Result, phishingrun.StatusFailed,
				fmt.Sprintf("the dispatched EmailGW run %s no longer exists", egRunID))
		}
		return run, fmt.Errorf("phishingrun: read EmailGW run %s: %w", egRunID, err)
	}

	switch egStatus {
	case "completed":
		exec, ok := LookupPhishingRunExecutor(run.ScenarioID)
		if !ok {
			return settleDispatch(ctx, pool, run, rec, run.Result, phishingrun.StatusFailed, "scenario is no longer executable")
		}
		outcome, err := exec(ctx, env, run.ID, map[string]any{"emailGwRunId": egRunID})
		if err != nil {
			return settleDispatch(ctx, pool, run, rec, run.Result, phishingrun.StatusFailed, err.Error())
		}
		raw, err := json.Marshal(outcome)
		if err != nil {
			return run, fmt.Errorf("phishingrun: marshal outcome: %w", err)
		}
		return settleDispatch(ctx, pool, run, rec, raw, phishingrun.StatusCompleted, "")
	case "failed", "partial":
		return settleDispatch(ctx, pool, run, rec, run.Result, phishingrun.StatusFailed,
			fmt.Sprintf("the dispatched EmailGW run ended as %s, so there is no complete evidence to grade", egStatus))
	}

	if time.Since(env2.Dispatch.DispatchedAt) > phishDispatchTimeout {
		return settleDispatch(ctx, pool, run, rec, run.Result, phishingrun.StatusFailed,
			fmt.Sprintf("timed out after %s waiting for EmailGW run %s", phishDispatchTimeout, egRunID))
	}
	return run, nil
}

func finishDispatch(ctx context.Context, pool *pgxpool.Pool, run *phishingrun.PhishingRun, result []byte, status phishingrun.Status, errMsg string) (*phishingrun.PhishingRun, error) {
	if err := db.UpdatePhishingRunStatus(ctx, pool, run.ID, status, result, errMsg); err != nil {
		return run, fmt.Errorf("phishingrun: finish dispatched run %s: %w", run.ID, err)
	}
	run.Status = status
	run.Error = errMsg
	run.Result = result
	now := time.Now().UTC()
	run.CompletedAt = &now
	return run, nil
}

// dispatchOutcomeFrom decodes a settled dispatch's stored outcome.
func dispatchOutcomeFrom(raw []byte) (phishval.Outcome, error) {
	var o phishval.Outcome
	err := json.Unmarshal(raw, &o)
	return o, err
}

// settleDispatch moves a dispatched run to its final state and records one audit entry
// for the settlement. The entry names the EmailGW run, the campaign context, and the
// test window, so the settlement can be traced to the operator's request.
func settleDispatch(ctx context.Context, pool *pgxpool.Pool, run *phishingrun.PhishingRun, rec dispatchRecord, result []byte, status phishingrun.Status, errMsg string) (*phishingrun.PhishingRun, error) {
	out, err := finishDispatch(ctx, pool, run, result, status, errMsg)
	if err != nil {
		return out, err
	}
	detail, _ := json.Marshal(map[string]any{
		"status":        string(status),
		"emailGwRunId":  rec.EmailGWRunID,
		"campaignId":    rec.CampaignID,
		"testWindowEnd": rec.TestWindowEnd,
		"error":         errMsg,
	})
	_, _ = pool.Exec(ctx,
		`INSERT INTO audit_logs (actor_id, action, resource, detail, ip, outcome)
		 VALUES ($1, 'phishingrun.dispatch.settled', $2, $3, '', $4)`,
		run.InitiatedBy, run.ID, detail, map[bool]string{true: "ok", false: "error"}[status == phishingrun.StatusCompleted])
	return out, nil
}

// RunPhishingDispatchPoller settles dispatched runs on a timer, so a dispatch finishes
// even when nobody reads it. It stops when ctx is cancelled. Startup runs it beside
// EmailGW recovery.
func RunPhishingDispatchPoller(ctx context.Context, pool *pgxpool.Pool, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := RefreshPhishingDispatches(ctx, pool, PhishingRunExecutorEnv{Pool: pool}); err != nil {
				log.Printf("[!] phishing dispatch refresh: %v", err)
			}
		}
	}
}

// RefreshPhishingDispatches settles every running dispatch once. It is the poller's
// unit of work, and tests call it directly.
func RefreshPhishingDispatches(ctx context.Context, pool *pgxpool.Pool, env PhishingRunExecutorEnv) error {
	rows, err := pool.Query(ctx,
		`SELECT id FROM phishing_runs WHERE status = 'running' AND result->'dispatch' IS NOT NULL`)
	if err != nil {
		return fmt.Errorf("phishingrun: list dispatched runs: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return fmt.Errorf("phishingrun: scan dispatched run: %w", err)
		}
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		run, err := db.GetPhishingRun(ctx, pool, id)
		if err != nil {
			return fmt.Errorf("phishingrun: load dispatched run %s: %w", id, err)
		}
		if _, err := refreshPhishingDispatch(ctx, pool, env, run); err != nil {
			return fmt.Errorf("phishingrun: refresh dispatched run %s: %w", id, err)
		}
	}
	return nil
}
