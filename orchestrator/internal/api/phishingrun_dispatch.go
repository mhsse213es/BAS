package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/emailgwrun"
	"github.com/audspect/bas/internal/phishingrun"
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
	DispatchedAt      time.Time `json:"dispatchedAt,omitempty"`
}

type dispatchResultEnvelope struct {
	Dispatch dispatchRecord `json:"dispatch"`
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
	environment := env.EmailGWEnvironment
	if environment == "" {
		environment = emailgwrun.EnvironmentLab
	}

	pending, err := json.Marshal(dispatchResultEnvelope{Dispatch: dispatchRecord{
		IdempotencyKey: key, EmailGWScenarioID: egID, Environment: string(environment), Recipient: recipients[0],
	}})
	if err != nil {
		return nil, fmt.Errorf("phishingrun: marshal dispatch record: %w", err)
	}
	run := &phishingrun.PhishingRun{
		ID: newID(), ScenarioID: req.ScenarioID, Status: phishingrun.StatusPending,
		Result: pending, InitiatedBy: req.InitiatedBy, StartedAt: time.Now().UTC(),
	}
	if err := db.InsertPhishingRun(ctx, pool, run); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return existingDispatchRun(ctx, pool, key)
		}
		return nil, fmt.Errorf("phishingrun: insert dispatch run: %w", err)
	}

	egRun, err := ExecuteEmailGWRun(ctx, pool, env.EmailGWProvider, env.EmailGWTarget, env.EmailGWOutbound,
		environment, EmailGWRunRequest{ScenarioID: egID, InitiatedBy: req.InitiatedBy})
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
		Environment: string(environment), Recipient: recipients[0], DispatchedAt: time.Now().UTC(),
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

	var egStatus string
	if err := pool.QueryRow(ctx, `SELECT status FROM email_gw_runs WHERE id = $1`, egRunID).Scan(&egStatus); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return finishDispatch(ctx, pool, run, run.Result, phishingrun.StatusFailed,
				fmt.Sprintf("the dispatched EmailGW run %s no longer exists", egRunID))
		}
		return run, fmt.Errorf("phishingrun: read EmailGW run %s: %w", egRunID, err)
	}

	switch egStatus {
	case "completed":
		exec, ok := LookupPhishingRunExecutor(run.ScenarioID)
		if !ok {
			return finishDispatch(ctx, pool, run, run.Result, phishingrun.StatusFailed, "scenario is no longer executable")
		}
		outcome, err := exec(ctx, env, run.ID, map[string]any{"emailGwRunId": egRunID})
		if err != nil {
			return finishDispatch(ctx, pool, run, run.Result, phishingrun.StatusFailed, err.Error())
		}
		raw, err := json.Marshal(outcome)
		if err != nil {
			return run, fmt.Errorf("phishingrun: marshal outcome: %w", err)
		}
		return finishDispatch(ctx, pool, run, raw, phishingrun.StatusCompleted, "")
	case "failed", "partial":
		return finishDispatch(ctx, pool, run, run.Result, phishingrun.StatusFailed,
			fmt.Sprintf("the dispatched EmailGW run ended as %s, so there is no complete evidence to grade", egStatus))
	}

	if time.Since(env2.Dispatch.DispatchedAt) > phishDispatchTimeout {
		return finishDispatch(ctx, pool, run, run.Result, phishingrun.StatusFailed,
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
