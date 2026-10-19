package api

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/phishbridge"
	"github.com/audspect/bas/internal/phishval"
)

// emailGWReadbackExecutor returns the executor for a phishing scenario whose
// catalog entry wraps an EmailGW expectation. It grades an EXISTING email gateway
// run, named by the operator in params["emailGwRunId"], and never dispatches mail.
//
// The run is refused, with no grade, unless it exists, is completed, has an
// efficacy result, and is for exactly the expectation this scenario maps to.
// Nothing falls back to a different run. A completed grade carries Provenance that
// names the exact run it was read from. Delivery, enforcement, detection, user
// interaction, and response are separate fields of the outcome, with no single
// aggregate verdict, so each one is reported on its own.
func emailGWReadbackExecutor(scenarioID string) PhishingRunExecutor {
	return func(ctx context.Context, env PhishingRunExecutorEnv, runID string, params map[string]any) (phishval.Outcome, error) {
		egRunID, _ := params["emailGwRunId"].(string)
		if egRunID == "" {
			return phishval.Outcome{}, fmt.Errorf("phishingrun: %s requires a non-empty emailGwRunId parameter", scenarioID)
		}
		if env.Pool == nil {
			return phishval.Outcome{}, fmt.Errorf("phishingrun: %s requires a database pool (deployment misconfiguration)", scenarioID)
		}
		wantEG, ok := emailGWExpectationFor(scenarioID)
		if !ok {
			return phishval.Outcome{}, fmt.Errorf("phishingrun: %s has no EmailGW expectation mapping", scenarioID)
		}

		var gotEG, status, environment string
		var resultRaw []byte
		var completedAt *time.Time
		if err := env.Pool.QueryRow(ctx,
			`SELECT scenario_id, status, environment, result, completed_at FROM email_gw_runs WHERE id = $1`, egRunID,
		).Scan(&gotEG, &status, &environment, &resultRaw, &completedAt); err != nil {
			return phishval.Outcome{}, fmt.Errorf("phishingrun: %s load email gateway run %q: %w", scenarioID, egRunID, err)
		}
		if gotEG != wantEG {
			return phishval.Outcome{}, fmt.Errorf("phishingrun: email gateway run %q is for %s, but %s needs %s", egRunID, gotEG, scenarioID, wantEG)
		}
		if status != "completed" {
			return phishval.Outcome{}, fmt.Errorf("phishingrun: %s refused: email gateway run %q is %s; only a completed run can be graded", scenarioID, egRunID, status)
		}
		if len(resultRaw) == 0 || string(resultRaw) == "null" {
			return phishval.Outcome{}, fmt.Errorf("phishingrun: %s refused: email gateway run %q has no efficacy result, so there is no evidence to grade", scenarioID, egRunID)
		}
		var r emailgwefficacy.EfficacyResult
		if err := json.Unmarshal(resultRaw, &r); err != nil {
			return phishval.Outcome{}, fmt.Errorf("phishingrun: %s decode efficacy result of %q: %w", scenarioID, egRunID, err)
		}

		catalogExp, err := lookupPhishingCatalogExpectation(scenarioID)
		if err != nil {
			return phishval.Outcome{}, err
		}
		outcome := phishval.Evaluate(runID, "", catalogExp, phishbridge.FromEmailGWEfficacyResult(r))
		outcome.Provenance = &phishval.Provenance{
			EmailGWRunID:       egRunID,
			EmailGWScenarioID:  gotEG,
			EmailGWEnvironment: environment,
			EmailGWCompletedAt: completedAt,
		}
		return outcome, nil
	}
}
