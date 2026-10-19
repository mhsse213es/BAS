package api

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/phishbridge"
	"github.com/audspect/bas/internal/phishval"
)

// emailGWReadbackExecutor returns the executor for a phishing scenario whose
// catalog entry wraps an EmailGW expectation. It grades an EXISTING email
// gateway run, named by params["emailGwRunId"], and never dispatches mail.
// The run must be for exactly the expectation this scenario maps to, so one
// scenario is never graded on another's message. A run with no efficacy
// result yet is NotTested, never a verdict.
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

		var gotEG string
		var resultRaw []byte
		if err := env.Pool.QueryRow(ctx,
			`SELECT scenario_id, result FROM email_gw_runs WHERE id = $1`, egRunID,
		).Scan(&gotEG, &resultRaw); err != nil {
			return phishval.Outcome{}, fmt.Errorf("phishingrun: %s load email gateway run %q: %w", scenarioID, egRunID, err)
		}
		if gotEG != wantEG {
			return phishval.Outcome{}, fmt.Errorf("phishingrun: email gateway run %q is for %s, but %s needs %s", egRunID, gotEG, scenarioID, wantEG)
		}

		var obs phishval.Observation
		if len(resultRaw) > 0 && string(resultRaw) != "null" {
			var r emailgwefficacy.EfficacyResult
			if err := json.Unmarshal(resultRaw, &r); err != nil {
				return phishval.Outcome{}, fmt.Errorf("phishingrun: %s decode efficacy result of %q: %w", scenarioID, egRunID, err)
			}
			obs = phishbridge.FromEmailGWEfficacyResult(r)
		}

		catalogExp, err := lookupPhishingCatalogExpectation(scenarioID)
		if err != nil {
			return phishval.Outcome{}, err
		}
		return phishval.Evaluate(runID, "", catalogExp, obs), nil
	}
}
