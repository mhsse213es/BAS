package api

import (
	"context"
	"fmt"
	"time"

	"github.com/audspect/bas/internal/phishbridge"
	"github.com/audspect/bas/internal/phishidentity"
	"github.com/audspect/bas/internal/phishval"
)

// paramPositiveInt reads a required, positive integer run parameter. JSON
// numbers arrive as float64. A missing or non-positive value is an error,
// never an invented default: the heuristics have no official threshold.
func paramPositiveInt(params map[string]any, key string) (int, error) {
	switch v := params[key].(type) {
	case int:
		if v > 0 {
			return v, nil
		}
	case int64:
		if v > 0 {
			return int(v), nil
		}
	case float64:
		if v > 0 && v == float64(int(v)) {
			return int(v), nil
		}
	}
	return 0, fmt.Errorf("phishingrun: %q must be a positive integer run parameter", key)
}

// executePHID004 runs PH-ID-004 (MFA fatigue), an EXPERIMENTAL heuristic. It
// reads the user's MFA denial events and applies the caller's burst threshold
// and window. Its verdict is labeled experimental in the observation's source.
// A missing reader or a failed read is NotTested, never a verdict.
func executePHID004(ctx context.Context, env PhishingRunExecutorEnv, runID string, params map[string]any) (phishval.Outcome, error) {
	userID, _ := params["userId"].(string)
	if userID == "" {
		return phishval.Outcome{}, fmt.Errorf("phishingrun: PH-ID-004 requires a non-empty userId parameter")
	}
	if err := refuseUnlessScoped(env.IdentityScope.Users, []string{userID}); err != nil {
		return phishval.Outcome{}, err
	}
	threshold, err := paramPositiveInt(params, "threshold")
	if err != nil {
		return phishval.Outcome{}, err
	}
	windowSeconds, err := paramPositiveInt(params, "windowSeconds")
	if err != nil {
		return phishval.Outcome{}, err
	}

	var obs phishval.Observation
	if env.IdentityReader != nil {
		events, err := env.IdentityReader.MFADenialEventsForUser(ctx, userID)
		if err == nil {
			verdict, detail := phishidentity.DetectMFAFatigueHeuristic(events, threshold, time.Duration(windowSeconds)*time.Second)
			obs = phishbridge.FromMFAFatigueHeuristic(verdict, detail)
		}
	}

	catalogExp, err := lookupPhishingCatalogExpectation("PH-ID-004")
	if err != nil {
		return phishval.Outcome{}, err
	}
	return phishval.Evaluate(runID, "", catalogExp, obs), nil
}

// executePHID005 runs PH-ID-005 (session theft response), an EXPERIMENTAL
// heuristic. It reads the user's risky sign-ins and the time their sign-in
// sessions were last revoked, and checks for a revocation after a risky event
// within the caller's window. It never revokes anything. A missing reader or a
// failed read is NotTested, never a verdict.
func executePHID005(ctx context.Context, env PhishingRunExecutorEnv, runID string, params map[string]any) (phishval.Outcome, error) {
	userID, _ := params["userId"].(string)
	if userID == "" {
		return phishval.Outcome{}, fmt.Errorf("phishingrun: PH-ID-005 requires a non-empty userId parameter")
	}
	if err := refuseUnlessScoped(env.IdentityScope.Users, []string{userID}); err != nil {
		return phishval.Outcome{}, err
	}
	windowSeconds, err := paramPositiveInt(params, "windowSeconds")
	if err != nil {
		return phishval.Outcome{}, err
	}

	var obs phishval.Observation
	if env.IdentityReader != nil {
		risky, err := env.IdentityReader.RiskySignInsForUser(ctx, userID)
		if err == nil {
			validFrom, err := env.IdentityReader.SignInSessionsValidFromDateTime(ctx, userID)
			if err == nil {
				verdict, detail := phishidentity.DetectSessionTheftResponseHeuristic(risky, validFrom, time.Duration(windowSeconds)*time.Second)
				obs = phishbridge.FromSessionTheftResponseHeuristic(verdict, detail)
			}
		}
	}

	catalogExp, err := lookupPhishingCatalogExpectation("PH-ID-005")
	if err != nil {
		return phishval.Outcome{}, err
	}
	return phishval.Evaluate(runID, "", catalogExp, obs), nil
}
