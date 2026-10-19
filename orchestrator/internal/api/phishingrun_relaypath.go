package api

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/phishbridge"
	"github.com/audspect/bas/internal/phishval"
)

// PH-EVA-002's two legs. Each run must be for one of its leg's expectation IDs,
// so the legs can never be swapped. Both known-good and known-bad forms are
// accepted, because the grade comes from the observed action, not the label.
var (
	relayPathDirectIDs = []string{"EG-016.relay-path.direct.known-good", "EG-016.relay-path.direct.known-bad"}
	relayPathRelayIDs  = []string{"EG-016.relay-path.relay.known-good", "EG-016.relay-path.relay.known-bad"}
)

// loadRelayPathLeg loads one leg's EmailGW run and decodes its observation.
// graded is false when the run has no efficacy result yet, and the observation
// is then empty, which Evaluate reports as NotTested.
func loadRelayPathLeg(ctx context.Context, pool *pgxpool.Pool, egRunID string, allowed []string) (obs phishval.Observation, graded bool, err error) {
	var gotEG string
	var resultRaw []byte
	if err := pool.QueryRow(ctx,
		`SELECT scenario_id, result FROM email_gw_runs WHERE id = $1`, egRunID,
	).Scan(&gotEG, &resultRaw); err != nil {
		return phishval.Observation{}, false, fmt.Errorf("phishingrun: PH-EVA-002 load email gateway run %q: %w", egRunID, err)
	}
	legOK := false
	for _, id := range allowed {
		if gotEG == id {
			legOK = true
			break
		}
	}
	if !legOK {
		return phishval.Observation{}, false, fmt.Errorf("phishingrun: email gateway run %q is for %s, which is not a valid leg for this slot", egRunID, gotEG)
	}
	if len(resultRaw) == 0 || string(resultRaw) == "null" {
		return phishval.Observation{}, false, nil
	}
	var r emailgwefficacy.EfficacyResult
	if err := json.Unmarshal(resultRaw, &r); err != nil {
		return phishval.Observation{}, false, fmt.Errorf("phishingrun: PH-EVA-002 decode efficacy result of %q: %w", egRunID, err)
	}
	return phishbridge.FromEmailGWEfficacyResult(r), true, nil
}

// executePHEVA002 grades PH-EVA-002 on two EmailGW runs, one per delivery path.
// The verdict is the direct path's enforcement against the catalog expectation.
// The relay leg never sets a verdict. If the relay path did not block the same
// spoof, the outcome's enforcement reason records a bypass finding. A missing
// result on either leg is NotTested for that leg, never a verdict.
func executePHEVA002(ctx context.Context, env PhishingRunExecutorEnv, runID string, params map[string]any) (phishval.Outcome, error) {
	directRunID, _ := params["emailGwRunId"].(string)
	relayRunID, _ := params["relayEmailGwRunId"].(string)
	if directRunID == "" || relayRunID == "" {
		return phishval.Outcome{}, fmt.Errorf("phishingrun: PH-EVA-002 requires emailGwRunId (direct path) and relayEmailGwRunId (relay path)")
	}
	if env.Pool == nil {
		return phishval.Outcome{}, fmt.Errorf("phishingrun: PH-EVA-002 requires a database pool (deployment misconfiguration)")
	}

	directObs, _, err := loadRelayPathLeg(ctx, env.Pool, directRunID, relayPathDirectIDs)
	if err != nil {
		return phishval.Outcome{}, err
	}
	relayObs, relayGraded, err := loadRelayPathLeg(ctx, env.Pool, relayRunID, relayPathRelayIDs)
	if err != nil {
		return phishval.Outcome{}, err
	}

	catalogExp, err := lookupPhishingCatalogExpectation("PH-EVA-002")
	if err != nil {
		return phishval.Outcome{}, err
	}
	outcome := phishval.Evaluate(runID, "", catalogExp, directObs)
	outcome.Enforcement.Reason = appendRelayLegNote(outcome.Enforcement.Reason, relayObs, relayGraded)
	return outcome, nil
}

// appendRelayLegNote adds the relay leg's finding to the enforcement reason. It
// never changes the verdict. A bypass is recorded as a labeled finding.
func appendRelayLegNote(reason string, relayObs phishval.Observation, relayGraded bool) string {
	var note string
	switch {
	case !relayGraded:
		note = "relay leg not graded: no efficacy result yet"
	case relayObs.Enforcement == nil:
		note = "relay leg not graded: no enforcement evidence"
	case relayObs.Enforcement.Outcome == phishval.EnforcementBlocked:
		note = "relay leg: relay path also blocked the spoof; no bypass observed"
	default:
		note = fmt.Sprintf("relay leg: BYPASS observed: relay path did not block the spoof (enforcement %s)", relayObs.Enforcement.Outcome)
	}
	if reason == "" {
		return note
	}
	return reason + "; " + note
}
