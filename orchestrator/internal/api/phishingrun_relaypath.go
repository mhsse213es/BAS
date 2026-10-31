package api

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

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

// loadRelayPathLeg loads one leg's EmailGW run and decodes its observation. The leg
// is refused, with no grade, unless the run is completed, has an efficacy result,
// and is for one of the leg's allowed expectations. It returns the provenance of
// the exact run it read.
func loadRelayPathLeg(ctx context.Context, pool *pgxpool.Pool, egRunID string, allowed []string) (phishval.Observation, *phishval.Provenance, error) {
	var gotEG, status, environment string
	var resultRaw []byte
	var completedAt *time.Time
	var campaign string
	if err := pool.QueryRow(ctx,
		`SELECT scenario_id, status, environment, result, completed_at, COALESCE(campaign_id, '') FROM email_gw_runs WHERE id = $1`, egRunID,
	).Scan(&gotEG, &status, &environment, &resultRaw, &completedAt, &campaign); err != nil {
		return phishval.Observation{}, nil, fmt.Errorf("phishingrun: PH-EVA-002 load email gateway run %q: %w", egRunID, err)
	}
	legOK := false
	for _, id := range allowed {
		if gotEG == id {
			legOK = true
			break
		}
	}
	if !legOK {
		return phishval.Observation{}, nil, fmt.Errorf("phishingrun: email gateway run %q is for %s, which is not a valid leg for this slot", egRunID, gotEG)
	}
	if status != "completed" {
		return phishval.Observation{}, nil, fmt.Errorf("phishingrun: PH-EVA-002 refused: email gateway run %q is %s; only a completed run can be graded", egRunID, status)
	}
	if len(resultRaw) == 0 || string(resultRaw) == "null" {
		return phishval.Observation{}, nil, fmt.Errorf("phishingrun: PH-EVA-002 refused: email gateway run %q has no efficacy result, so there is no evidence to grade", egRunID)
	}
	var r emailgwefficacy.EfficacyResult
	if err := json.Unmarshal(resultRaw, &r); err != nil {
		return phishval.Observation{}, nil, fmt.Errorf("phishingrun: PH-EVA-002 decode efficacy result of %q: %w", egRunID, err)
	}
	prov := &phishval.Provenance{
		EmailGWRunID:       egRunID,
		EmailGWScenarioID:  gotEG,
		EmailGWEnvironment: environment,
		EmailGWCompletedAt: completedAt,
		CampaignID:         campaign,
	}
	return phishbridge.FromEmailGWEfficacyResult(r), prov, nil
}

// executePHEVA002 grades PH-EVA-002 on two EmailGW runs, one per delivery path.
// The verdict is the direct path's enforcement against the catalog expectation.
// The relay leg never sets a verdict. If the relay path did not block the same
// spoof, the outcome's enforcement reason records a bypass finding. Either leg
// that is not completed, or has no result, refuses the whole grade. Each leg's run
// is recorded: Provenance for the direct leg, RelayProvenance for the relay leg.
func executePHEVA002(ctx context.Context, env PhishingRunExecutorEnv, runID string, params map[string]any) (phishval.Outcome, error) {
	directRunID, _ := params["emailGwRunId"].(string)
	relayRunID, _ := params["relayEmailGwRunId"].(string)
	if directRunID == "" || relayRunID == "" {
		return phishval.Outcome{}, fmt.Errorf("phishingrun: PH-EVA-002 requires emailGwRunId (direct path) and relayEmailGwRunId (relay path)")
	}
	if env.Pool == nil {
		return phishval.Outcome{}, fmt.Errorf("phishingrun: PH-EVA-002 requires a database pool (deployment misconfiguration)")
	}

	directObs, directProv, err := loadRelayPathLeg(ctx, env.Pool, directRunID, relayPathDirectIDs)
	if err != nil {
		return phishval.Outcome{}, err
	}
	relayObs, relayProv, err := loadRelayPathLeg(ctx, env.Pool, relayRunID, relayPathRelayIDs)
	if err != nil {
		return phishval.Outcome{}, err
	}

	// Both legs must come from one campaign. Refusing a mismatch or a missing campaign
	// keeps two unrelated runs from being graded together.
	if directProv.CampaignID == "" || relayProv.CampaignID == "" {
		return phishval.Outcome{}, fmt.Errorf("phishingrun: PH-EVA-002 refused: both legs must belong to a campaign, and %q or %q has none", directRunID, relayRunID)
	}
	if directProv.CampaignID != relayProv.CampaignID {
		return phishval.Outcome{}, fmt.Errorf("phishingrun: PH-EVA-002 refused: the legs belong to different campaigns (%s and %s); both must be from the same campaign", directProv.CampaignID, relayProv.CampaignID)
	}
	directProv.Role = "direct_path"
	relayProv.Role = "relay_path"

	catalogExp, err := lookupPhishingCatalogExpectation("PH-EVA-002")
	if err != nil {
		return phishval.Outcome{}, err
	}
	outcome := phishval.Evaluate(runID, "", catalogExp, directObs)
	outcome.Enforcement.Reason = appendRelayLegNote(outcome.Enforcement.Reason, relayObs)
	outcome.Provenance = directProv
	outcome.RelayProvenance = relayProv
	return outcome, nil
}

// appendRelayLegNote adds the relay leg's finding to the enforcement reason. It
// never changes the verdict. A bypass is recorded as a labeled finding.
func appendRelayLegNote(reason string, relayObs phishval.Observation) string {
	var note string
	switch {
	case relayObs.Enforcement == nil:
		note = "relay leg: no enforcement evidence"
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
