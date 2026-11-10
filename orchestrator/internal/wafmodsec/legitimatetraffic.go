package wafmodsec

import (
	"context"
	"fmt"
	"time"

	"github.com/audspect/bas/internal/vendors/modsecwaf"
	"github.com/audspect/bas/internal/wafassessment"
	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafval"
)

// LegitimateTrafficLiveVectorIDs is 4 of
// AudspectLegitimateTrafficScenario's 6 contributing vectors --
// SQLI-001, XSS-001, PATHTRAV-001, RATE-001 -- the ones whose
// BenignCounterpart uses only the ""/"query:<param>" PayloadLocation
// forms modsecwaf.BuildRequest implements. Unlike every other scenario
// in this package, this one drives each vector's BENIGN request, never
// Malicious: this scenario evaluates wafval.ClaimFalsePositive (does the
// WAF incorrectly block legitimate traffic), not ClaimPrevention.
// RATE-001's benign leg is a single ordinary request at normal cadence --
// genuinely testable here, unlike RATE-001's own malicious leg (a
// multi-request burst over a time window), which is why RATE-001 never
// appears in AutomatedAbuseLiveVectorIDs (no such list exists: Automated
// Abuse's vectors are all behavioral/timing-based and none can be
// honestly represented by modsecwaf.Client's single-request Send). The
// other 2 of this scenario's 6 vectors -- API-001 ("path:order_id") and
// FILEUP-001 ("body:multipart:file") -- are real, disclosed gaps.
var LegitimateTrafficLiveVectorIDs = []string{"SQLI-001", "XSS-001", "PATHTRAV-001", "RATE-001"}

// legitTrafficLiveSeverities mirrors wafassessment's own (unexported)
// legitTrafficSeverities: every contributing vector ID's real severity,
// from the one catalog this scenario's vectors all come from.
func legitTrafficLiveSeverities() (map[string]wafcatalog.Severity, error) {
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return nil, fmt.Errorf("loading wafcatalog: %w", err)
	}
	severityByID := make(map[string]wafcatalog.Severity, len(catalog))
	for _, v := range catalog {
		severityByID[v.ID] = v.Severity
	}
	return severityByID, nil
}

// BuildLegitimateTrafficLiveFixtures drives each of
// LegitimateTrafficLiveVectorIDs' real BENIGN counterpart request against
// the live WAF client and returns one wafassessment.VectorFixture per
// vector, labeled EvidenceSourceLiveExecution. BuildCollectionResults
// itself is claim-agnostic -- it reports Enforcement/Origin from the raw
// HTTP response the same way regardless of which leg produced it -- so no
// change to it was needed to reuse it here for a false-positive claim.
func BuildLegitimateTrafficLiveFixtures(ctx context.Context, client *modsecwaf.Client) (map[string]wafassessment.VectorFixture, error) {
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return nil, fmt.Errorf("loading wafcatalog: %w", err)
	}
	byID := make(map[string]wafcatalog.AttackVector, len(catalog))
	for _, v := range catalog {
		byID[v.ID] = v
	}

	fixtures := make(map[string]wafassessment.VectorFixture, len(LegitimateTrafficLiveVectorIDs))
	for _, id := range LegitimateTrafficLiveVectorIDs {
		v, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("vector %q not found in the real catalog", id)
		}
		if v.BenignCounterpart == nil {
			return nil, fmt.Errorf("vector %q has no BenignCounterpart to drive live", id)
		}
		resp, err := client.Send(ctx, *v.BenignCounterpart)
		if err != nil {
			return nil, fmt.Errorf("driving %s's benign counterpart live against the WAF: %w", id, err)
		}
		key := wafval.CorrelationKey{TestExecutionID: id, RequestID: id}
		results := BuildCollectionResults(resp, key, time.Now())
		fixtures[id] = wafassessment.VectorFixture{
			VectorID:       id,
			Results:        results,
			EvidenceSource: wafassessment.EvidenceSourceLiveExecution,
		}
	}
	return fixtures, nil
}

// RunLegitimateTrafficLive loads the real legitimate-traffic scenario and
// its severities, builds its live fixtures, and evaluates them through
// the real, unmodified wafassessment.EvaluateLegitimateTrafficScenario.
func RunLegitimateTrafficLive(ctx context.Context, client *modsecwaf.Client) (wafassessment.EnterpriseScenario, wafassessment.ScenarioResult, error) {
	scenario, err := wafassessment.AudspectLegitimateTrafficScenario()
	if err != nil {
		return wafassessment.EnterpriseScenario{}, wafassessment.ScenarioResult{}, fmt.Errorf("loading legitimate-traffic scenario: %w", err)
	}
	fixtures, err := BuildLegitimateTrafficLiveFixtures(ctx, client)
	if err != nil {
		return wafassessment.EnterpriseScenario{}, wafassessment.ScenarioResult{}, fmt.Errorf("building live fixtures: %w", err)
	}
	severityByID, err := legitTrafficLiveSeverities()
	if err != nil {
		return wafassessment.EnterpriseScenario{}, wafassessment.ScenarioResult{}, fmt.Errorf("loading severities: %w", err)
	}
	result, err := wafassessment.EvaluateLegitimateTrafficScenario(scenario, fixtures, severityByID)
	if err != nil {
		return wafassessment.EnterpriseScenario{}, wafassessment.ScenarioResult{}, fmt.Errorf("evaluating scenario: %w", err)
	}
	return scenario, result, nil
}
