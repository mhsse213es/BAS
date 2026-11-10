package wafmodsec

import (
	"context"
	"fmt"
	"time"

	"github.com/audspect/bas/internal/vendors/modsecwaf"
	"github.com/audspect/bas/internal/wafassessment"
	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafpolicygap"
	"github.com/audspect/bas/internal/wafval"
)

// policyIntegrityPolicyBasis mirrors wafassessment's own (unexported)
// policyIntegrityPolicyBasis -- the baseline policy document every policy-gap
// scenario's evidence is evaluated against.
const policyIntegrityPolicyBasis = "owasp-crs-default"

// PolicyIntegrityLiveVectorIDs is 1 of AudspectPolicyIntegrityScenario's 6
// contributing policy-gap scenarios: GAP-001 (detection-only mode), the only
// one this lab has a genuine second, deliberately weakened WAF instance for
// (see lab/wafmodsec/docker-compose.yml's "waf-weakened" service,
// MODSEC_RULE_ENGINE=DetectionOnly -- WAF-wide, broader than GAP-001's own
// literal "the matching rule... was switched to detection-only", disclosed
// in lab/wafmodsec/README.md). GAP-002/GAP-004 (exclusion rule, priority
// conflict) need a per-rule ModSecurity override mounted on a weakened
// instance, a different, more involved build than a single env var toggle.
// GAP-003/GAP-005/GAP-006 need modsecwaf.BuildRequest's still-missing
// body:json:/path: PayloadLocation forms.
var PolicyIntegrityLiveVectorIDs = []string{"GAP-001"}

// BuildPolicyIntegrityLiveFixtures drives GAP-001's referenced vector's
// malicious leg against BOTH the baseline and weakened live WAF clients and
// returns one wafassessment.PolicyGapFixture, labeled
// EvidenceSourceLiveExecution. PolicyDifferentiationConfirmed is true
// because the two containers' differing MODSEC_RULE_ENGINE setting is known
// directly from lab/wafmodsec/docker-compose.yml, not inferred from
// behavior -- the same honesty standard RunAutomatedAbuseLive applies to its
// own lab-side rate-limit config.
func BuildPolicyIntegrityLiveFixtures(ctx context.Context, baselineClient, weakenedClient *modsecwaf.Client) (map[string]wafassessment.PolicyGapFixture, error) {
	gapCatalog, err := wafpolicygap.AudspectWAFPolicyGapCatalog()
	if err != nil {
		return nil, fmt.Errorf("loading policy-gap catalog: %w", err)
	}
	gapByID := make(map[string]wafpolicygap.PolicyGapScenario, len(gapCatalog))
	for _, g := range gapCatalog {
		gapByID[g.ID] = g
	}
	attackCatalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return nil, fmt.Errorf("loading attack catalog: %w", err)
	}
	vectorByID := make(map[string]wafcatalog.AttackVector, len(attackCatalog))
	for _, v := range attackCatalog {
		vectorByID[v.ID] = v
	}

	fixtures := make(map[string]wafassessment.PolicyGapFixture, len(PolicyIntegrityLiveVectorIDs))
	for _, id := range PolicyIntegrityLiveVectorIDs {
		gapScenario, ok := gapByID[id]
		if !ok {
			return nil, fmt.Errorf("policy-gap scenario %q not found in wafpolicygap catalog", id)
		}
		vector, ok := vectorByID[gapScenario.AttackVectorID]
		if !ok {
			return nil, fmt.Errorf("attack vector %q (referenced by %q) not found in wafcatalog", gapScenario.AttackVectorID, id)
		}

		baselineResp, err := baselineClient.Send(ctx, vector.Malicious)
		if err != nil {
			return nil, fmt.Errorf("driving %s's baseline leg live: %w", id, err)
		}
		weakenedResp, err := weakenedClient.Send(ctx, vector.Malicious)
		if err != nil {
			return nil, fmt.Errorf("driving %s's weakened leg live: %w", id, err)
		}

		now := time.Now()
		baselineKey := wafval.CorrelationKey{TestExecutionID: id + "-baseline", RequestID: id + "-baseline"}
		weakenedKey := wafval.CorrelationKey{TestExecutionID: id + "-weakened", RequestID: id + "-weakened"}
		fixtures[id] = wafassessment.PolicyGapFixture{
			BaselineEvidence:               BuildCollectionResults(baselineResp, baselineKey, now),
			WeakenedEvidence:               BuildCollectionResults(weakenedResp, weakenedKey, now),
			PolicyDifferentiationConfirmed: true,
			EvidenceSource:                 wafassessment.EvidenceSourceLiveExecution,
		}
	}
	return fixtures, nil
}

// RunPolicyIntegrityLive loads the real policy-integrity scenario, builds
// its live fixtures against both WAF clients, and evaluates them through
// the real, unmodified wafassessment.EvaluatePolicyIntegrityScenario.
func RunPolicyIntegrityLive(ctx context.Context, baselineClient, weakenedClient *modsecwaf.Client) (wafassessment.EnterpriseScenario, wafassessment.ScenarioResult, error) {
	scenario, err := wafassessment.AudspectPolicyIntegrityScenario()
	if err != nil {
		return wafassessment.EnterpriseScenario{}, wafassessment.ScenarioResult{}, fmt.Errorf("loading policy-integrity scenario: %w", err)
	}
	fixtures, err := BuildPolicyIntegrityLiveFixtures(ctx, baselineClient, weakenedClient)
	if err != nil {
		return wafassessment.EnterpriseScenario{}, wafassessment.ScenarioResult{}, fmt.Errorf("building live fixtures: %w", err)
	}
	result, err := wafassessment.EvaluatePolicyIntegrityScenario(scenario, policyIntegrityPolicyBasis, fixtures)
	if err != nil {
		return wafassessment.EnterpriseScenario{}, wafassessment.ScenarioResult{}, fmt.Errorf("evaluating scenario: %w", err)
	}
	return scenario, result, nil
}
