package wafmodsec

import (
	"context"
	"fmt"
	"time"

	"github.com/audspect/bas/internal/vendors/modsecwaf"
	"github.com/audspect/bas/internal/wafassessment"
	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/waforigin"
	"github.com/audspect/bas/internal/wafval"
)

// originResiliencePolicyBasis mirrors wafassessment's own (unexported)
// originResiliencePolicyBasis.
const originResiliencePolicyBasis = "owasp-crs-default"

// OriginResilienceLiveVectorIDs is 3 of
// AudspectOriginResilienceScenario's 5 contributing scenarios:
//   - WAFORIGIN-001 (routing coverage gap): SQLI-001's malicious payload
//     sent to the documented /search route (baseline) and to a real,
//     undocumented /legacy-search route that proxies to the same origin
//     but has `modsecurity off;` (see lab/wafmodsec/nginx/default.conf) --
//     a genuine routing-coverage gap, not a simulated one.
//   - WAFORIGIN-002 (direct origin reachability): XSS-001's malicious
//     payload sent through the WAF edge (baseline) and directly to the
//     origin container's own separately-published host port (bypass) --
//     see lab/wafmodsec/docker-compose.yml's own doc comment on
//     origin's port 8890.
//   - WAFORIGIN-005 (cross-node consistency): PATHTRAV-001's malicious
//     payload driven independently against the baseline ("waf") and
//     weakened ("waf-weakened") containers already built for
//     policy-integrity, reused here as the two "nodes" this scenario
//     compares -- a genuine two-node disagreement, though its cause (a
//     known, deliberate policy difference) is the same one already
//     disclosed for policy-integrity's GAP-001, not independent
//     configuration decay.
//
// WAFORIGIN-003 (fail-open during WAF unavailability) needs actually
// taking the WAF container down mid-test, a disruptive, differently-
// shaped build than an HTTP probe. WAFORIGIN-004 (TLS downgrade with a
// forged proxy header) needs a real TLS listener negotiating a
// deliberately deprecated protocol version, a separate, more involved
// piece of infrastructure this lab doesn't have. Both stay unwired.
var OriginResilienceLiveVectorIDs = []string{"WAFORIGIN-001", "WAFORIGIN-002", "WAFORIGIN-005"}

func findAttackVector(id string) (wafcatalog.AttackVector, error) {
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return wafcatalog.AttackVector{}, fmt.Errorf("loading attack catalog: %w", err)
	}
	for _, v := range catalog {
		if v.ID == id {
			return v, nil
		}
	}
	return wafcatalog.AttackVector{}, fmt.Errorf("attack vector %q not found in wafcatalog", id)
}

// BuildOriginResilienceLiveFixtures drives WAFORIGIN-001/002/005's real
// probes against baselineClient (the documented "waf" path, also
// WAFORIGIN-005's node-a), bypassClient (origin-002's direct-origin
// path, published separately), and weakenedClient (WAFORIGIN-005's
// node-b, the same "waf-weakened" instance policy-integrity uses).
func BuildOriginResilienceLiveFixtures(ctx context.Context, baselineClient, bypassClient, weakenedClient *modsecwaf.Client) (map[string]wafassessment.OriginResilienceFixture, error) {
	fixtures := make(map[string]wafassessment.OriginResilienceFixture, 3)

	sqli, err := findAttackVector("SQLI-001")
	if err != nil {
		return nil, err
	}
	baselineResp, err := baselineClient.Send(ctx, sqli.Malicious)
	if err != nil {
		return nil, fmt.Errorf("driving WAFORIGIN-001's baseline leg live: %w", err)
	}
	bypassTmpl := sqli.Malicious
	bypassTmpl.Path = "/legacy-search"
	bypassResp, err := baselineClient.Send(ctx, bypassTmpl)
	if err != nil {
		return nil, fmt.Errorf("driving WAFORIGIN-001's bypass leg live: %w", err)
	}
	now := time.Now()
	fixtures["WAFORIGIN-001"] = wafassessment.OriginResilienceFixture{
		BaselineEvidence: BuildCollectionResults(baselineResp, wafval.CorrelationKey{TestExecutionID: "WAFORIGIN-001-baseline", RequestID: "WAFORIGIN-001-baseline"}, now),
		BypassEvidence:   BuildCollectionResults(bypassResp, wafval.CorrelationKey{TestExecutionID: "WAFORIGIN-001-bypass", RequestID: "WAFORIGIN-001-bypass"}, now),
		EvidenceSource:   wafassessment.EvidenceSourceLiveExecution,
	}

	xss, err := findAttackVector("XSS-001")
	if err != nil {
		return nil, err
	}
	xssBaselineResp, err := baselineClient.Send(ctx, xss.Malicious)
	if err != nil {
		return nil, fmt.Errorf("driving WAFORIGIN-002's baseline leg live: %w", err)
	}
	directResp, err := bypassClient.Send(ctx, xss.Malicious)
	if err != nil {
		return nil, fmt.Errorf("driving WAFORIGIN-002's direct-origin leg live: %w", err)
	}
	fixtures["WAFORIGIN-002"] = wafassessment.OriginResilienceFixture{
		BaselineEvidence: BuildCollectionResults(xssBaselineResp, wafval.CorrelationKey{TestExecutionID: "WAFORIGIN-002-baseline", RequestID: "WAFORIGIN-002-baseline"}, now),
		BypassEvidence:   BuildCollectionResults(directResp, wafval.CorrelationKey{TestExecutionID: "WAFORIGIN-002-bypass", RequestID: "WAFORIGIN-002-bypass"}, now),
		EvidenceSource:   wafassessment.EvidenceSourceLiveExecution,
	}

	pathtrav, err := findAttackVector("PATHTRAV-001")
	if err != nil {
		return nil, err
	}
	nodeAResp, err := baselineClient.Send(ctx, pathtrav.Malicious)
	if err != nil {
		return nil, fmt.Errorf("driving WAFORIGIN-005's node-a leg live: %w", err)
	}
	nodeBResp, err := weakenedClient.Send(ctx, pathtrav.Malicious)
	if err != nil {
		return nil, fmt.Errorf("driving WAFORIGIN-005's node-b leg live: %w", err)
	}
	nodeAKey := wafval.CorrelationKey{TestExecutionID: "WAFORIGIN-005-node-a", RequestID: "WAFORIGIN-005-node-a"}
	nodeBKey := wafval.CorrelationKey{TestExecutionID: "WAFORIGIN-005-node-b", RequestID: "WAFORIGIN-005-node-b"}
	fixtures["WAFORIGIN-005"] = wafassessment.OriginResilienceFixture{
		NodeEvidence: []waforigin.NodeEvidence{
			{NodeID: "waf", Evidence: BuildCollectionResults(nodeAResp, nodeAKey, now), Key: nodeAKey},
			{NodeID: "waf-weakened", Evidence: BuildCollectionResults(nodeBResp, nodeBKey, now), Key: nodeBKey},
		},
		EvidenceSource: wafassessment.EvidenceSourceLiveExecution,
	}

	return fixtures, nil
}

// RunOriginResilienceLive loads the real origin-resilience scenario,
// builds its live fixtures against the three real clients, and
// evaluates them through the real, unmodified
// wafassessment.EvaluateOriginResilienceScenario.
func RunOriginResilienceLive(ctx context.Context, baselineClient, bypassClient, weakenedClient *modsecwaf.Client) (wafassessment.EnterpriseScenario, wafassessment.ScenarioResult, error) {
	scenario, err := wafassessment.AudspectOriginResilienceScenario()
	if err != nil {
		return wafassessment.EnterpriseScenario{}, wafassessment.ScenarioResult{}, fmt.Errorf("loading origin-resilience scenario: %w", err)
	}
	fixtures, err := BuildOriginResilienceLiveFixtures(ctx, baselineClient, bypassClient, weakenedClient)
	if err != nil {
		return wafassessment.EnterpriseScenario{}, wafassessment.ScenarioResult{}, fmt.Errorf("building live fixtures: %w", err)
	}
	result, err := wafassessment.EvaluateOriginResilienceScenario(scenario, originResiliencePolicyBasis, fixtures)
	if err != nil {
		return wafassessment.EnterpriseScenario{}, wafassessment.ScenarioResult{}, fmt.Errorf("evaluating scenario: %w", err)
	}
	return scenario, result, nil
}
