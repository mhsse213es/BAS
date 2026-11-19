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

// RoutingCacheIntegrityLiveVectorIDs is 2 of
// AudspectRoutingCacheIntegrityScenario's 3 contributing vectors:
// CACHE-002 (cache deception via a static-looking path suffix,
// PayloadLocation "") and CACHE-003 (cache poisoning via parameter
// cloaking, PayloadLocation "query:utm_source"). CACHE-001 (cache
// poisoning via an unkeyed X-Forwarded-Host header) is a real, disclosed
// gap: modsecwaf.BuildRequest implements only "" and "query:<param>",
// not "header:<name>".
var RoutingCacheIntegrityLiveVectorIDs = []string{"CACHE-002", "CACHE-003"}

// BuildRoutingCacheIntegrityLiveFixtures drives each of
// RoutingCacheIntegrityLiveVectorIDs' real malicious request against the
// live WAF client and returns one wafassessment.VectorFixture per vector,
// labeled EvidenceSourceLiveExecution.
func BuildRoutingCacheIntegrityLiveFixtures(ctx context.Context, client *modsecwaf.Client) (map[string]wafassessment.VectorFixture, error) {
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return nil, fmt.Errorf("loading wafcatalog: %w", err)
	}
	byID := make(map[string]wafcatalog.AttackVector, len(catalog))
	for _, v := range catalog {
		byID[v.ID] = v
	}

	fixtures := make(map[string]wafassessment.VectorFixture, len(RoutingCacheIntegrityLiveVectorIDs))
	for _, id := range RoutingCacheIntegrityLiveVectorIDs {
		v, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("vector %q not found in the real catalog", id)
		}
		resp, err := client.Send(ctx, v.Malicious)
		if err != nil {
			return nil, fmt.Errorf("driving %s live against the WAF: %w", id, err)
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

// RunRoutingCacheIntegrityLive loads the real routing-cache-integrity
// scenario and catalog, builds its live fixtures, and evaluates them
// through the real, unmodified wafassessment.EvaluateScenario.
func RunRoutingCacheIntegrityLive(ctx context.Context, client *modsecwaf.Client) (wafassessment.EnterpriseScenario, wafassessment.ScenarioResult, error) {
	scenario, err := wafassessment.AudspectRoutingCacheIntegrityScenario()
	if err != nil {
		return wafassessment.EnterpriseScenario{}, wafassessment.ScenarioResult{}, fmt.Errorf("loading routing-cache-integrity scenario: %w", err)
	}
	fixtures, err := BuildRoutingCacheIntegrityLiveFixtures(ctx, client)
	if err != nil {
		return wafassessment.EnterpriseScenario{}, wafassessment.ScenarioResult{}, fmt.Errorf("building live fixtures: %w", err)
	}
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return wafassessment.EnterpriseScenario{}, wafassessment.ScenarioResult{}, fmt.Errorf("loading wafcatalog: %w", err)
	}
	result, err := wafassessment.EvaluateScenario(scenario, fixtures, catalog)
	if err != nil {
		return wafassessment.EnterpriseScenario{}, wafassessment.ScenarioResult{}, fmt.Errorf("evaluating scenario: %w", err)
	}
	return scenario, result, nil
}
