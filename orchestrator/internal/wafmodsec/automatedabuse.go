package wafmodsec

import (
	"context"
	"fmt"
	"time"

	"github.com/audspect/bas/internal/vendors/modsecwaf"
	"github.com/audspect/bas/internal/wafassessment"
	"github.com/audspect/bas/internal/wafbotabuse"
	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafval"
)

// AutomatedAbuseLiveVectorIDs is 1 of AudspectAutomatedAbuseScenario's 6
// contributing vectors: RATE-001, the only one a real nginx `limit_req`
// zone has been configured for in the lab (see
// lab/wafmodsec/nginx/00-limit-req-zone.conf). The other 5 are each a
// different, bigger gap: RATE-002 needs per-account aggregation across
// sessions/source addresses the lab's origin has no concept of;
// BOTABUSE-001 needs a bot-management/JS-challenge layer CRS does not
// provide; BOTABUSE-002 needs a second, header-keyed rate-limit zone;
// BOTABUSE-003/004 need real stateful lockout/CAPTCHA logic at the origin.
var AutomatedAbuseLiveVectorIDs = []string{"RATE-001"}

// automatedAbuseBurstSize is how many concurrent requests RATE-001 drives
// in one burst -- large enough to reliably exceed the lab's deliberately
// strict 2r/s burst=3 zone within a single round of concurrent requests
// (curl-confirmed: a burst of 10 to /api/quote yields some 200s then 503s),
// small enough to stay a fast, bounded test.
const automatedAbuseBurstSize = 10

// automatedAbuseLiveSeverities mirrors wafassessment's own (unexported)
// automatedAbuseSeverities: the real severity of every Automated Abuse
// contributing vector ID, merged across both source catalogs. Required by
// wafassessment.EvaluateScenarioWithSeverities, which this scenario must
// use instead of EvaluateScenario since its vectors span two catalogs.
func automatedAbuseLiveSeverities() (map[string]wafcatalog.Severity, error) {
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return nil, fmt.Errorf("loading wafcatalog: %w", err)
	}
	botabuse, err := wafbotabuse.AudspectWAFBotAbuseCatalog()
	if err != nil {
		return nil, fmt.Errorf("loading wafbotabuse catalog: %w", err)
	}
	severityByID := make(map[string]wafcatalog.Severity, len(catalog)+len(botabuse))
	for _, v := range catalog {
		severityByID[v.ID] = v.Severity
	}
	for _, v := range botabuse {
		severityByID[v.ID] = wafcatalog.Severity(string(v.Severity))
	}
	return severityByID, nil
}

// BuildAutomatedAbuseLiveFixtures drives RATE-001 as a real burst against
// the live WAF client and returns one wafassessment.VectorFixture, labeled
// EvidenceSourceLiveExecution.
func BuildAutomatedAbuseLiveFixtures(ctx context.Context, client *modsecwaf.Client) (map[string]wafassessment.VectorFixture, error) {
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return nil, fmt.Errorf("loading wafcatalog: %w", err)
	}
	byID := make(map[string]wafcatalog.AttackVector, len(catalog))
	for _, v := range catalog {
		byID[v.ID] = v
	}

	fixtures := make(map[string]wafassessment.VectorFixture, len(AutomatedAbuseLiveVectorIDs))
	for _, id := range AutomatedAbuseLiveVectorIDs {
		v, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("vector %q not found in wafcatalog", id)
		}
		responses, err := client.SendBurst(ctx, v.Malicious, automatedAbuseBurstSize)
		if err != nil {
			return nil, fmt.Errorf("driving %s live as a burst against the WAF: %w", id, err)
		}
		key := wafval.CorrelationKey{TestExecutionID: id, RequestID: id}
		results := BuildBurstCollectionResults(responses, key, time.Now())
		fixtures[id] = wafassessment.VectorFixture{
			VectorID:       id,
			Results:        results,
			EvidenceSource: wafassessment.EvidenceSourceLiveExecution,
		}
	}
	return fixtures, nil
}

// RunAutomatedAbuseLive loads the real automated-abuse scenario and its
// merged severities, builds its live fixtures, and evaluates them through
// the real, unmodified wafassessment.EvaluateScenarioWithSeverities.
func RunAutomatedAbuseLive(ctx context.Context, client *modsecwaf.Client) (wafassessment.EnterpriseScenario, wafassessment.ScenarioResult, error) {
	scenario, err := wafassessment.AudspectAutomatedAbuseScenario()
	if err != nil {
		return wafassessment.EnterpriseScenario{}, wafassessment.ScenarioResult{}, fmt.Errorf("loading automated-abuse scenario: %w", err)
	}
	fixtures, err := BuildAutomatedAbuseLiveFixtures(ctx, client)
	if err != nil {
		return wafassessment.EnterpriseScenario{}, wafassessment.ScenarioResult{}, fmt.Errorf("building live fixtures: %w", err)
	}
	severityByID, err := automatedAbuseLiveSeverities()
	if err != nil {
		return wafassessment.EnterpriseScenario{}, wafassessment.ScenarioResult{}, fmt.Errorf("loading severities: %w", err)
	}
	result, err := wafassessment.EvaluateScenarioWithSeverities(scenario, fixtures, severityByID)
	if err != nil {
		return wafassessment.EnterpriseScenario{}, wafassessment.ScenarioResult{}, fmt.Errorf("evaluating scenario: %w", err)
	}
	return scenario, result, nil
}
