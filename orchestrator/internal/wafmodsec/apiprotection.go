package wafmodsec

import (
	"context"
	"fmt"
	"time"

	"github.com/audspect/bas/internal/vendors/modsecwaf"
	"github.com/audspect/bas/internal/wafapiflow"
	"github.com/audspect/bas/internal/wafassessment"
	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafval"
)

// APIProtectionLiveVectorIDs is 2 of AudspectAPIProtectionScenario's 8
// contributing vectors: API-003 (wafcatalog, excessive data exposure via
// "query:fields") and APIFLOW-005 (wafapiflow, unbounded bulk-export via
// "query:limit") -- the only two whose PayloadLocation
// modsecwaf.BuildRequest implements. The other 6 use path:/body:/header:
// forms that are real, disclosed gaps, not an oversight.
var APIProtectionLiveVectorIDs = []string{"API-003", "APIFLOW-005"}

// apiflowToWafcatalogTemplate converts a wafapiflow.RequestTemplate to the
// structurally identical wafcatalog.RequestTemplate modsecwaf.Client.Send
// requires -- the two types are independent (wafapiflow depends on neither
// wafcatalog nor modsecwaf), so this conversion, not a modsecwaf change, is
// what lets this one live client drive vectors from either catalog.
func apiflowToWafcatalogTemplate(t wafapiflow.RequestTemplate) wafcatalog.RequestTemplate {
	return wafcatalog.RequestTemplate{
		Method:          t.Method,
		Path:            t.Path,
		PayloadLocation: t.PayloadLocation,
		Payload:         t.Payload,
		Description:     t.Description,
	}
}

// apiProtectionLiveSeverities mirrors wafassessment's own (unexported)
// apiProtectionSeverities: the real severity of every API Protection
// contributing vector ID, merged across both source catalogs. Required by
// wafassessment.EvaluateScenarioWithSeverities, which this scenario must
// use instead of EvaluateScenario since its vectors span two catalogs.
func apiProtectionLiveSeverities() (map[string]wafcatalog.Severity, error) {
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return nil, fmt.Errorf("loading wafcatalog: %w", err)
	}
	apiflow, err := wafapiflow.AudspectWAFAPIFlowCatalog()
	if err != nil {
		return nil, fmt.Errorf("loading wafapiflow catalog: %w", err)
	}
	severityByID := make(map[string]wafcatalog.Severity, len(catalog)+len(apiflow))
	for _, v := range catalog {
		severityByID[v.ID] = v.Severity
	}
	for _, v := range apiflow {
		severityByID[v.ID] = wafcatalog.Severity(string(v.Severity))
	}
	return severityByID, nil
}

// BuildAPIProtectionLiveFixtures drives API-003 (wafcatalog) and
// APIFLOW-005 (wafapiflow) against the live WAF client and returns one
// wafassessment.VectorFixture per vector, labeled
// EvidenceSourceLiveExecution.
func BuildAPIProtectionLiveFixtures(ctx context.Context, client *modsecwaf.Client) (map[string]wafassessment.VectorFixture, error) {
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return nil, fmt.Errorf("loading wafcatalog: %w", err)
	}
	byID := make(map[string]wafcatalog.AttackVector, len(catalog))
	for _, v := range catalog {
		byID[v.ID] = v
	}
	apiflow, err := wafapiflow.AudspectWAFAPIFlowCatalog()
	if err != nil {
		return nil, fmt.Errorf("loading wafapiflow catalog: %w", err)
	}
	apiflowByID := make(map[string]wafapiflow.APIFlowVector, len(apiflow))
	for _, v := range apiflow {
		apiflowByID[v.ID] = v
	}

	fixtures := make(map[string]wafassessment.VectorFixture, len(APIProtectionLiveVectorIDs))
	for _, id := range APIProtectionLiveVectorIDs {
		var tmpl wafcatalog.RequestTemplate
		if v, ok := byID[id]; ok {
			tmpl = v.Malicious
		} else if v, ok := apiflowByID[id]; ok {
			tmpl = apiflowToWafcatalogTemplate(v.Malicious)
		} else {
			return nil, fmt.Errorf("vector %q not found in either real catalog", id)
		}
		resp, err := client.Send(ctx, tmpl)
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

// RunAPIProtectionLive loads the real api-protection scenario and its
// merged severities, builds its live fixtures, and evaluates them through
// the real, unmodified wafassessment.EvaluateScenarioWithSeverities.
func RunAPIProtectionLive(ctx context.Context, client *modsecwaf.Client) (wafassessment.EnterpriseScenario, wafassessment.ScenarioResult, error) {
	scenario, err := wafassessment.AudspectAPIProtectionScenario()
	if err != nil {
		return wafassessment.EnterpriseScenario{}, wafassessment.ScenarioResult{}, fmt.Errorf("loading api-protection scenario: %w", err)
	}
	fixtures, err := BuildAPIProtectionLiveFixtures(ctx, client)
	if err != nil {
		return wafassessment.EnterpriseScenario{}, wafassessment.ScenarioResult{}, fmt.Errorf("building live fixtures: %w", err)
	}
	severityByID, err := apiProtectionLiveSeverities()
	if err != nil {
		return wafassessment.EnterpriseScenario{}, wafassessment.ScenarioResult{}, fmt.Errorf("loading severities: %w", err)
	}
	result, err := wafassessment.EvaluateScenarioWithSeverities(scenario, fixtures, severityByID)
	if err != nil {
		return wafassessment.EnterpriseScenario{}, wafassessment.ScenarioResult{}, fmt.Errorf("evaluating scenario: %w", err)
	}
	return scenario, result, nil
}
