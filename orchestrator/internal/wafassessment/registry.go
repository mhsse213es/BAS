package wafassessment

import (
	"fmt"

	"github.com/audspect/bas/internal/wafcatalog"
)

// scenarioLoader fully owns its own evaluation path -- it loads
// whatever seed scenario/fixtures/catalog it needs and evaluates them
// however is correct for that scenario's claim shape (ClaimPrevention
// via EvaluateScenario today; future scenarios may evaluate a
// different wafval claim or verdict shape entirely). The registry and
// everything built on it (reporting, API handlers) only ever sees the
// resulting (EnterpriseScenario, ScenarioResult), so it stays uniform
// across however many different evaluation shapes the real scenarios
// turn out to need.
type scenarioLoader func() (EnterpriseScenario, ScenarioResult, error)

func loadExploitPreventionScenario() (EnterpriseScenario, ScenarioResult, error) {
	scenario, err := AudspectExploitPreventionScenario()
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	fixtures, err := AudspectExploitPreventionFixtures()
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	result, err := EvaluateScenario(scenario, fixtures, catalog)
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	return scenario, result, nil
}

func loadHTTPProtocolIntegrityScenario() (EnterpriseScenario, ScenarioResult, error) {
	scenario, err := AudspectHTTPProtocolIntegrityScenario()
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	fixtures, err := AudspectHTTPProtocolIntegrityFixtures()
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	result, err := EvaluateScenario(scenario, fixtures, catalog)
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	return scenario, result, nil
}

func loadAPIProtectionScenario() (EnterpriseScenario, ScenarioResult, error) {
	scenario, err := AudspectAPIProtectionScenario()
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	fixtures, err := AudspectAPIProtectionFixtures()
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	severityByID, err := apiProtectionSeverities()
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	result, err := EvaluateScenarioWithSeverities(scenario, fixtures, severityByID)
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	return scenario, result, nil
}

func loadAutomatedAbuseScenario() (EnterpriseScenario, ScenarioResult, error) {
	scenario, err := AudspectAutomatedAbuseScenario()
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	fixtures, err := AudspectAutomatedAbuseFixtures()
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	severityByID, err := automatedAbuseSeverities()
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	result, err := EvaluateScenarioWithSeverities(scenario, fixtures, severityByID)
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	return scenario, result, nil
}

func loadPolicyIntegrityScenario() (EnterpriseScenario, ScenarioResult, error) {
	scenario, err := AudspectPolicyIntegrityScenario()
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	fixtures := AudspectPolicyIntegrityFixtures()
	result, err := EvaluatePolicyIntegrityScenario(scenario, policyIntegrityPolicyBasis, fixtures)
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	return scenario, result, nil
}

func loadRoutingCacheIntegrityScenario() (EnterpriseScenario, ScenarioResult, error) {
	scenario, err := AudspectRoutingCacheIntegrityScenario()
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	fixtures, err := AudspectRoutingCacheIntegrityFixtures()
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	result, err := EvaluateScenario(scenario, fixtures, catalog)
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	return scenario, result, nil
}

func loadFileUploadContentTrustScenario() (EnterpriseScenario, ScenarioResult, error) {
	scenario, err := AudspectFileUploadContentTrustScenario()
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	fixtures, err := AudspectFileUploadContentTrustFixtures()
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	result, err := EvaluateScenario(scenario, fixtures, catalog)
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	return scenario, result, nil
}

func loadDetectionTelemetryScenario() (EnterpriseScenario, ScenarioResult, error) {
	scenario, err := AudspectDetectionTelemetryScenario()
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	fixtures := AudspectDetectionTelemetryFixtures()
	result, err := EvaluateDetectionTelemetryScenario(scenario, fixtures)
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	return scenario, result, nil
}

func loadLegitimateTrafficScenario() (EnterpriseScenario, ScenarioResult, error) {
	scenario, err := AudspectLegitimateTrafficScenario()
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	fixtures := AudspectLegitimateTrafficFixtures()
	severityByID, err := legitTrafficSeverities()
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	result, err := EvaluateLegitimateTrafficScenario(scenario, fixtures, severityByID)
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	return scenario, result, nil
}

func loadOriginResilienceScenario() (EnterpriseScenario, ScenarioResult, error) {
	scenario, err := AudspectOriginResilienceScenario()
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	fixtures := AudspectOriginResilienceFixtures()
	result, err := EvaluateOriginResilienceScenario(scenario, originResiliencePolicyBasis, fixtures)
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	return scenario, result, nil
}

// scenarioRegistry is the slug -> loader lookup every enterprise
// scenario registers itself in. The slug is the console-facing
// identifier (used in URLs); it is deliberately distinct from
// EnterpriseScenario.ID, which is the catalog-facing identifier.
var scenarioRegistry = map[string]scenarioLoader{
	"exploit-prevention":        loadExploitPreventionScenario,
	"http-protocol-integrity":   loadHTTPProtocolIntegrityScenario,
	"api-protection":            loadAPIProtectionScenario,
	"automated-abuse":           loadAutomatedAbuseScenario,
	"policy-integrity":          loadPolicyIntegrityScenario,
	"routing-cache-integrity":   loadRoutingCacheIntegrityScenario,
	"file-upload-content-trust": loadFileUploadContentTrustScenario,
	"detection-telemetry":       loadDetectionTelemetryScenario,
	"legitimate-traffic":        loadLegitimateTrafficScenario,
	"origin-resilience":         loadOriginResilienceScenario,
}

// EvaluateScenarioBySlug looks up slug in the registry and returns its
// real, current seed scenario and evaluated result.
func EvaluateScenarioBySlug(slug string) (EnterpriseScenario, ScenarioResult, error) {
	loader, ok := scenarioRegistry[slug]
	if !ok {
		return EnterpriseScenario{}, ScenarioResult{}, fmt.Errorf("unknown enterprise scenario slug %q", slug)
	}
	scenario, result, err := loader()
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, fmt.Errorf("evaluating scenario %q: %w", slug, err)
	}
	return scenario, result, nil
}
