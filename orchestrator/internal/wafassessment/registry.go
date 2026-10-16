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

// scenarioRegistry is the slug -> loader lookup every enterprise
// scenario registers itself in. The slug is the console-facing
// identifier (used in URLs); it is deliberately distinct from
// EnterpriseScenario.ID, which is the catalog-facing identifier.
var scenarioRegistry = map[string]scenarioLoader{
	"exploit-prevention":      loadExploitPreventionScenario,
	"http-protocol-integrity": loadHTTPProtocolIntegrityScenario,
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
