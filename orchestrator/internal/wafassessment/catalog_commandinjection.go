package wafassessment

import (
	"fmt"

	"github.com/audspect/bas/internal/wafcatalog"
)

// AudspectCommandInjectionScenario bundles all sixteen command-injection
// vectors (CMDI-001..016) under one objective. It is the console-facing
// view of the Phase 1 WAF depth work.
//
// Every vector is UNTESTED in this build. AudspectCommandInjectionFixtures
// returns an empty map on purpose: no live WAF has been run against these
// payloads, so no outcome is recorded. Recording a Blocked or Missed result
// here would be invented evidence. The evaluator reports each vector without
// a fixture as untested and never counts it as a pass, so the scenario stays
// ScenarioIncomplete until a lab run supplies real collection results.
func AudspectCommandInjectionScenario() (EnterpriseScenario, error) {
	ids := make([]string, 0, 16)
	for i := 1; i <= 16; i++ {
		ids = append(ids, fmt.Sprintf("CMDI-%03d", i))
	}
	scenario, err := NewEnterpriseScenario(
		"WAFSCENARIO-COMMAND-INJECTION-DEPTH",
		"Command Injection Depth",
		"evaluate whether the WAF blocks OS command injection across Unix and Windows shells, the common operator forms, obfuscation (quote-splitting, caret-escape, ${IFS}, encoding), and input locations beyond the query string (headers and JSON bodies), while keeping the benign twin of each request unblocked",
		ids,
		"target exposes a diagnostic or conversion endpoint that passes user input to an OS shell, reachable through the WAF; a lab WAF with its own telemetry; Unix-like and Windows origin hosts for the platform-specific vectors",
		"a WAF-mechanism CollectionResult per contributing vector from a live lab run, with the benign twin of each vector also observed; none recorded in this build",
		"catalog CMDI-001..016 (Phase 1 WAF depth, 2026-11); payloads are harmless probes enforced by the catalog deny-list; no seeded fixture outcomes by design",
	)
	if err != nil {
		return EnterpriseScenario{}, fmt.Errorf("loading command-injection-depth scenario: %w", err)
	}
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return EnterpriseScenario{}, fmt.Errorf("loading command-injection-depth scenario: %w", err)
	}
	if err := ValidateAgainstCatalog(scenario, catalog); err != nil {
		return EnterpriseScenario{}, fmt.Errorf("loading command-injection-depth scenario: %w", err)
	}
	return scenario, nil
}

// AudspectCommandInjectionFixtures returns no fixtures. See
// AudspectCommandInjectionScenario for why this is empty by design.
func AudspectCommandInjectionFixtures() (map[string]VectorFixture, error) {
	return map[string]VectorFixture{}, nil
}

func loadCommandInjectionScenario() (EnterpriseScenario, ScenarioResult, error) {
	scenario, err := AudspectCommandInjectionScenario()
	if err != nil {
		return EnterpriseScenario{}, ScenarioResult{}, err
	}
	fixtures, err := AudspectCommandInjectionFixtures()
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
