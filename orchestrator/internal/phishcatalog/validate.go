package phishcatalog

import "fmt"

// ValidateCatalog rejects a catalog containing a duplicate scenario ID, an
// unrecognized Coverage state, a Coverage above CoverageCatalogOnly with
// no MappedImplementation, or a Variant whose ID collides with any
// scenario/variant ID or whose BaseScenarioID does not resolve within the
// same catalog -- structurally enforcing phishing.txt's "a catalog entry
// is not an executable scenario" rule: nothing may claim fixture/adapter/
// live-tested coverage without naming what actually implements it, and
// no variant may silently duplicate an implementation under an
// unconnected ID.
func ValidateCatalog(scenarios []Scenario) error {
	seen := make(map[string]bool, len(scenarios))
	for _, s := range scenarios {
		if seen[s.ID] {
			return fmt.Errorf("duplicate scenario ID %q", s.ID)
		}
		seen[s.ID] = true
		switch s.Coverage {
		case CoverageCatalogOnly, CoverageFixtureTested, CoverageAdapterTested, CoverageLiveValidated:
		default:
			return fmt.Errorf("scenario %q: unrecognized coverage state %q", s.ID, s.Coverage)
		}
		if s.Coverage != CoverageCatalogOnly && s.MappedImplementation == "" {
			return fmt.Errorf("scenario %q: coverage %q claimed with no MappedImplementation", s.ID, s.Coverage)
		}
		for _, v := range s.Variants {
			if seen[v.ID] {
				return fmt.Errorf("duplicate scenario/variant ID %q", v.ID)
			}
			seen[v.ID] = true
			if v.BaseScenarioID != s.ID {
				return fmt.Errorf("variant %q: BaseScenarioID %q does not match owning scenario %q", v.ID, v.BaseScenarioID, s.ID)
			}
		}
	}
	return nil
}

// ByID resolves a scenario ID within scenarios, or false if unknown.
func ByID(scenarios []Scenario, id string) (Scenario, bool) {
	for _, s := range scenarios {
		if s.ID == id {
			return s, true
		}
	}
	return Scenario{}, false
}

// VariantByID resolves a variant ID within scenarios (searching every
// scenario's own Variants slice), or false if unknown.
func VariantByID(scenarios []Scenario, id string) (Variant, bool) {
	for _, s := range scenarios {
		for _, v := range s.Variants {
			if v.ID == id {
				return v, true
			}
		}
	}
	return Variant{}, false
}
