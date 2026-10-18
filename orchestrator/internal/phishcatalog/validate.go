package phishcatalog

import "fmt"

// ValidateCatalog rejects a catalog containing a duplicate scenario ID, an
// unrecognized Coverage state, or a Coverage above CoverageCatalogOnly
// with no MappedImplementation -- structurally enforcing phishing.txt's
// "a catalog entry is not an executable scenario" rule: nothing may claim
// fixture/adapter/live-tested coverage without naming what actually
// implements it.
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
