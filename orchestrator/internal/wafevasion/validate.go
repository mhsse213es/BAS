package wafevasion

import "fmt"

// ValidateEvasionCatalog rejects a catalog containing two scenarios with
// the same ID. NewEvasionScenario cannot see sibling entries, so this is
// the single place uniqueness is enforced across a whole catalog snapshot.
func ValidateEvasionCatalog(scenarios []EvasionScenario) error {
	seen := make(map[string]bool, len(scenarios))
	for _, s := range scenarios {
		if seen[s.ID] {
			return fmt.Errorf("duplicate evasion scenario ID %q", s.ID)
		}
		seen[s.ID] = true
	}
	return nil
}
