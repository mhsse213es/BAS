package wafpolicygap

import "fmt"

// ValidatePolicyGapCatalog rejects a catalog containing two scenarios with
// the same ID. NewPolicyGapScenario cannot see sibling entries, so this is
// the single place uniqueness is enforced across a whole catalog snapshot.
func ValidatePolicyGapCatalog(scenarios []PolicyGapScenario) error {
	seen := make(map[string]bool, len(scenarios))
	for _, s := range scenarios {
		if seen[s.ID] {
			return fmt.Errorf("duplicate policy-gap scenario ID %q", s.ID)
		}
		seen[s.ID] = true
	}
	return nil
}
