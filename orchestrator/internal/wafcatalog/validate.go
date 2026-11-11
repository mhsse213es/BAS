package wafcatalog

import "fmt"

// ValidateCatalog rejects a catalog containing two entries with the same ID.
// NewAttackVector cannot see sibling entries, so this is the single place
// uniqueness is enforced across a whole catalog snapshot.
func ValidateCatalog(vectors []AttackVector) error {
	seen := make(map[string]bool, len(vectors))
	for _, v := range vectors {
		if seen[v.ID] {
			return fmt.Errorf("duplicate attack vector ID %q", v.ID)
		}
		seen[v.ID] = true
		switch v.Platform {
		case PlatformUnspecified, PlatformAny, PlatformUnix, PlatformWindows:
		default:
			return fmt.Errorf("attack vector %q has unknown platform %q", v.ID, v.Platform)
		}
	}
	return nil
}
