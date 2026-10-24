package cvecatalog

import "fmt"

// ValidateCatalog rejects a catalog containing two entries with the same
// CVE ID. NewCVEEntry cannot see sibling entries, so this is the single
// place uniqueness is enforced across a whole catalog snapshot.
func ValidateCatalog(entries []CVEEntry) error {
	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		if seen[e.ID] {
			return fmt.Errorf("duplicate CVE ID %q", e.ID)
		}
		seen[e.ID] = true
	}
	return nil
}
