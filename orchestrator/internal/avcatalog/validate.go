package avcatalog

import "fmt"

// ValidateCatalog rejects a catalog containing a duplicate vector ID.
func ValidateCatalog(vectors []Vector) error {
	seen := make(map[string]bool, len(vectors))
	for _, v := range vectors {
		if seen[v.ID] {
			return fmt.Errorf("duplicate vector ID %q", v.ID)
		}
		seen[v.ID] = true
	}
	return nil
}
