package wafapiflow

import "fmt"

// ValidateAPIFlowCatalog rejects a catalog containing two vectors with the
// same ID. NewAPIFlowVector cannot see sibling entries, so this is the
// single place uniqueness is enforced across a whole catalog snapshot.
func ValidateAPIFlowCatalog(vectors []APIFlowVector) error {
	seen := make(map[string]bool, len(vectors))
	for _, v := range vectors {
		if seen[v.ID] {
			return fmt.Errorf("duplicate API-flow vector ID %q", v.ID)
		}
		seen[v.ID] = true
	}
	return nil
}
