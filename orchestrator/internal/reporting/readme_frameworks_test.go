package reporting

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/compliance"
)

// The audit pack README must list every framework the pack actually writes, not a typed-in subset.
func TestAuditPackReadmeListsEveryLoadedFramework(t *testing.T) {
	m, err := compliance.NewMapper()
	if err != nil {
		t.Fatalf("NewMapper: %v", err)
	}
	listing := frameworkListing(m)
	for _, fw := range m.Frameworks() {
		if !strings.Contains(listing, fw.ID+".csv") {
			t.Errorf("README framework list omits %s.csv", fw.ID)
		}
	}
}
