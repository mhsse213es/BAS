package emailgwefficacy

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The console keeps its own copy of the scenario list (web/src/features/email.js, EG_CATALOG) because the server has
// no endpoint that lists the static scenarios. That copy fell behind once already (it stopped at EG-010 while the
// server ran EG-020). This test fails the build when any expectation the server can run is missing from the console.
func TestConsoleCatalogListsEveryExpectationTheServerCanRun(t *testing.T) {
	path := filepath.Join("..", "..", "web", "src", "features", "email.js")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("console source not available from this checkout: %v", err)
	}
	src := string(raw)
	var missing []string
	for id := range expectationByID {
		if !strings.Contains(src, "'"+id+"'") {
			missing = append(missing, id)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d expectation(s) can be run by the server but are not in EG_CATALOG in web/src/features/email.js: %v", len(missing), missing)
	}
}
