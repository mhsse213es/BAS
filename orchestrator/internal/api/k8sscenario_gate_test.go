package api

import (
	"testing"

	"github.com/audspect/bas/internal/license"
)

// TestK8sScenarioRoutesAreCloudProduct checks the Kubernetes routes sit under the Enterprise cloud product line,
// so a licence without it cannot read or drive them.
func TestK8sScenarioRoutesAreCloudProduct(t *testing.T) {
	for _, path := range []string{"/api/k8s-scenarios", "/api/k8s-scenarios/runs", "/api/k8s-scenarios/runs/x/approve"} {
		line, ok := productForPath(path)
		if !ok || line != license.ProductCloud {
			t.Fatalf("%s maps to (%q, %v), want the cloud product", path, line, ok)
		}
	}
}
