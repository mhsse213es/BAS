package integrity

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLinuxInstalledSoftwareScenarioSignatureVerifies loads the shipped
// scenario and its .sig from the repo and checks the signature against the
// edited YAML. A stale or mismatched .sig fails this test.
func TestLinuxInstalledSoftwareScenarioSignatureVerifies(t *testing.T) {
	path := filepath.Join("..", "..", "..", "scenarios", "linux-installed-software.yaml")
	if _, err := os.Stat(path + ".sig"); err != nil {
		t.Fatalf("missing .sig: %v", err)
	}
	if err := VerifyScenarioFile(path); err != nil {
		t.Fatalf("scenario signature does not verify: %v", err)
	}
}
