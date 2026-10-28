package dlpfixture

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/audspect/bas/internal/scenario"
)

const browserUploadScenarioPath = "../../../scenarios/dlp-exfiltration-browser-upload.yaml"

func TestBrowserUpload_SingleSinkVerifiedMultipartStep(t *testing.T) {
	b, err := os.ReadFile(browserUploadScenarioPath)
	if err != nil {
		t.Fatalf("read %s: %v", browserUploadScenarioPath, err)
	}
	var s scenario.Scenario
	if err := yaml.Unmarshal(b, &s); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	// One step on purpose: sink results are keyed by technique ID, so a second step with the same technique could not be
	// reported separately.
	if len(s.Steps) != 1 {
		t.Fatalf("steps = %d, want exactly 1", len(s.Steps))
	}
	c := s.Steps[0].Command
	for _, want := range []string{"{{SINK_TOKEN}}", "{{SINK_URL}}", "MultipartFormDataContent", "Mozilla/5.0", "text/csv", "[BAS-SIM-DLP]", "[BAS-SIM-DLP-BROWSER-UPLOAD]"} {
		if !strings.Contains(c, want) {
			t.Errorf("command does not contain %q", want)
		}
	}
	// Sink-verified: the verdict comes from the destination's receipt, never from a local marker.
	if strings.Contains(c, "DLP_OBSERVATION: ") {
		t.Error("a sink-verified step must not print a local DLP_OBSERVATION marker")
	}
	for _, banned := range []string{"Start-Process", "Invoke-Expression", "iex ", "DownloadString", "certutil", "bitsadmin"} {
		if strings.Contains(c, banned) {
			t.Errorf("command contains %q", banned)
		}
	}
	if s.Steps[0].TechniqueID != "T1567" || !s.Steps[0].ProductionSafe {
		t.Errorf("technique=%q production_safe=%v, want T1567 and true", s.Steps[0].TechniqueID, s.Steps[0].ProductionSafe)
	}
}
