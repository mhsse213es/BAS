package reporting

import (
	"bytes"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/models"
)

func TestForensicCSV(t *testing.T) {
	results := []models.SimulationResult{
		{
			Technique: models.AttackTechnique{ID: "T1003", Name: "OS Credential Dumping", Tactic: "credential-access"},
			Severity:  "Critical", Result: models.ResultFail,
			Details: "Exploited CVE-2021-34527 via spooler.", Remediation: "Patch.",
		},
		{
			Technique: models.AttackTechnique{ID: "T1059", Name: "Command Interpreter", Tactic: "execution"},
			Severity:  "High", Result: models.ResultPass,
			Details: "Blocked by AppControl.",
		},
	}
	var buf bytes.Buffer
	WriteForensicCSV(&buf, "Test Scenario", results)
	out := buf.String()

	for _, want := range []string{
		"Technique ID", "ATT&CK URL", // header
		"Not Prevented",              // FAIL → Not Prevented
		"Prevented",                  // PASS → Prevented
		"CVE-2021-34527",             // surfaced from the result's own text
		"Credential Access",          // humanized tactic
	} {
		if !strings.Contains(out, want) {
			t.Errorf("forensic CSV missing %q", want)
		}
	}
	// CVE must NOT be fabricated for the PASS row (no CVE in its text).
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 { // header + 2 rows
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	if strings.Contains(lines[2], "CVE-") {
		t.Errorf("PASS row must not carry a CVE: %s", lines[2])
	}
}
