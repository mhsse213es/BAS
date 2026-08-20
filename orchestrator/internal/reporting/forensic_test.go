package reporting

import (
	"bytes"
	"encoding/csv"
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
	WriteForensicCSV(&buf, "Test Scenario", results, "", 0)
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

// TestForensicCSV_StepNameColumn proves each row's Step Name column carries
// the specific dispatched atomic's own name, distinguishing rows that share
// the same Technique ID/Name -- routine in a Full Sweep, where a technique
// commonly has several atomics tested in one run.
func TestForensicCSV_StepNameColumn(t *testing.T) {
	results := []models.SimulationResult{
		{
			Technique: models.AttackTechnique{ID: "T1003", Name: "OS Credential Dumping", Tactic: "credential-access"},
			StepName:  "T1003 - Test 1: Mimikatz",
			Severity:  "Critical", Result: models.ResultFail,
		},
		{
			Technique: models.AttackTechnique{ID: "T1003", Name: "OS Credential Dumping", Tactic: "credential-access"},
			StepName:  "T1003 - Test 3: LSASS dump via comsvcs.dll MiniDump",
			Severity:  "Critical", Result: models.ResultPass,
		},
	}
	var buf bytes.Buffer
	WriteForensicCSV(&buf, "Test Scenario", results, "", 0)

	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("parse csv: %v", err)
	}
	if len(rows) != 3 { // header + 2 rows
		t.Fatalf("expected 3 rows, got %d", len(rows))
	}
	colIdx := -1
	for i, h := range rows[0] {
		if h == "Step Name" {
			colIdx = i
		}
	}
	if colIdx == -1 {
		t.Fatal("CSV header missing a \"Step Name\" column")
	}
	if rows[1][colIdx] != "T1003 - Test 1: Mimikatz" {
		t.Errorf("row 1 Step Name = %q, want %q", rows[1][colIdx], "T1003 - Test 1: Mimikatz")
	}
	if rows[2][colIdx] != "T1003 - Test 3: LSASS dump via comsvcs.dll MiniDump" {
		t.Errorf("row 2 Step Name = %q, want %q", rows[2][colIdx], "T1003 - Test 3: LSASS dump via comsvcs.dll MiniDump")
	}
	if rows[1][colIdx] == rows[2][colIdx] {
		t.Error("both rows have the same Technique ID/Name but must show distinct Step Names")
	}
}
