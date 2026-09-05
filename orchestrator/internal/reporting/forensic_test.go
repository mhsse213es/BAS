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

// colIndex finds a column by its exact header text, failing the test if the
// header is missing -- robust against the columns being reordered later.
func colIndex(t *testing.T, header []string, name string) int {
	t.Helper()
	for i, h := range header {
		if h == name {
			return i
		}
	}
	t.Fatalf("CSV header missing a %q column", name)
	return -1
}

// TestForensicCSV_DetectionAlertCleanupBlockingControlColumns proves the
// richer per-technique fields the HTML/PDF report already shows --
// detection provider/confidence/MTTD, cleanup verdict/error, and the
// specific blocking control -- are also present in the forensic CSV, not
// just the flat 16-column table it shipped with before.
func TestForensicCSV_DetectionAlertCleanupBlockingControlColumns(t *testing.T) {
	results := []models.SimulationResult{
		{
			Technique:        models.AttackTechnique{ID: "T1003", Name: "OS Credential Dumping", Tactic: "credential-access"},
			Result:           models.ResultFail,
			DetectionVerdict: "detected",
			DetectionAlert:   &models.DetectionAlert{Provider: "CrowdStrike Falcon", Confidence: "high", MTTDMs: 4200},
			CleanupVerdict:   "partial",
			CleanupError:     "access denied removing staged payload",
			BlockingControl:  &models.BlockingControl{Name: "Defender ASR: Block credential stealing"},
		},
	}
	var buf bytes.Buffer
	WriteForensicCSV(&buf, "Test Scenario", results, "", 0)
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("parse csv: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows (header + 1), got %d", len(rows))
	}
	header, row := rows[0], rows[1]

	cases := map[string]string{
		"Detection":            "Detected",
		"Detection Provider":   "CrowdStrike Falcon",
		"Detection Confidence": "high",
		"MTTD (ms)":            "4200",
		"Cleanup Verdict":      "partial",
		"Cleanup Error":        "access denied removing staged payload",
		"Blocking Control":     "Defender ASR: Block credential stealing",
	}
	for col, want := range cases {
		got := row[colIndex(t, header, col)]
		if got != want {
			t.Errorf("column %q = %q, want %q", col, got, want)
		}
	}
}

// TestForensicCSV_DetectionVerdictPreferredOverEventClassifier proves the
// CSV's Detection column can never disagree with the HTML/PDF report for
// the same result: DetectionVerdict (populated by the post-run detection
// sweep, SubmitRunDetections) must win over the older
// classifyDetection(r.Events) heuristic, exactly as engine.go's own
// "DetectionVerdict... is preferred" comment documents. A FAIL result with
// empty Events would classify as "None" via the legacy heuristic alone --
// proving DetectionVerdict="detected" overrides that, not just coexists
// with it.
func TestForensicCSV_DetectionVerdictPreferredOverEventClassifier(t *testing.T) {
	results := []models.SimulationResult{
		{
			Technique:        models.AttackTechnique{ID: "T1003", Name: "OS Credential Dumping", Tactic: "credential-access"},
			Result:           models.ResultFail,
			Events:           nil, // legacy classifier alone would say "None"
			DetectionVerdict: "detected",
		},
	}
	var buf bytes.Buffer
	WriteForensicCSV(&buf, "Test Scenario", results, "", 0)
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("parse csv: %v", err)
	}
	got := rows[1][colIndex(t, rows[0], "Detection")]
	if got != "Detected" {
		t.Errorf("Detection = %q, want %q (DetectionVerdict must win over the empty-Events legacy classifier)", got, "Detected")
	}
}
