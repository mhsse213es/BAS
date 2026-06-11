package reporting

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	fpdf "github.com/go-pdf/fpdf"

	"github.com/audspect/bas/internal/models"
)

// The cp1252 translator must convert UTF-8 punctuation to single core-font bytes
// so it renders correctly. If it is not applied, the raw multi-byte UTF-8
// sequences survive into the (uncompressed) content stream and render as
// mojibake (e.g. "—" → "Ã¢â‚¬â€•"). Assert those sequences are absent.
func TestPDFUnicodeTranslatorEncodesPunctuation(t *testing.T) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetCompression(false)
	pdf.AddPage()
	pdf.SetFont("Helvetica", "", 12)
	tr := pdf.UnicodeTranslatorFromDescriptor("")
	pdf.Cell(0, 10, tr("em—dash mid·dot 2.5× tail…"))

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		t.Fatalf("Output: %v", err)
	}
	raw := buf.Bytes()
	utf8Seqs := map[string][]byte{
		"em dash (—)":  {0xE2, 0x80, 0x94},
		"middot (·)":   {0xC2, 0xB7},
		"multiply (×)": {0xC3, 0x97},
		"ellipsis (…)": {0xE2, 0x80, 0xA6},
	}
	for name, seq := range utf8Seqs {
		if bytes.Contains(raw, seq) {
			t.Errorf("PDF still contains raw UTF-8 %s — translator not applied (mojibake)", name)
		}
	}
}

// The detailed-results report must distinguish a passive configuration audit
// from an active exploit so a reader does not treat "is WDigest disabled?" and
// "dump LSASS" as the same evidence. ART/Caldera execute the technique; custom
// posture checks and everything else only inspect configuration.
func TestTestKindClassification(t *testing.T) {
	cases := []struct {
		framework string
		want      string
	}{
		{"art", "Active Adversary Behavioral Test"},
		{"ART", "Active Adversary Behavioral Test"},
		{"caldera", "Active Adversary Behavioral Test"},
		{"custom", "Policy Configuration Check"},
		{"sigma", "Policy Configuration Check"},
		{"", "Policy Configuration Check"},
		{"  custom  ", "Policy Configuration Check"},
	}
	for _, c := range cases {
		if got := testKind(c.framework); got != c.want {
			t.Errorf("testKind(%q) = %q, want %q", c.framework, got, c.want)
		}
	}
}

func TestRenderReportPDF(t *testing.T) {
	now := time.Now().UTC()
	rep := &FullReport{
		GeneratedAt: now,
		Agent: models.Agent{
			AgentID: "agent-123", Hostname: "BANK-WS-01",
			OSVersion: "Windows 11 Pro 23H2", EnvLabel: "Production",
		},
		Summary: ExecutiveSummary{
			RiskScore: 72, Classification: "High Risk",
			PreventionScore: 41, ExposureScore: 63,
			CoverageScore: 0, KillChainCoverage: 21, KillChainAmplifier: 1.8,
			Trend: "Baseline", TotalTechniques: 12, PassedTechniques: 5, FailedTechniques: 7,
			LastRunAt: now, LastScenarioName: "RBI Ransomware Resilience Sweep",
			CriticalFailures: []models.CriticalFailure{
				{TechniqueID: "T1486", Name: "Data Encrypted for Impact", Tactic: "impact", Severity: "Critical"},
			},
			Recommendations: []string{
				"Deploy application allow-listing to block unsigned binaries.",
				"Enable tamper protection on the EDR agent.",
			},
		},
		TacticHeatmap: []TacticEntry{
			{Tactic: "execution", Passed: 2, Failed: 1, Total: 3, PassPct: 66, Weight: "High"},
			{Tactic: "credential-access", Passed: 0, Failed: 3, Total: 3, PassPct: 0, Weight: "Critical"},
		},
		TopFindings: []Finding{
			{TechniqueID: "T1003", TechniqueName: "OS Credential Dumping", Tactic: "credential-access",
				Severity: "Critical", Details: "LSASS memory was read without being blocked.",
				Remediation: "Enable Credential Guard and LSA protection."},
		},
		Runs: []RunSummary{{ID: "run-abcdef123456", ScenarioName: "RBI Ransomware Resilience Sweep"}},
		ObjectiveRisks: []ObjectiveRisk{
			{Objective: "Credential Theft", Tactic: "credential-access", Risk: "High", Tested: 3, Failed: 3},
			{Objective: "Persistence", Tactic: "persistence", Risk: "Low", Tested: 2, Failed: 0},
			{Objective: "Code Execution", Tactic: "execution", Risk: "Medium", Tested: 3, Failed: 1},
		},
		Reverted: []string{
			`Registry: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\AtomicTest (deleted)`,
			`File: C:\Windows\TEMP\nanodump.dmp (deleted)`,
		},
		SecurityTools: []string{"Microsoft Defender (real-time protection ON)", "EDR: CrowdStrike Falcon", "EDR: Sysmon"},
		Detection:     DetectionSummary{ExecutedUnprevented: 7, Detected: 2, LoggedOnly: 3, Undetected: 2},
	}
	results := []models.SimulationResult{
		{Technique: models.AttackTechnique{ID: "T1059.001", Name: "PowerShell", Tactic: "execution"},
			Result: models.ResultFail, Severity: "High",
			Details:      "Encoded PowerShell command executed successfully.",
			ThreatImpact: "An attacker can run arbitrary code in memory, evading file-based AV.",
			Remediation:  "Enable Constrained Language Mode and script block logging.",
			Framework:    "art"},
		{Technique: models.AttackTechnique{ID: "T1003", Name: "OS Credential Dumping", Tactic: "credential-access"},
			Result: models.ResultPass, Severity: "Critical",
			Details: "Access to LSASS was denied by the security control.", Framework: "art"},
		{Technique: models.AttackTechnique{ID: "T1547", Name: "Boot Autostart", Tactic: "persistence"},
			Result: models.ResultSkipped, Severity: "Medium", Framework: "art"},
		// ERROR verdict whose detail carries the punctuation that mojibakes under
		// the WinAnsi core font (— · × …). Rendering must succeed: a runtime
		// failure to load the cp1252 translator surfaces as an Output error here.
		{Technique: models.AttackTechnique{ID: "T1112", Name: "Modify Registry", Tactic: "defense-evasion"},
			Result: models.ResultError, Severity: "High",
			Details:   "Execution error (malformed content) — ERROR: Invalid syntax · amplified 2.5× …",
			Framework: "art"},
	}
	// Give the FAIL result detection telemetry so the per-row Detection line renders.
	results[0].Events = []string{"1116:Microsoft-Windows-Windows Defender/Operational"}

	var buf bytes.Buffer
	if err := RenderReportPDF(&buf, rep, results); err != nil {
		t.Fatalf("RenderReportPDF: %v", err)
	}
	if !strings.HasPrefix(buf.String(), "%PDF-") {
		t.Errorf("output is not a PDF (prefix %q)", buf.String()[:min(8, buf.Len())])
	}
	if buf.Len() < 3000 {
		t.Errorf("PDF suspiciously small: %d bytes", buf.Len())
	}
	if out := os.Getenv("BAS_PDF_OUT"); out != "" {
		if err := os.WriteFile(out, buf.Bytes(), 0644); err != nil {
			t.Fatalf("write sample: %v", err)
		}
		t.Logf("wrote sample PDF to %s (%d bytes)", out, buf.Len())
	}
}
