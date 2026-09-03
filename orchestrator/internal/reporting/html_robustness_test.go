package reporting

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
)

// robustnessReport builds the minimal FullReport needed to reach the report
// sections these regression tests target (Executive Summary, the Detection
// Validation Matrix, Technical Findings cards, and the Environment
// Restoration section). Callers override TechniqueMatrix/EnvRestoration/
// Glossary for the specific bug under test.
func robustnessReport(now time.Time) *FullReport {
	return &FullReport{
		GeneratedAt: now,
		Agent: models.Agent{
			AgentID: "agent-rt", Hostname: "RT-HOST", IPAddress: "10.0.0.9",
		},
		Summary: ExecutiveSummary{
			RiskScore: 50, Classification: "Medium Risk",
			TotalRuns: 1, TotalTechniques: 1, LastRunAt: now, LastScenarioName: "Robustness Test",
		},
		Reliability: Reliability{Attempted: 1, Valid: 1, Confidence: "High"},
	}
}

// TestGenerateHTML_CleanupVerdictOmitted regression-tests html.go's cleanup-
// verdict rendering: TechniqueRow.CleanupVerdict is `omitempty` (engine.go),
// so a technique with no cleanup verdict is a genuinely common shape (e.g. a
// step that never ran a cleanup command) and arrives at the template as a
// missing map key — a nil interface{} — rather than "". Before the fix, both
// the bare `{{eq .cleanupVerdict "..."}}` comparisons and the
// cleanupVerdictColor/cleanupVerdictLabel funcs (typed for `string`) errored
// on that nil and aborted the render.
func TestGenerateHTML_CleanupVerdictOmitted(t *testing.T) {
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	rep := robustnessReport(now)
	rep.TechniqueMatrix = []TechniqueRow{
		{
			TechniqueID: "T1059.001", TechniqueName: "PowerShell", Tactic: "execution",
			Severity: "Critical", ExecVerdict: "fail",
			// CleanupVerdict intentionally left "" (zero value, dropped by omitempty).
		},
	}
	var buf bytes.Buffer
	if err := GenerateHTML(&buf, rep, nil); err != nil {
		t.Fatalf("GenerateHTML errored after %d bytes: %v", buf.Len(), err)
	}
	out := buf.String()
	if !strings.Contains(out, "T1059.001") {
		t.Fatalf("rendered report missing the seeded technique; output %d bytes", len(out))
	}
	// cleanupVerdictLabel's fallback for an unset verdict is an em dash.
	if !strings.Contains(out, "—") {
		t.Errorf("expected the no-cleanup-defined fallback label (—) in output")
	}
}

// TestGenerateHTML_DistinguishesStepNamesForSameTechnique proves the
// Detection Validation Matrix table renders each atomic's own step name, so
// two rows sharing the same TechniqueID/TechniqueName (routine in a Full
// Sweep, where one technique commonly has several atomics) are visually
// distinguishable in the rendered HTML report, not just identical duplicate
// rows.
func TestGenerateHTML_DistinguishesStepNamesForSameTechnique(t *testing.T) {
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	rep := robustnessReport(now)
	rep.TechniqueMatrix = []TechniqueRow{
		{
			TechniqueID: "T1003", TechniqueName: "OS Credential Dumping", Tactic: "credential-access",
			StepName: "T1003 - Test 1: Mimikatz",
			Severity: "Critical", ExecVerdict: "fail",
		},
		{
			TechniqueID: "T1003", TechniqueName: "OS Credential Dumping", Tactic: "credential-access",
			StepName: "T1003 - Test 3: LSASS dump via comsvcs.dll MiniDump",
			Severity: "Critical", ExecVerdict: "pass",
		},
	}
	var buf bytes.Buffer
	if err := GenerateHTML(&buf, rep, nil); err != nil {
		t.Fatalf("GenerateHTML errored after %d bytes: %v", buf.Len(), err)
	}
	out := buf.String()
	if !strings.Contains(out, "T1003 - Test 1: Mimikatz") {
		t.Error("rendered report missing the first atomic's step name")
	}
	if !strings.Contains(out, "T1003 - Test 3: LSASS dump via comsvcs.dll MiniDump") {
		t.Error("rendered report missing the second atomic's step name")
	}
}

// TestGenerateHTML_EnvRestorationNil regression-tests that a FullReport with
// EnvRestoration == nil (real shape: engine.go only assigns it when
// buildEnvRestoration reports HasData) renders cleanly. Before the fix, the
// campaign-run-breakdown and leaked-steps blocks sat outside the
// `{{if .envRestoration}}` guard and dereferenced a nil `.envRestoration` via
// `.envRestoration.runCount` / `.envRestoration.stepsLeaked`, aborting the
// render regardless of the run/gt argument coercion.
func TestGenerateHTML_EnvRestorationNil(t *testing.T) {
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	rep := robustnessReport(now)
	rep.EnvRestoration = nil
	var buf bytes.Buffer
	if err := GenerateHTML(&buf, rep, nil); err != nil {
		t.Fatalf("GenerateHTML errored after %d bytes: %v", buf.Len(), err)
	}
	if strings.Contains(buf.String(), "Campaign Run Breakdown") {
		t.Error("Campaign Run Breakdown should not render when envRestoration is nil")
	}
}

// TestGenerateHTML_EnvRestorationRunLevel_ZeroCampaignFields regression-tests
// the common single-run shape: EnvRestoration is non-nil (HasData true) but
// RunCount/RunsClean/RunsWithIssues are the campaign-only fields, left at
// their zero value and dropped by omitempty (engine.go). Before the fix,
// `{{if gt .envRestoration.runCount 1.0}}` compared a missing key (nil) with
// the builtin `gt`, which errors on a nil operand.
func TestGenerateHTML_EnvRestorationRunLevel_ZeroCampaignFields(t *testing.T) {
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	rep := robustnessReport(now)
	rep.EnvRestoration = &EnvRestoration{
		HasData: true, StepsTotal: 1, StepsWithCleanup: 1, StepsCleaned: 1,
		CleanupRate: 100, CoverageRate: 100, ImpactLevel: "clean",
		ImpactLabel: "Clean", StatusLabel: "Successful", ExecSummary: "All steps reverted.",
		// RunCount / RunsClean / RunsWithIssues intentionally left at zero
		// (omitempty) — the real shape for a single-run report.
	}
	var buf bytes.Buffer
	if err := GenerateHTML(&buf, rep, nil); err != nil {
		t.Fatalf("GenerateHTML errored after %d bytes: %v", buf.Len(), err)
	}
	if strings.Contains(buf.String(), "Campaign Run Breakdown") {
		t.Error("Campaign Run Breakdown should not render for a single-run report (runCount <= 1)")
	}
}

// TestGenerateHTML_EnvRestorationCampaign_RunBreakdownRenders is the positive
// counterpart to the two tests above: a real campaign-level EnvRestoration
// (RunCount > 1, StepsLeaked > 0) must render both the Campaign Run
// Breakdown block and the "Steps Requiring Manual Remediation" table,
// proving the nil/zero-value guards didn't also suppress the legitimate
// case. StepsLeaked > 0 also regression-tests the table's row rendering: it
// used to reference `.verdict`, a key TechniqueRow never populates (only
// `execVerdict` exists — see engine.go), so the table errored whenever
// reached. html.go now reads `.execVerdict` there instead.
func TestGenerateHTML_EnvRestorationCampaign_RunBreakdownRenders(t *testing.T) {
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	rep := robustnessReport(now)
	rep.TechniqueMatrix = []TechniqueRow{
		{TechniqueID: "T1003.001", TechniqueName: "LSASS Memory", Tactic: "credential-access",
			Severity: "High", ExecVerdict: "fail", CleanupVerdict: "leaked"},
	}
	rep.EnvRestoration = &EnvRestoration{
		HasData: true, StepsTotal: 3, StepsWithCleanup: 3, StepsCleaned: 2, StepsLeaked: 1,
		CleanupRate: 66.7, CoverageRate: 100, ImpactLevel: "minor",
		ImpactLabel: "Minor", StatusLabel: "Attention Required", ExecSummary: "One step left an artifact.",
		RunCount: 3, RunsClean: 2, RunsWithIssues: 1,
	}
	var buf bytes.Buffer
	if err := GenerateHTML(&buf, rep, nil); err != nil {
		t.Fatalf("GenerateHTML errored after %d bytes: %v", buf.Len(), err)
	}
	out := buf.String()
	for _, want := range []string{
		"Campaign Run Breakdown", "Residual Changes",
		"Steps Requiring Manual Remediation", "T1003.001", "FAIL", "LEAKED",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered report missing %q", want)
		}
	}
}

// TestGenerateHTML_GlossaryDataSourcesAndMitigations regression-tests
// html.go's `join` template func against GlossaryEntry.DataSources/
// Mitigations ([]string, engine.go). GenerateHTML renders from a
// json-round-tripped map[string]any (garble-safe render path — see
// GenerateHTML's doc comment), so a populated []string arrives at the
// template as []interface{}, not []string. `join` was typed
// `func([]string) string`, so the template engine rejected the argument
// outright before the fix.
func TestGenerateHTML_GlossaryDataSourcesAndMitigations(t *testing.T) {
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	rep := robustnessReport(now)
	rep.Glossary = []GlossaryEntry{
		{
			TechniqueID: "T1059.001", Name: "PowerShell", Tactic: "execution",
			Description: "Adversaries may abuse PowerShell.",
			DataSources: []string{"Process monitoring", "Command-line logging"},
			Mitigations: []string{"Disable or restrict PowerShell (M1042)"},
		},
	}
	var buf bytes.Buffer
	if err := GenerateHTML(&buf, rep, nil); err != nil {
		t.Fatalf("GenerateHTML errored after %d bytes: %v", buf.Len(), err)
	}
	out := buf.String()
	if !strings.Contains(out, "Process monitoring, Command-line logging") {
		t.Errorf("expected joined data sources in output")
	}
	if !strings.Contains(out, "Disable or restrict PowerShell (M1042)") {
		t.Errorf("expected joined mitigations in output")
	}
}

// TestGenerateHTML_ScreenMediaResetsPageMinHeight regression-tests the
// on-screen counterpart of the 2026-08-20 print/PDF blank-page fix. The base
// `.page`/`.inner` rules force min-height:297mm (a full A4 page) so a short
// Section (e.g. an ATT&CK Tactic Breakdown table for a 2-tactic run) renders
// as a full physical page with a large blank void below its actual content.
// @media print already resets this to min-height:0 (the 2026-08-20 fix), but
// that reset never applied to on-screen viewing (@media screen only adds
// box-shadow/border-radius) -- so the same class of bug is still live for
// anyone opening the HTML report in a browser rather than printing/exporting
// it. This test asserts the @media screen block carries the same min-height
// reset the @media print block already has.
func TestGenerateHTML_ScreenMediaResetsPageMinHeight(t *testing.T) {
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	rep := robustnessReport(now)
	var buf bytes.Buffer
	if err := GenerateHTML(&buf, rep, nil); err != nil {
		t.Fatalf("GenerateHTML errored after %d bytes: %v", buf.Len(), err)
	}
	out := buf.String()
	screenStart := strings.Index(out, "@media screen{")
	screenEnd := strings.Index(out, "@media print{")
	if screenStart == -1 || screenEnd == -1 || screenEnd < screenStart {
		t.Fatalf("could not locate @media screen{...}@media print{ block in rendered CSS")
	}
	screenBlock := out[screenStart:screenEnd]
	if !strings.Contains(screenBlock, ".page,.page .inner{min-height:0}") {
		t.Errorf("expected @media screen to reset .page/.inner min-height like @media print does, got block:\n%s", screenBlock)
	}
}

// TestReportTemplate_NoDarkThemeColours guards against dark-theme markup
// surviving in what is a light report (body{background:#fff;color:#1a2332}).
//
// Found 2026-09-03 by measuring a real rendered PDF: the Privilege Assessment
// panel carried background:rgba(13,17,23,0.5) with color:#fff on its headline
// number, so it rendered as a grey box with near-invisible white text. A
// per-step privilege callout used a solid background:#0d1117, and four
// attack-flow cards used a #30363d border. All are GitHub dark-palette values
// left over from an earlier dark report design.
//
// NOT a print/PDF bug: the same inline styles apply on screen, so the panel was
// equally broken in the browser.
//
// This asserts against the TEMPLATE SOURCE rather than rendered output, and
// deliberately so. The first version of this test rendered robustnessReport()
// and searched the HTML -- but that fixture populates neither privilegeSummary
// nor attackFlow, so every affected block sat inside an untaken {{if}} and the
// test passed against the unfixed template. Checking the source covers every
// conditional branch regardless of what a fixture happens to exercise.
//
// Banning dark BACKGROUNDS is what makes the light-text case unreachable too:
// color:#fff is legitimate on the cover, which really does have a dark navy
// band (.cover{background:#0b1420}), so it is not banned directly -- without a
// dark box to sit on, white text cannot go invisible.
func TestReportTemplate_NoDarkThemeColours(t *testing.T) {
	banned := map[string]string{
		"rgba(13,17,23": "dark panel background — use var(--surface)",
		"#0d1117":       "dark panel background — use var(--surface)",
		"#c9d1d9":       "dark-theme body text — use var(--ink)",
		"#30363d":       "dark-theme border — use var(--line)",
		"#21262d":       "dark-theme border — use var(--line)",
	}
	for colour, guidance := range banned {
		if strings.Contains(reportHTML, colour) {
			t.Errorf("dark-theme colour %s present in the light report template: %s", colour, guidance)
		}
	}
}
