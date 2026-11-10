package reporting

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// The agent's verify stage reports "restore incomplete: ..." when, after the restore, Windows still opens something
// differently or a recorded change could not be put back. A report must never call such a run clean, however the
// steps' own cleanup went.

func TestBuildEnvRestoration_RestoreIncompleteIsListedAndNeverReportedAsClean(t *testing.T) {
	matrix := []TechniqueRow{{TechniqueID: "T1548.002", CleanupVerdict: "reverted"}}
	reverted := []string{
		"registry value restored: HKCU\\Software\\Classes\\Folder",
		`restore incomplete: health: ".cpl" now opens with "explorer.exe" (was "rundll32.exe shell32.dll,Control_RunDLL \"%1\",%*")`,
	}
	e := buildEnvRestoration(matrix, reverted)

	if len(e.RestoreIssues) != 1 || !strings.Contains(e.RestoreIssues[0], `".cpl" now opens with`) {
		t.Fatalf("the incomplete restore must be listed without its machine prefix, got %v", e.RestoreIssues)
	}
	if strings.HasPrefix(e.RestoreIssues[0], "restore incomplete:") {
		t.Errorf("the issue text should not repeat the prefix: %q", e.RestoreIssues[0])
	}
	if e.ImpactLevel == "clean" || e.StatusLabel == "Successful" {
		t.Errorf("a run with an incomplete restore was reported clean: %q / %q", e.ImpactLevel, e.StatusLabel)
	}
	if !strings.Contains(e.ExecSummary, "1 ") || !strings.Contains(strings.ToLower(e.ExecSummary), "not fully restored") {
		t.Errorf("the summary must say the endpoint was not fully restored, got %q", e.ExecSummary)
	}
}

func TestBuildEnvRestoration_ManyRestoreIssuesAreReportedAsFailed(t *testing.T) {
	matrix := []TechniqueRow{{TechniqueID: "T1548.002", CleanupVerdict: "reverted"}}
	var reverted []string
	for i := 0; i < 4; i++ {
		reverted = append(reverted, "restore incomplete: health: x")
	}
	e := buildEnvRestoration(matrix, reverted)
	if e.StatusLabel != "Failed" || e.ImpactLevel != "persistent" {
		t.Errorf("four unrestored items is a failure, got %q / %q", e.StatusLabel, e.ImpactLevel)
	}
}

func TestBuildEnvRestoration_NoIncompleteLinesChangesNothing(t *testing.T) {
	matrix := []TechniqueRow{{TechniqueID: "T1059.001", CleanupVerdict: "reverted"}}
	e := buildEnvRestoration(matrix, []string{"service removed: x", "stray process stopped: calc.exe (pid 4)"})
	if len(e.RestoreIssues) != 0 || e.ImpactLevel != "clean" || e.StatusLabel != "Successful" {
		t.Errorf("a clean run must stay clean: %+v", e)
	}
}

func TestBuildEnvRestoration_ARunWithOnlyIncompleteRestoresStillHasData(t *testing.T) {
	// no steps ran a cleanup of their own, but the agent could not restore something: that must still be shown
	e := buildEnvRestoration(nil, []string{"restore incomplete: service could not be deleted: x"})
	if !e.HasData || len(e.RestoreIssues) != 1 {
		t.Errorf("a failed restore must be reported even with no steps: %+v", e)
	}
}

func TestGenerateHTML_RestoreIssuesAreShownProminentlyAndOnlyWhenPresent(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	rep := robustnessReport(now)
	rep.EnvRestoration = &EnvRestoration{
		HasData: true, StepsTotal: 1, StepsWithCleanup: 1, StepsCleaned: 1, CleanupRate: 100, CoverageRate: 100,
		ImpactLevel: "minor", ImpactLabel: "Endpoint Not Fully Restored (1)", StatusLabel: "Attention Required",
		ExecSummary:   "x",
		RestoreIssues: []string{`health: ".cpl" now opens with "explorer.exe" <b>x</b>`},
	}
	var buf bytes.Buffer
	if err := GenerateHTML(&buf, rep, nil); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Not fully restored") || !strings.Contains(out, `&#34;.cpl&#34; now opens with`) {
		t.Error("the report must list what the agent could not restore")
	}
	if strings.Contains(out, "<b>x</b>") {
		t.Error("issue text must be escaped, it comes from the endpoint")
	}

	rep.EnvRestoration.RestoreIssues = nil
	rep.EnvRestoration.ImpactLevel, rep.EnvRestoration.StatusLabel = "clean", "Successful"
	buf.Reset()
	if err := GenerateHTML(&buf, rep, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "Not fully restored") {
		t.Error("the block must not appear when nothing is wrong")
	}
}
