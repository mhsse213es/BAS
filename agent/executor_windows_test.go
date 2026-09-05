//go:build windows

package main

import (
	"strings"
	"testing"
)

// TestRunCleanup_CapturesFailureDetail proves a failing cleanup command's own
// stderr/exit code is captured and reported, not silently discarded. Before
// this, runCleanup returned a bare "partial"/"leaked" verdict with no way to
// tell why -- found via a real production report showing a leaked temp file
// with zero diagnostic trail anywhere in scenario_runs.results.
func TestRunCleanup_CapturesFailureDetail(t *testing.T) {
	const marker = "definitely-does-not-exist-xyz123"
	step := ScenarioStep{
		Cleanup: "Remove-Item -Path 'C:\\" + marker + "' -ErrorAction Stop",
	}
	verdict, detail := runCleanup(step)
	if verdict != "partial" {
		t.Fatalf("verdict = %q, want %q", verdict, "partial")
	}
	if detail == "" {
		t.Fatal("detail = \"\", want the cleanup command's own stderr/exit code captured")
	}
	if !strings.Contains(detail, marker) {
		t.Errorf("detail = %q, want it to contain the failing command's own error text (marker %q)", detail, marker)
	}
}

// TestRunCleanup_SuccessReportsNoDetail confirms a successful cleanup still
// returns an empty detail string -- detail is only meaningful evidence for a
// failure, never noise on the common path.
func TestRunCleanup_SuccessReportsNoDetail(t *testing.T) {
	step := ScenarioStep{Cleanup: "exit 0"}
	verdict, detail := runCleanup(step)
	if verdict != "reverted" {
		t.Fatalf("verdict = %q, want %q", verdict, "reverted")
	}
	if detail != "" {
		t.Errorf("detail = %q, want empty on success", detail)
	}
}
