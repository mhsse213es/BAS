package reporting

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
)

func appCtlResult(stepName, technique, output string) models.SimulationResult {
	return models.SimulationResult{
		StepName:  stepName,
		Technique: models.AttackTechnique{ID: technique},
		RawOutput: output,
	}
}

const appCtlIndirectOut = "APPCTL_FAMILY: indirect_execution\nAPPCTL_COVERAGE: Exe=Enabled\nAPPCTL_DETECTION: source=sysmon_process_create result=visible\nAPPCTL_OUTCOME: blocked_as_expected\nPASS: blocked. [BAS-SIM]\n"

// Evidence is scoped to the run it was passed for. The section carries the
// run ID, and rows come only from the results handed to it.
func TestBuildAppControlSection_MapsEvidenceToItsRun(t *testing.T) {
	results := []models.SimulationResult{
		appCtlResult("Application control indirect execution via cmd.exe parent (T1202)", "T1202", appCtlIndirectOut),
	}
	sec := buildAppControlSection("run-A", results)
	if !sec.HasData {
		t.Fatal("run with an appcontrol step must have data")
	}
	if sec.RunID != "run-A" {
		t.Errorf("RunID = %q, want run-A", sec.RunID)
	}
	if len(sec.Rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(sec.Rows))
	}
	r := sec.Rows[0]
	if r.Family != "indirect_execution" || r.Technique != "T1202" || r.Outcome != "blocked_as_expected" || r.Visibility != "visible" {
		t.Errorf("row = %+v", r)
	}
}

// A run with no appcontrol steps must not show the section at all, so
// existing reports are unchanged.
func TestBuildAppControlSection_HiddenWhenNoAppControlSteps(t *testing.T) {
	results := []models.SimulationResult{
		appCtlResult("Credential dumping", "T1003", "PASS: nothing relevant"),
	}
	if sec := buildAppControlSection("run-A", results); sec.HasData {
		t.Errorf("HasData = true for a run with no appcontrol steps: %+v", sec)
	}
}

// A step that ran but produced no structured outcome is unverified, never a
// pass and never silently dropped.
func TestBuildAppControlSection_MissingOutcomeIsUnverified(t *testing.T) {
	results := []models.SimulationResult{
		appCtlResult("Application control script host proxy: cscript runs a benign .vbs (T1059.005)", "T1059.005", "cscript: error 0x80070005"),
	}
	sec := buildAppControlSection("run-A", results)
	st := familyStatus(t, sec, "script_host_proxy")
	if st.Status != "unverified" {
		t.Errorf("status = %q, want unverified", st.Status)
	}
	if len(sec.Rows) != 0 {
		t.Errorf("a step with no outcome must not produce a row, got %d", len(sec.Rows))
	}
}

// Every family appears in the report, in a fixed order, so a family that was
// not exercised is stated as not run rather than omitted.
func TestBuildAppControlSection_AllFamiliesListedInOrder(t *testing.T) {
	results := []models.SimulationResult{
		appCtlResult("Application control indirect execution", "T1202", appCtlIndirectOut),
	}
	sec := buildAppControlSection("run-A", results)
	want := []string{"indirect_execution", "alternate_binary", "script_host_proxy", "alternate_ps_host", "parent_child_asr"}
	if len(sec.Families) != len(want) {
		t.Fatalf("families = %d, want %d", len(sec.Families), len(want))
	}
	for i, f := range want {
		if sec.Families[i].Family != f {
			t.Errorf("family[%d] = %s, want %s", i, sec.Families[i].Family, f)
		}
	}
	if familyStatus(t, sec, "alternate_binary").Status != "not_run" {
		t.Errorf("an unexercised family must read not_run")
	}
	if familyStatus(t, sec, "indirect_execution").Status != "blocked_as_expected" {
		t.Errorf("exercised family must carry its outcome")
	}
}

// Prevention and telemetry stay independent: an allowed path can be visible,
// and a blocked path can be unseen. Neither is inferred from the other.
func TestBuildAppControlSection_PreventionAndVisibilityIndependent(t *testing.T) {
	allowedVisible := "APPCTL_FAMILY: alternate_binary\nAPPCTL_DETECTION: source=sysmon_process_create result=visible\nAPPCTL_OUTCOME: allowed_unexpectedly\n"
	blockedUnseen := "APPCTL_FAMILY: parent_child_asr\nAPPCTL_DETECTION: source=sysmon_process_create result=not_visible\nAPPCTL_OUTCOME: blocked_as_expected\n"
	results := []models.SimulationResult{
		appCtlResult("Application control alternate binary: renamed powershell.exe copy (T1036)", "T1036", allowedVisible),
		appCtlResult("Application control parent-child ASR: spoofed Office parent (T1204.002)", "T1204.002", blockedUnseen),
	}
	sec := buildAppControlSection("run-A", results)
	got := map[string][2]string{}
	for _, r := range sec.Rows {
		got[r.Family] = [2]string{r.Outcome, r.Visibility}
	}
	if got["alternate_binary"] != [2]string{"allowed_unexpectedly", "visible"} {
		t.Errorf("alternate_binary = %v", got["alternate_binary"])
	}
	if got["parent_child_asr"] != [2]string{"blocked_as_expected", "not_visible"} {
		t.Errorf("parent_child_asr = %v", got["parent_child_asr"])
	}
}

// A family that produced conflicting outcomes in one run is inconclusive, not
// whichever row happened to come first.
func TestBuildAppControlSection_ConflictingOutcomesAreInconclusive(t *testing.T) {
	a := "APPCTL_FAMILY: alternate_binary\nAPPCTL_DETECTION: source=sysmon_process_create result=visible\nAPPCTL_OUTCOME: blocked_as_expected\n"
	b := "APPCTL_FAMILY: alternate_binary\nAPPCTL_DETECTION: source=sysmon_process_create result=visible\nAPPCTL_OUTCOME: allowed_unexpectedly\n"
	sec := buildAppControlSection("run-A", []models.SimulationResult{
		appCtlResult("Application control alternate binary A", "T1036", a),
		appCtlResult("Application control alternate binary B", "T1036", b),
	})
	if st := familyStatus(t, sec, "alternate_binary").Status; st != "inconclusive" {
		t.Errorf("status = %q, want inconclusive", st)
	}
}

// The rendered report carries the section, the family coverage, and the
// limitations, and states that fixture tests are not enforcement evidence.
func TestGenerateHTML_AppControlSectionRendered(t *testing.T) {
	results := []models.SimulationResult{
		appCtlResult("Application control indirect execution via cmd.exe parent (T1202)", "T1202", appCtlIndirectOut),
	}
	rep := &FullReport{GeneratedAt: time.Now().UTC(), AppControl: buildAppControlSection("run-A", results)}
	var buf bytes.Buffer
	if err := GenerateHTML(&buf, rep, nil); err != nil {
		t.Fatalf("GenerateHTML: %v", err)
	}
	html := buf.String()
	for _, want := range []string{
		"Application Control Efficacy",
		"indirect_execution",
		"blocked_as_expected",
		"alternate_binary",
		"not_run",
		"Live AppLocker and ASR enforcement",
		"Fixture tests",
		"not evidence of enforcement",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("report HTML missing %q", want)
		}
	}
}

func TestGenerateHTML_AppControlSectionHiddenWithoutData(t *testing.T) {
	rep := &FullReport{GeneratedAt: time.Now().UTC()}
	var buf bytes.Buffer
	if err := GenerateHTML(&buf, rep, nil); err != nil {
		t.Fatalf("GenerateHTML: %v", err)
	}
	if strings.Contains(buf.String(), "Application Control Efficacy") {
		t.Error("section must not render for a run with no appcontrol steps")
	}
}

func familyStatus(t *testing.T, sec AppControlSection, family string) AppControlFamilyStatus {
	t.Helper()
	for _, f := range sec.Families {
		if f.Family == family {
			return f
		}
	}
	t.Fatalf("family %s not listed", family)
	return AppControlFamilyStatus{}
}
