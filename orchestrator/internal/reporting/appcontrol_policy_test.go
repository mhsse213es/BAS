package reporting

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
)

const inprocOutRestricted = "APPCTL_FAMILY: inprocess_hosting\nAPPCTL_COVERAGE: HostLanguageMode=ConstrainedLanguage\nAPPCTL_EVIDENCE: test_id=t1 policy=restricted expected=blocked ran=True exit=0 host_addtype=blocked capture=x\nAPPCTL_DETECTION: source=none result=unknown\nAPPCTL_OUTCOME: blocked_as_expected\nPASS: blocked. [BAS-SIM]\n"

const inprocOutNotStated = "APPCTL_FAMILY: inprocess_hosting\nAPPCTL_COVERAGE: HostLanguageMode=FullLanguage\nAPPCTL_EVIDENCE: test_id=t2 policy= expected=unknown ran=True exit=0 host_addtype=allowed capture=x\nAPPCTL_DETECTION: source=none result=unknown\nAPPCTL_OUTCOME: inconclusive\nSKIP: UNVERIFIED. [BAS-SIM]\n"

// The observed state and the intended policy are shown with the verdict, so a
// reader can see what was measured and what it was judged against.
func TestBuildAppControlSection_InProcessShowsObservedAndPolicy(t *testing.T) {
	sec := buildAppControlSection("run-p", []models.SimulationResult{
		appCtlResult("Application control in-process PowerShell host: language mode (T1059.001)", "T1059.001", inprocOutRestricted),
	})
	if len(sec.Rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(sec.Rows))
	}
	r := sec.Rows[0]
	if r.Observed != "HostLanguageMode=ConstrainedLanguage; Add-Type blocked" {
		t.Errorf("Observed = %q", r.Observed)
	}
	if r.Policy != "restricted" {
		t.Errorf("Policy = %q, want restricted", r.Policy)
	}
	if r.Outcome != "blocked_as_expected" {
		t.Errorf("Outcome = %q", r.Outcome)
	}
}

// An unstated policy is shown as not stated, never as a default.
func TestBuildAppControlSection_UnstatedPolicyIsShownNotDefaulted(t *testing.T) {
	sec := buildAppControlSection("run-q", []models.SimulationResult{
		appCtlResult("Application control in-process PowerShell host: language mode (T1059.001)", "T1059.001", inprocOutNotStated),
	})
	r := sec.Rows[0]
	if r.Policy != "not stated" {
		t.Errorf("Policy = %q, want \"not stated\"", r.Policy)
	}
	if r.Outcome != "inconclusive" {
		t.Errorf("Outcome = %q, want inconclusive", r.Outcome)
	}
}

// Families without a policy input show no policy, not a blank that looks stated.
func TestBuildAppControlSection_OtherFamiliesHaveNoPolicy(t *testing.T) {
	sec := buildAppControlSection("run-r", []models.SimulationResult{
		appCtlResult("Application control indirect execution via cmd.exe parent (T1202)", "T1202", appCtlIndirectOut),
	})
	if sec.Rows[0].Policy != "" {
		t.Errorf("Policy = %q, want empty for a family with no policy input", sec.Rows[0].Policy)
	}
	if sec.Rows[0].Observed != "Exe=Enabled" {
		t.Errorf("Observed = %q, want the controlling collection mode", sec.Rows[0].Observed)
	}
}

// The rendered report carries the observed state, the intended policy, and the
// AMSI limitation.
func TestGenerateHTML_InProcessEvidenceAndAMSILimitRendered(t *testing.T) {
	sec := buildAppControlSection("run-h", []models.SimulationResult{
		appCtlResult("Application control in-process PowerShell host: language mode (T1059.001)", "T1059.001", inprocOutNotStated),
	})
	rep := &FullReport{GeneratedAt: time.Now().UTC(), AppControl: sec}
	var buf bytes.Buffer
	if err := GenerateHTML(&buf, rep, nil); err != nil {
		t.Fatalf("GenerateHTML: %v", err)
	}
	html := buf.String()
	for _, want := range []string{"Observed state", "Intended policy", "HostLanguageMode=FullLanguage", "not stated", "AMSI or ScriptBlock logging"} {
		if !strings.Contains(html, want) {
			t.Errorf("report missing %q", want)
		}
	}
}
