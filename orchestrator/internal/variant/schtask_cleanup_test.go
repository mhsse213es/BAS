package variant

import (
	"strings"
	"testing"
)

// A schtasks variant creates a scheduled task, and the agent can kill it between create and delete. Its cleanup must
// name the same task the command creates, and it stays unverified until a lab run confirms it.
func TestSchedTaskVariant_CleanupNamesTheTaskItCreates(t *testing.T) {
	var found bool
	fams := []PayloadFamily{{Name: "Recon - Identity", Payload: "whoami /all", Executor: "powershell", CleanupStatus: CleanupReadOnly}}
	for _, tpl := range GenerateFromFamilies("T1059.001", "art", fams, false) {
		if tpl.ExecContext != CtxSchedTask {
			continue
		}
		found = true
		name := taskNameFrom(tpl.Command)
		if name == "" {
			t.Fatalf("command does not create a named task: %s", tpl.Command)
		}
		if !strings.Contains(tpl.Cleanup, name) {
			t.Errorf("cleanup %q does not check task %q", tpl.Cleanup, name)
		}
		if tpl.CleanupStatus != CleanupUnverified {
			t.Errorf("schtasks cleanup status = %q, want unverified until the lab run", tpl.CleanupStatus)
		}
	}
	if !found {
		t.Fatal("no schtasks variant generated")
	}
}

func TestWithCleanup_SchedTaskOverridesBaseCleanupAsUnverified(t *testing.T) {
	tpl := Template{TechniqueID: "T1", BaseID: "b", Encoding: "plain", ExecContext: CtxSchedTask, Executor: "cmd", Command: `schtasks.exe /create /tn "BAS-V-x"`}
	got := WithCleanup(tpl, "Remove-Item x", CleanupVerified)
	if got.CleanupStatus != CleanupUnverified {
		t.Errorf("status = %q, want unverified", got.CleanupStatus)
	}
	if strings.Contains(got.Cleanup, "Remove-Item") {
		t.Errorf("a PowerShell base cleanup must not run in a cmd variant: %q", got.Cleanup)
	}
}

func TestWithCleanup_OtherContextsKeepTheGivenCleanup(t *testing.T) {
	tpl := Template{ExecContext: CtxPowershellDirect}
	got := WithCleanup(tpl, "rm x", CleanupVerified)
	if got.Cleanup != "rm x" || got.CleanupStatus != CleanupVerified {
		t.Errorf("got cleanup=%q status=%q", got.Cleanup, got.CleanupStatus)
	}
}

// taskNameFrom pulls the quoted /tn value out of a schtasks create command.
func taskNameFrom(cmd string) string {
	i := strings.Index(cmd, `/tn "`)
	if i < 0 {
		return ""
	}
	rest := cmd[i+len(`/tn "`):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	return rest[:j]
}
