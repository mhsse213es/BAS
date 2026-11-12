package variant

import "testing"

func TestCleanupEligible(t *testing.T) {
	cases := []struct {
		name    string
		cleanup string
		status  string
		want    bool
	}{
		{"verified with a cleanup command", "rm x", CleanupVerified, true},
		{"verified but the command is blank", "  ", CleanupVerified, false},
		{"read-only needs no cleanup", "", CleanupReadOnly, true},
		{"unverified is never eligible", "rm x", CleanupUnverified, false},
		{"no status recorded fails closed", "rm x", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := CleanupEligible(c.cleanup, c.status); got != c.want {
				t.Errorf("CleanupEligible(%q,%q) = %v, want %v", c.cleanup, c.status, got, c.want)
			}
		})
	}
}

// Every variant built from a payload family carries that family's explicit cleanup, never a borrowed one.
func TestGenerateFromFamilies_CarriesEachFamiliesCleanup(t *testing.T) {
	families := []PayloadFamily{
		{Name: "Recon", Payload: "whoami", CleanupStatus: CleanupReadOnly},
		{Name: "Stager", Payload: "iwr http://127.0.0.1/x", Cleanup: "Remove-Item x", CleanupStatus: CleanupVerified},
	}
	templates := GenerateFromFamilies("T1059.001", "art", families, false)
	if len(templates) == 0 {
		t.Fatal("no templates generated")
	}
	seen := map[string]bool{}
	for _, tpl := range templates {
		seen[tpl.BaseID] = true
		if tpl.ExecContext == CtxSchedTask {
			// A scheduled-task variant creates a task, so it is never read-only; it is covered by its own test.
			if tpl.CleanupStatus != CleanupUnverified {
				t.Errorf("%s schtasks variant status = %q, want unverified", tpl.BaseID, tpl.CleanupStatus)
			}
			continue
		}
		switch tpl.BaseID {
		case "Recon":
			if tpl.CleanupStatus != CleanupReadOnly || tpl.Cleanup != "" {
				t.Errorf("Recon: status=%q cleanup=%q", tpl.CleanupStatus, tpl.Cleanup)
			}
		case "Stager":
			if tpl.CleanupStatus != CleanupVerified || tpl.Cleanup != "Remove-Item x" {
				t.Errorf("Stager: status=%q cleanup=%q", tpl.CleanupStatus, tpl.Cleanup)
			}
		}
	}
	if !seen["Recon"] || !seen["Stager"] {
		t.Errorf("families seen = %v", seen)
	}
}
