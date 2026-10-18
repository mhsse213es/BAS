package scenario

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// visibilityFixture controls the ScriptBlock log observation for the
// in-process host. The host output is a restricted result, so the outcome is
// fixed and the test isolates visibility.
type visibilityFixture struct {
	name           string
	sbEnabled      bool // EnableScriptBlockLogging = 1 by policy
	logReadable    bool
	eventSeen      bool // a 4104 event containing this run's marker exists
	wantVisibility string
}

var visibilityFixtures = []visibilityFixture{
	{"logging enabled, host script block recorded", true, true, true, "visible"},
	{"logging enabled, no script block recorded", true, true, false, "not_visible"},
	{"logging enabled, operational log unreadable", true, false, false, "unknown"},
	{"logging not enabled, record would exist", false, true, true, "unknown"},
	{"logging not enabled, no record", false, true, false, "unknown"},
}

func visibilityPrelude(fx visibilityFixture) string {
	b := func(v bool) string {
		if v {
			return "$true"
		}
		return "$false"
	}
	base := inprocessPrelude(inprocessFixture{
		helper: true, policy: "restricted",
		output: "HOST_LANGUAGE_MODE: ConstrainedLanguage\nHOST_ADDTYPE: blocked\nMARKER\n",
	})
	return base + "\n" +
		"$global:BasSbEnabled = " + b(fx.sbEnabled) + "\n" +
		"$global:BasLogOK = " + b(fx.logReadable) + "\n" +
		"$global:BasEventSeen = " + b(fx.eventSeen) + "\n" +
		`function Get-ItemProperty { [CmdletBinding()] param($Path, $Name)
  if ($global:BasSbEnabled) { [pscustomobject]@{ EnableScriptBlockLogging = 1 } }
}
function Get-WinEvent { [CmdletBinding()] param($FilterHashtable)
  if (-not $global:BasLogOK) { throw 'operational log unavailable' }
  if ($global:BasEventSeen) { [pscustomobject]@{ Message = "Script block: $global:BasCaptured" } }
}
`
}

// TestInProcessVisibility_ScriptBlockLogCorrelation checks that visibility is
// visible only when ScriptBlock logging is enabled and the run's marker is in
// event 4104. It is unknown whenever the record cannot be expected or read.
// It is never not_visible unless logging is on.
func TestInProcessVisibility_ScriptBlockLogCorrelation(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("behavioral step is Windows PowerShell")
	}
	path := filepath.Join("..", "..", "..", "scenarios", "appcontrol-efficacy.yaml")
	for _, fx := range visibilityFixtures {
		t.Run(fx.name, func(t *testing.T) {
			command := loadStepCommand(t, path, inprocessStep)
			out := runPosturePowerShell(t, visibilityPrelude(fx)+"\n"+command)
			want := "APPCTL_DETECTION: source=powershell_scriptblock_4104 result=" + fx.wantVisibility
			if !strings.Contains(out, want) {
				t.Errorf("want %s\n%s", want, out)
			}
			wantState := "scriptblock_logging=not_enabled"
			if fx.sbEnabled {
				wantState = "scriptblock_logging=enabled"
			}
			if !strings.Contains(out, wantState) {
				t.Errorf("evidence must record %s\n%s", wantState, out)
			}
			if !strings.Contains(out, "APPCTL_OUTCOME: blocked_as_expected") {
				t.Errorf("visibility fixtures must keep the blocked outcome\n%s", out)
			}
		})
	}
}
