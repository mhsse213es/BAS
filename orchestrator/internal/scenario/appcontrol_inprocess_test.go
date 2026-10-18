package scenario

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// inprocessFixture is one controlled observation for the inprocess_hosting
// family. policy is the customer's stated intent (BAS_INPROC_POLICY): restricted,
// unrestricted, or empty when not stated. The custom host's output is supplied
// directly, with MARKER standing for the marker the step generated. Nothing is
// launched.
type inprocessFixture struct {
	name        string
	helper      bool   // helper configured and present
	policy      string // BAS_INPROC_POLICY: restricted, unrestricted, or "" (not stated)
	output      string // what the custom host printed
	wantOutcome string
	wantPrefix  string
}

const inprocessStep = "Application control in-process PowerShell host"

var inprocessFixtures = []inprocessFixture{
	{"no custom host configured", false, "restricted", "", "not_applicable", "SKIP:"},

	// Policy: restricted. The host must be restricted.
	{"restricted policy: constrained host blocks Add-Type", true, "restricted",
		"HOST_LANGUAGE_MODE: ConstrainedLanguage\nHOST_ADDTYPE: blocked\nMARKER\n",
		"blocked_as_expected", "PASS:"},
	{"restricted policy: full-language host allows Add-Type", true, "restricted",
		"HOST_LANGUAGE_MODE: FullLanguage\nHOST_ADDTYPE: allowed\nMARKER\n",
		"allowed_unexpectedly", "FAIL:"},
	{"restricted policy: constrained host still allows Add-Type", true, "restricted",
		"HOST_LANGUAGE_MODE: ConstrainedLanguage\nHOST_ADDTYPE: allowed\nMARKER\n",
		"allowed_unexpectedly", "FAIL:"},
	{"restricted policy: Add-Type blocked under full language, not by language mode", true, "restricted",
		"HOST_LANGUAGE_MODE: FullLanguage\nHOST_ADDTYPE: blocked\nMARKER\n",
		"inconclusive", "SKIP:"},

	// Policy: unrestricted. FullLanguage is permitted; the exposure is documented.
	{"unrestricted policy: full-language host allows Add-Type", true, "unrestricted",
		"HOST_LANGUAGE_MODE: FullLanguage\nHOST_ADDTYPE: allowed\nMARKER\n",
		"allowed_by_policy", "PASS:"},
	{"unrestricted policy: host blocks Add-Type (stricter than policy)", true, "unrestricted",
		"HOST_LANGUAGE_MODE: ConstrainedLanguage\nHOST_ADDTYPE: blocked\nMARKER\n",
		"inconclusive", "SKIP:"},

	// Policy not stated: UNVERIFIED, never a FAIL.
	{"policy not stated: full-language host allows Add-Type is UNVERIFIED", true, "",
		"HOST_LANGUAGE_MODE: FullLanguage\nHOST_ADDTYPE: allowed\nMARKER\n",
		"inconclusive", "SKIP:"},
	{"policy not stated: constrained host blocks Add-Type is UNVERIFIED", true, "",
		"HOST_LANGUAGE_MODE: ConstrainedLanguage\nHOST_ADDTYPE: blocked\nMARKER\n",
		"inconclusive", "SKIP:"},

	// Unusable host output, whatever the policy.
	{"host ran but reported no marker", true, "restricted",
		"HOST_LANGUAGE_MODE: ConstrainedLanguage\nHOST_ADDTYPE: blocked\n",
		"inconclusive", "SKIP:"},
	{"host printed no structured result", true, "restricted",
		"HOST_ERROR: SecurityException\nMARKER\n",
		"inconclusive", "SKIP:"},
}

func inprocessPrelude(fx inprocessFixture) string {
	present := "$false"
	if fx.helper {
		present = "$true"
	}
	var b strings.Builder
	b.WriteString("$env:BAS_INPROC_HOST = 'C:\\bas\\bas-pshost.exe'\n")
	b.WriteString("$env:BAS_INPROC_POLICY = '" + fx.policy + "'\n")
	b.WriteString("$global:BasHelperPresent = " + present + "\n")
	b.WriteString("$global:BasHostOut = '" + strings.ReplaceAll(fx.output, "'", "''") + "'\n")
	b.WriteString(`function Test-Path { [CmdletBinding()] param($LiteralPath) $global:BasHelperPresent }
function Start-Process { [CmdletBinding()] param($FilePath, $ArgumentList, $WindowStyle, [switch]$PassThru, [switch]$Wait, $RedirectStandardOutput)
  $global:BasCaptured = [string]$ArgumentList
  [pscustomobject]@{ ExitCode = 0 }
}
function Get-Content { [CmdletBinding()] param($Path) $global:BasHostOut.Replace('MARKER', $global:BasCaptured) }
`)
	return b.String()
}

// TestInProcessHosting_OutcomeFromHostOutput drives the shipped step through
// each policy and host output. It checks the structured outcome, the verdict
// prefix, that the verdict depends on the stated policy, and that telemetry
// visibility is reported as unknown.
func TestInProcessHosting_OutcomeFromHostOutput(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("behavioral step is Windows PowerShell")
	}
	path := filepath.Join("..", "..", "..", "scenarios", "appcontrol-efficacy.yaml")
	for _, fx := range inprocessFixtures {
		t.Run(fx.name, func(t *testing.T) {
			command := loadStepCommand(t, path, inprocessStep)
			out := runPosturePowerShell(t, inprocessPrelude(fx)+"\n"+command)
			if !strings.Contains(out, "APPCTL_FAMILY: inprocess_hosting") {
				t.Errorf("missing APPCTL_FAMILY: inprocess_hosting\n%s", out)
			}
			if !strings.Contains(out, "APPCTL_OUTCOME: "+fx.wantOutcome) {
				t.Errorf("want APPCTL_OUTCOME: %s\n%s", fx.wantOutcome, out)
			}
			if !strings.Contains(out, fx.wantPrefix) {
				t.Errorf("want verdict prefix %s\n%s", fx.wantPrefix, out)
			}
			// No ScriptBlock logging is enabled in these fixtures, so visibility
			// is unknown, never not_visible. See the visibility tests.
			if !strings.Contains(out, "APPCTL_DETECTION: source=powershell_scriptblock_4104 result=unknown") {
				t.Errorf("visibility must be unknown when ScriptBlock logging is not enabled\n%s", out)
			}
			if fx.policy == "" && fx.helper && !strings.Contains(out, "UNVERIFIED") {
				t.Errorf("an unstated policy must be reported as UNVERIFIED\n%s", out)
			}
			if fx.wantPrefix != "PASS:" && strings.Contains(out, "PASS:") {
				t.Errorf("non-pass fixture emitted PASS:\n%s", out)
			}
		})
	}
}

// TestInProcessHosting_RealHostBinary runs the shipped step against a real
// bas-pshost.exe. It is skipped unless BAS_INPROC_HOST points at a built
// binary, so the default suite does not depend on a compiler or a build.
// The policy comes from BAS_INPROC_POLICY, which may be unset.
func TestInProcessHosting_RealHostBinary(t *testing.T) {
	helper := os.Getenv("BAS_INPROC_HOST")
	if helper == "" || runtime.GOOS != "windows" {
		t.Skip("set BAS_INPROC_HOST to a built bas-pshost.exe to run this")
	}
	path := filepath.Join("..", "..", "..", "scenarios", "appcontrol-efficacy.yaml")
	command := loadStepCommand(t, path, inprocessStep)
	setup := "$env:BAS_INPROC_HOST = '" + strings.ReplaceAll(helper, "'", "''") + "'\n"
	if p := os.Getenv("BAS_INPROC_POLICY"); p != "" {
		setup += "$env:BAS_INPROC_POLICY = '" + strings.ReplaceAll(p, "'", "''") + "'\n"
	}
	out := runPosturePowerShell(t, setup+command)
	if !strings.Contains(out, "APPCTL_OUTCOME:") {
		t.Fatalf("real host run produced no structured outcome\n%s", out)
	}
	t.Logf("real host result:\n%s", out)
}
