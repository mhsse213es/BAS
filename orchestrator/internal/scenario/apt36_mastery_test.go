package scenario

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var apt36Scenarios = map[string]int{
	"apt36-kill-chain":            10,
	"apt36-initial-execution":     5,
	"apt36-discovery":             5,
	"apt36-collection-credential": 5,
	"apt36-persistence-evasion":   5,
	"apt36-command-control":       7,
}

func TestAPT36_LibraryDecisionTable(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("oracle is Windows PowerShell")
	}
	lib, err := os.ReadFile(filepath.Join("..", "..", "..", "scenarios-src", "apt36-common", "lib.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	table := `$cases = @(
 @('prevented: not run, one block event', $false, 1, $true, $true, $true, 'prevented'),
 @('absence alone is inconclusive', $false, 0, $true, $true, $true, 'inconclusive'),
 @('unreadable log is inconclusive', $false, 0, $false, $false, $true, 'inconclusive'),
 @('ran with a block event is a failure', $true, 1, $true, $true, $true, 'allowed_unexpectedly'),
 @('ran while enforcing is a failure', $true, 0, $true, $true, $true, 'allowed_unexpectedly'),
 @('ran, nothing enforcing', $true, 0, $true, $false, $true, 'not_enforced'),
 @('build below floor', $false, 1, $true, $true, $false, 'not_applicable')
)
foreach ($c in $cases) { $r = Resolve-A36Outcome -Ran $c[1] -Blocks $c[2] -Readable $c[3] -Enforcing $c[4] -BuildOk $c[5]; if ($r.Outcome -ne $c[6]) { "BAD $($c[0]) want=$($c[6]) got=$($r.Outcome)" } }
'TABLE_DONE'`
	out := runPosturePowerShell(t, string(lib)+"\n"+table)
	if !strings.Contains(out, "TABLE_DONE") || strings.Contains(out, "BAD ") {
		t.Fatalf("decision table failed:\n%s", out)
	}
}

type apt36Doc struct {
	ProductLine string `yaml:"product_line"`
	Steps       []struct {
		ID      string `yaml:"id"`
		Name    string `yaml:"name"`
		Tech    string `yaml:"technique_id"`
		Command string `yaml:"command"`
		Cleanup string `yaml:"cleanup"`
	} `yaml:"steps"`
}

func loadAPT36(t *testing.T, id string) apt36Doc {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "scenarios", id+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var d apt36Doc
	if err := yaml.Unmarshal(data, &d); err != nil {
		t.Fatalf("%s: %v", id, err)
	}
	return d
}

func TestAPT36_EveryStepWellFormed(t *testing.T) {
	for id, want := range apt36Scenarios {
		d := loadAPT36(t, id)
		if d.ProductLine != "killchain" {
			t.Errorf("%s: product_line = %q, want killchain", id, d.ProductLine)
		}
		if len(d.Steps) != want {
			t.Errorf("%s: %d steps, want %d", id, len(d.Steps), want)
		}
		seen := map[string]bool{}
		for _, s := range d.Steps {
			if seen[s.ID] {
				t.Errorf("%s: duplicate step id %s", id, s.ID)
			}
			seen[s.ID] = true
			for _, w := range []string{"Invoke-A36Test", "APT36_OUTCOME", "Resolve-A36Outcome"} {
				if !strings.Contains(s.Command, w) {
					t.Errorf("%s %s: command lacks %q", id, s.ID, w)
				}
			}
			if strings.TrimSpace(s.Cleanup) == "" {
				t.Errorf("%s %s: no cleanup", id, s.ID)
			}
			if s.Tech == "" {
				t.Errorf("%s %s: no technique", id, s.ID)
			}
			for _, r := range s.Command + s.Name {
				if r > 126 {
					t.Errorf("%s %s: non-ASCII character", id, s.ID)
					break
				}
			}
		}
	}
}

// Steps that touch a shared subsystem (WMI, the service control manager, or
// live Defender configuration) rather than only a run-tagged file or
// registry value must never run without the operator setting their gate.
func TestAPT36_GatedStepsSkipWithoutGate(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("behavioral steps are Windows PowerShell")
	}
	cases := []struct{ scen, id, gate string }{
		{"apt36-persistence-evasion", "apt36-pe1", "BAS_CONFIRM_APT36_WMI_SUBSCRIPTION"},
		{"apt36-persistence-evasion", "apt36-pe3", "BAS_CONFIRM_APT36_SERVICE_CREATE"},
		{"apt36-persistence-evasion", "apt36-pe5", "BAS_CONFIRM_APT36_DEFENDER_EXCLUSION"},
		{"apt36-command-control", "apt36-k3", "BAS_CONFIRM_APT36_REMOTE_STAGING"},
		{"apt36-command-control", "apt36-k5", "BAS_CONFIRM_APT36_LATERAL_MOVEMENT"},
		{"apt36-command-control", "apt36-k6", "BAS_CONFIRM_APT36_LATERAL_MOVEMENT"},
	}
	for _, c := range cases {
		d := loadAPT36(t, c.scen)
		var cmd string
		for _, s := range d.Steps {
			if s.ID == c.id {
				cmd = s.Command
			}
		}
		if cmd == "" {
			t.Fatalf("%s not found", c.id)
		}
		for _, val := range []string{"", "True", "1", "yes"} {
			t.Run(c.gate+"="+val, func(t *testing.T) {
				out := runPosturePowerShell(t, "$env:"+c.gate+" = '"+val+"'\n"+cmd)
				if !strings.Contains(out, "not_applicable") || !strings.Contains(out, "SKIP:") || !strings.Contains(out, c.gate) {
					t.Errorf("gate value %q must skip and name %s\n%s", val, c.gate, out)
				}
			})
		}
	}
}

// The WinRM exposure check and the defense-evasion COM/registry steps must
// never themselves change the live state they report on.
func TestAPT36_K4NeverChangesWinRMState(t *testing.T) {
	d := loadAPT36(t, "apt36-command-control")
	var cmd string
	for _, s := range d.Steps {
		if s.ID == "apt36-k4" {
			cmd = s.Command
		}
	}
	if cmd == "" {
		t.Fatal("apt36-k4 not found")
	}
	for _, verb := range []string{"Start-Service", "Stop-Service", "Set-Item WSMan", "Enable-PSRemoting", "Disable-PSRemoting"} {
		if strings.Contains(cmd, verb) {
			t.Errorf("apt36-k4 must be read-only; found %q in its command", verb)
		}
	}
}
