package scenario

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var apt29Scenarios = map[string]int{
	"apt29-kill-chain":         6,
	"apt29-execution-evasion":  9,
	"apt29-persistence":        4,
	"apt29-credential-access":  3,
	"apt29-command-control":    3,
	"apt29-collection-staging": 3,
}

func TestAPT29_LibraryDecisionTable(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("oracle is Windows PowerShell")
	}
	lib, err := os.ReadFile(filepath.Join("..", "..", "..", "scenarios-src", "apt29-common", "lib.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	table := `$cases = @(
 @('prevented: not run, one block event', $false, 1, $true, $true, $true, 'prevented'),
 @('absence alone is inconclusive', $false, 0, $true, $true, $true, 'inconclusive'),
 @('absence with enforcement active is still inconclusive', $false, 0, $true, $true, $true, 'inconclusive'),
 @('unreadable log is inconclusive', $false, 0, $false, $false, $true, 'inconclusive'),
 @('ran with a block event is a failure', $true, 1, $true, $true, $true, 'allowed_unexpectedly'),
 @('ran while enforcing is a failure', $true, 0, $true, $true, $true, 'allowed_unexpectedly'),
 @('ran, nothing enforcing', $true, 0, $true, $false, $true, 'not_enforced'),
 @('ran with unreadable log, nothing enforcing', $true, 0, $false, $false, $true, 'not_enforced'),
 @('build below floor', $false, 1, $true, $true, $false, 'not_applicable')
)
foreach ($c in $cases) { $r = Resolve-A29Outcome -Ran $c[1] -Blocks $c[2] -Readable $c[3] -Enforcing $c[4] -BuildOk $c[5]; if ($r.Outcome -ne $c[6]) { "BAD $($c[0]) want=$($c[6]) got=$($r.Outcome)" } }
'TABLE_DONE'`
	out := runPosturePowerShell(t, string(lib)+"\n"+table)
	if !strings.Contains(out, "TABLE_DONE") || strings.Contains(out, "BAD ") {
		t.Fatalf("decision table failed:\n%s", out)
	}
}

type apt29Doc struct {
	ProductLine string `yaml:"product_line"`
	Steps       []struct {
		ID       string   `yaml:"id"`
		Name     string   `yaml:"name"`
		Tech     string   `yaml:"technique_id"`
		Command  string   `yaml:"command"`
		Cleanup  string   `yaml:"cleanup"`
		Profiles []string `yaml:"detection_profiles"`
	} `yaml:"steps"`
}

func loadAPT29(t *testing.T, id string) apt29Doc {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "scenarios", id+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var d apt29Doc
	if err := yaml.Unmarshal(data, &d); err != nil {
		t.Fatalf("%s: %v", id, err)
	}
	return d
}

func TestAPT29_EveryStepWellFormed(t *testing.T) {
	// Techniques MITRE does not attribute to G0016; they must never be tagged here.
	notAttributed := []string{"T1003.001", "T1041", "T1518.001", "T1543.003", "T1546.015", "T1555.004", "T1567.002", "T1569.002", "T1615"}
	for id, want := range apt29Scenarios {
		d := loadAPT29(t, id)
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
			for _, w := range []string{"Invoke-A29Test", "APT29_OUTCOME", "Resolve-A29Outcome"} {
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
			for _, bad := range notAttributed {
				if s.Tech == bad {
					t.Errorf("%s %s: technique %s is not attributed to G0016", id, s.ID, bad)
				}
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

func TestAPT29_KillChainKeepsDetectionProfiles(t *testing.T) {
	d := loadAPT29(t, "apt29-kill-chain")
	want := map[string]string{
		"apt29-s2a": "windows_encoded_powershell", "apt29-s2b": "windows_encoded_powershell",
		"apt29-s3": "windows_runkey_persistence", "apt29-s4": "windows_schtask_persistence", "apt29-s5": "windows_dns_c2",
	}
	for _, s := range d.Steps {
		if w, ok := want[s.ID]; ok {
			if len(s.Profiles) != 1 || s.Profiles[0] != w {
				t.Errorf("%s: detection_profiles = %v, want [%s]", s.ID, s.Profiles, w)
			}
			delete(want, s.ID)
		}
	}
	if len(want) != 0 {
		t.Errorf("missing stages: %v", want)
	}
}

func TestAPT29_GatedStepsSkipWithoutGate(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("behavioral steps are Windows PowerShell")
	}
	cases := []struct{ scen, id, gate string }{
		{"apt29-execution-evasion", "apt29-x9", "BAS_CONFIRM_APT29_TEST_LOG"},
		{"apt29-persistence", "apt29-p3", "BAS_CONFIRM_APT29_WMI_SUBSCRIPTION"},
		{"apt29-command-control", "apt29-k3", "BAS_CONFIRM_APT29_PORTPROXY"},
		{"apt29-collection-staging", "apt29-o2", "BAS_CONFIRM_APT29_REMOTE_STAGING"},
	}
	for _, c := range cases {
		d := loadAPT29(t, c.scen)
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
				if !strings.Contains(out, "APT29_OUTCOME: not_applicable") || !strings.Contains(out, "SKIP:") || !strings.Contains(out, c.gate) {
					t.Errorf("gate value %q must skip and name %s\n%s", val, c.gate, out)
				}
			})
		}
	}
}
