package segprobe

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Live gates run against the real seg-lab (Linux host with Docker, e.g. the
// staging host). They are skipped unless SEG_LAB=1. SEG_LAB_DIR names the lab
// directory; the default is relative to this package.
//
// Every test sets the firewall rules it needs and restores the default
// core-banking rules when it finishes, so the tests do not depend on order.

type labEnv struct {
	dir     string
	compose string
	p       Provider
}

func newLabEnv(t *testing.T) labEnv {
	t.Helper()
	if os.Getenv("SEG_LAB") != "1" {
		t.Skip("live lab gate: set SEG_LAB=1 on a host running the seg-lab")
	}
	dir := os.Getenv("SEG_LAB_DIR")
	if dir == "" {
		dir = filepath.Join("..", "..", "..", "lab", "segmentation")
	}
	compose := filepath.Join(dir, "docker-compose.yml")
	return labEnv{dir: dir, compose: compose, p: NewDockerProvider(compose)}
}

func (e labEnv) dockerCompose(t *testing.T, args ...string) {
	t.Helper()
	full := append([]string{"compose", "-f", e.compose}, args...)
	if _, err := execRunner(context.Background(), "docker", full...); err != nil {
		t.Fatalf("docker %s: %v", strings.Join(full, " "), err)
	}
}

// applyRules replaces the firewall rule set with a file from fw/rules.
// noCatchall sets NO_CATCHALL=1, so unmatched traffic is dropped unlogged.
func (e labEnv) applyRules(t *testing.T, file string, noCatchall bool) {
	t.Helper()
	args := []string{"exec", "-T"}
	if noCatchall {
		args = append(args, "-e", "NO_CATCHALL=1")
	}
	args = append(args, "seg-fw", "/rules/apply.sh", "/rules/"+file)
	e.dockerCompose(t, args...)
}

func (e labEnv) restoreDefaults(t *testing.T) {
	t.Cleanup(func() { e.applyRules(t, "core-banking.sh", false) })
}

func (e labEnv) pack(t *testing.T, name string) Scenario {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.dir, "scenarios", name+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := LoadScenario(b)
	if err != nil {
		t.Fatalf("pack %s: %v", name, err)
	}
	return s
}

func onlyProbe(s Scenario, id string) Scenario {
	out := s
	out.Probes = nil
	for _, p := range s.Probes {
		if p.ID == id {
			out.Probes = append(out.Probes, p)
		}
	}
	return out
}

func (e labEnv) verdictOf(t *testing.T, s Scenario, probeID string) ProbeOutcome {
	t.Helper()
	// Quiet time before each single probe, so earlier firewall records are
	// outside this probe's evidence window (the executor does the same between
	// probes of one scenario).
	time.Sleep(probeGap)
	res, err := RunScenario(context.Background(), e.p, onlyProbe(s, probeID), 0)
	if err != nil {
		t.Fatalf("RunScenario: %v", err)
	}
	if len(res.Outcomes) != 1 {
		t.Fatalf("probe %q not found in scenario %s", probeID, s.ID)
	}
	return res.Outcomes[0]
}

func TestLive_RulesResetBetweenRuns(t *testing.T) {
	e := newLabEnv(t)
	e.restoreDefaults(t)
	s := e.pack(t, "core-banking-tiering")

	e.applyRules(t, "test-open-corp-db.sh", false)
	if o := e.verdictOf(t, s, "corp-to-db"); o.Verdict != FAIL {
		t.Fatalf("with the opened rule: got %s (%s), want FAIL", o.Verdict, o.Reason)
	}

	e.applyRules(t, "core-banking.sh", false)
	if o := e.verdictOf(t, s, "corp-to-db"); o.Verdict != PASS {
		t.Fatalf("after reset to default rules: got %s (%s), want PASS", o.Verdict, o.Reason)
	}
}

// G1: a prohibited path that is opened must be graded FAIL.
func TestLive_G1_OpenedProhibitedPath_IsFail(t *testing.T) {
	e := newLabEnv(t)
	e.restoreDefaults(t)
	e.applyRules(t, "test-open-corp-db.sh", false)
	if o := e.verdictOf(t, e.pack(t, "core-banking-tiering"), "corp-to-db"); o.Verdict != FAIL {
		t.Fatalf("got %s (%s), want FAIL", o.Verdict, o.Reason)
	}
}

// G2: a prohibited path blocked with firewall evidence must be graded PASS.
func TestLive_G2_FirewallBlock_IsPass(t *testing.T) {
	e := newLabEnv(t)
	e.restoreDefaults(t)
	e.applyRules(t, "core-banking.sh", false)
	if o := e.verdictOf(t, e.pack(t, "core-banking-tiering"), "corp-to-db"); o.Verdict != PASS {
		t.Fatalf("got %s (%s), want PASS", o.Verdict, o.Reason)
	}
}

// G3: a timeout with nothing logged for the tuple must be UNKNOWN, never PASS.
func TestLive_G3_NoEvidence_IsUnknown(t *testing.T) {
	e := newLabEnv(t)
	e.restoreDefaults(t)
	e.applyRules(t, "test-no-evidence.sh", true)
	if o := e.verdictOf(t, e.pack(t, "core-banking-tiering"), "corp-to-db"); o.Verdict != UNKNOWN {
		t.Fatalf("got %s (%s), want UNKNOWN", o.Verdict, o.Reason)
	}
}

// G4: a destination that is down must be graded ERROR, not as a block.
func TestLive_G4_DestinationDown_IsError(t *testing.T) {
	e := newLabEnv(t)
	e.restoreDefaults(t)
	e.applyRules(t, "core-banking.sh", false)
	e.dockerCompose(t, "stop", "core-db")
	t.Cleanup(func() { e.dockerCompose(t, "start", "core-db") })
	if o := e.verdictOf(t, e.pack(t, "core-banking-tiering"), "app-to-db-authorized"); o.Verdict != ERROR {
		t.Fatalf("got %s (%s), want ERROR", o.Verdict, o.Reason)
	}
}

// G5: an authorized path with accept evidence must be graded PASS.
func TestLive_G5_AuthorizedPath_IsPass(t *testing.T) {
	e := newLabEnv(t)
	e.restoreDefaults(t)
	e.applyRules(t, "core-banking.sh", false)
	if o := e.verdictOf(t, e.pack(t, "core-banking-tiering"), "app-to-db-authorized"); o.Verdict != PASS {
		t.Fatalf("got %s (%s), want PASS", o.Verdict, o.Reason)
	}
}

// G6: with the firewall log collector stopped, every probe must be UNKNOWN.
func TestLive_G6_LogDisabled_IsUnknown(t *testing.T) {
	e := newLabEnv(t)
	e.restoreDefaults(t)
	e.applyRules(t, "core-banking.sh", false)
	e.dockerCompose(t, "exec", "-T", "seg-fw", "pkill", "ulogd")
	t.Cleanup(func() {
		e.dockerCompose(t, "exec", "-T", "seg-fw", "ulogd", "-d", "-c", "/etc/ulogd.conf")
	})
	s := e.pack(t, "core-banking-tiering")
	for _, p := range s.Probes {
		if o := e.verdictOf(t, s, p.ID); o.Verdict != UNKNOWN {
			t.Fatalf("probe %s: got %s (%s), want UNKNOWN", p.ID, o.Verdict, o.Reason)
		}
	}
}

// Determinism: each pack, run three times on the same rules, gives identical
// verdicts for every probe, and every verdict is PASS.
func TestLive_ThreeRunsIdentical(t *testing.T) {
	e := newLabEnv(t)
	e.restoreDefaults(t)
	cases := []struct{ pack, rules string }{
		{"swift-isolation", "swift.sh"},
		{"cde-atm-isolation", "cde-atm.sh"},
		{"core-banking-tiering", "core-banking.sh"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.pack, func(t *testing.T) {
			e.applyRules(t, c.rules, false)
			runs, stable, err := RunRepeated(context.Background(), e.p, e.pack(t, c.pack), 3)
			if err != nil {
				t.Fatal(err)
			}
			if !stable {
				t.Fatalf("verdicts changed across runs: %s", describeRuns(runs))
			}
			// Stable is not enough: every probe in these packs is designed to
			// PASS on this lab, so a consistent UNKNOWN or FAIL is a failure too.
			for _, r := range runs {
				for _, o := range r.Outcomes {
					if o.Verdict != PASS {
						t.Fatalf("run %d probe %s: got %s (%s), want PASS", r.RunIndex, o.Spec.ID, o.Verdict, o.Reason)
					}
				}
			}
		})
	}
}

func describeRuns(runs []RunResult) string {
	var b strings.Builder
	for _, r := range runs {
		for _, o := range r.Outcomes {
			fmt.Fprintf(&b, "[run %d %s=%s] ", r.RunIndex, o.Spec.ID, o.Verdict)
		}
	}
	return b.String()
}
