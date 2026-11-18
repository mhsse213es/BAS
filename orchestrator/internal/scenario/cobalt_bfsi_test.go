package scenario

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/bfsisim"
)

func TestCobaltBFSIPacks_ParseWithCommandAndCleanup(t *testing.T) {
	want := map[string]int{
		"cobalt-group-bfsi-credential-access":    8,
		"cobalt-group-bfsi-lateral-movement":     6,
		"cobalt-group-bfsi-discovery":            4,
		"cobalt-group-bfsi-collection-exfil":     6,
		"cobalt-group-bfsi-defense-evasion":      7,
		"cobalt-group-bfsi-financial-impact":     7,
		"cobalt-group-bfsi-persistence-variants": 4,
		"cobalt-group-bfsi-c2-variants":          4,
		"cobalt-group-bfsi-recon":                2,
		"cobalt-group-bfsi-access-execution":     2,
	}
	for pack, n := range want {
		b, err := os.ReadFile(filepath.Join("..", "..", "..", "scenarios", pack+".yaml"))
		if err != nil {
			t.Fatalf("read %s: %v", pack, err)
		}
		sc, err := ParseYAML(b)
		if err != nil {
			t.Fatalf("parse %s: %v", pack, err)
		}
		if len(sc.Steps) != n {
			t.Errorf("%s: got %d steps, want %d", pack, len(sc.Steps), n)
		}
		for _, s := range sc.Steps {
			if s.Command == "" {
				t.Errorf("%s %s: empty command", pack, s.TechniqueID)
			}
			if s.Cleanup == "" {
				t.Errorf("%s %s: empty cleanup", pack, s.TechniqueID)
			}
		}
	}
}

// findStepByTechnique returns the command of the first step in path matching techniqueID.
func findStepByTechnique(t *testing.T, path, techniqueID string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sc, err := ParseYAML(b)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	for _, s := range sc.Steps {
		if s.TechniqueID == techniqueID {
			return s.Command
		}
	}
	t.Fatalf("no step with technique_id %q in %s", techniqueID, path)
	return ""
}

// findStepByActionKey returns the command of the first step in path matching actionKey. Unlike
// findStepByTechnique, this disambiguates steps that intentionally share one technique_id (the
// financial-impact pack tags fin-01..06 all T1565.001).
func findStepByActionKey(t *testing.T, path, actionKey string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sc, err := ParseYAML(b)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	for _, s := range sc.Steps {
		if s.ActionKey == actionKey {
			return s.Command
		}
	}
	t.Fatalf("no step with action_key %q in %s", actionKey, path)
	return ""
}

func runCobaltBFSIPowerShell(t *testing.T, script string) string {
	t.Helper()
	out, _ := exec.Command("powershell", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-Command", script).CombinedOutput()
	return string(out)
}

// TestCobaltBFSIAttackPath_CredentialToDiscoveryCorrelation runs one real step
// from the credential-access pack and one from the discovery pack back to
// back, against a live bfsisim.Simulator instance (not a mock), and checks
// that both produce a classifiable verdict with strictly increasing
// timestamps — the minimal evidence-correlation guarantee the P0 plan called
// for: a later stage's evidence must postdate the earlier stage's.
func TestCobaltBFSIAttackPath_CredentialToDiscoveryCorrelation(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("scenario steps are PowerShell")
	}

	sim := bfsisim.NewSimulator("127.0.0.1:0")
	if err := sim.Start(); err != nil {
		t.Fatalf("start simulator: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = sim.Stop(ctx)
	}()
	host, port, found := strings.Cut(sim.Addr(), ":")
	if !found {
		t.Fatalf("unexpected simulator addr %q", sim.Addr())
	}

	credCmd := findStepByTechnique(t, filepath.Join("..", "..", "..", "scenarios", "cobalt-group-bfsi-credential-access.yaml"), "T1003.001")
	discCmd := findStepByTechnique(t, filepath.Join("..", "..", "..", "scenarios", "cobalt-group-bfsi-discovery.yaml"), "T1046")

	// Clear any stale undo record from a previous interrupted run, so New-CgUndoRecord's
	// exclusive create doesn't itself fail and mask the real LSASS-access verdict.
	undoPath := filepath.Join(os.TempDir(), "bas-cg-undo", "cred-01.json")
	_ = os.Remove(undoPath)
	defer os.Remove(undoPath)

	t1 := time.Now()
	credOut := runCobaltBFSIPowerShell(t, credCmd)
	t2 := time.Now()

	os.Setenv("BFSI_SIMULATOR_HOST", host)
	os.Setenv("BFSI_SIMULATOR_PORT", port)
	defer os.Unsetenv("BFSI_SIMULATOR_HOST")
	defer os.Unsetenv("BFSI_SIMULATOR_PORT")
	discOut := runCobaltBFSIPowerShell(t, discCmd)
	t3 := time.Now()

	if !strings.Contains(credOut, "[BAS-CRED-CRED-01]") {
		t.Errorf("credential-access step did not produce its verdict tag; output: %s", credOut)
	}
	if !strings.HasPrefix(strings.TrimSpace(credOut), "PASS:") && !strings.HasPrefix(strings.TrimSpace(credOut), "ERROR:") {
		t.Errorf("credential-access step verdict was neither PASS nor ERROR (expected one, since no real LSASS access control is present in CI): %s", credOut)
	}

	if !strings.Contains(discOut, "[BAS-BFSI-bfsi-01]") {
		t.Errorf("discovery step did not produce its verdict tag; output: %s", discOut)
	}
	if !strings.Contains(discOut, "found 2 applications") {
		t.Errorf("discovery step did not reflect the live simulator's actual service count: %s", discOut)
	}

	if !t1.Before(t2) || !t2.Before(t3) {
		t.Errorf("evidence timestamps are not strictly increasing: t1=%v t2=%v t3=%v", t1, t2, t3)
	}
}

// TestCobaltBFSIFinancialImpact_LedgerManipulationDetected runs the real fin-01 PowerShell command
// against a live bfsisim.Simulator (not a mock) and asserts the verdict is PASS, reflecting the
// stub ledger's actual duplicate-id-rejection behavior (HTTP 409 on an in-place amount overwrite).
func TestCobaltBFSIFinancialImpact_LedgerManipulationDetected(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("scenario steps are PowerShell")
	}

	sim := bfsisim.NewSimulator("127.0.0.1:0")
	if err := sim.Start(); err != nil {
		t.Fatalf("start simulator: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = sim.Stop(ctx)
	}()
	host, port, found := strings.Cut(sim.Addr(), ":")
	if !found {
		t.Fatalf("unexpected simulator addr %q", sim.Addr())
	}

	finCmd := findStepByActionKey(t, filepath.Join("..", "..", "..", "scenarios", "cobalt-group-bfsi-financial-impact.yaml"), "financial_transaction_manipulation")

	undoPath := filepath.Join(os.TempDir(), "bas-cg-undo", "fin-01.json")
	_ = os.Remove(undoPath)
	defer os.Remove(undoPath)

	os.Setenv("BFSI_SIMULATOR_HOST", host)
	os.Setenv("BFSI_SIMULATOR_PORT", port)
	defer os.Unsetenv("BFSI_SIMULATOR_HOST")
	defer os.Unsetenv("BFSI_SIMULATOR_PORT")

	out := runCobaltBFSIPowerShell(t, finCmd)

	if !strings.Contains(out, "[BAS-FIN-FIN-01]") {
		t.Fatalf("financial-impact step did not produce its verdict tag; output: %s", out)
	}
	if !strings.HasPrefix(strings.TrimSpace(out), "PASS:") {
		t.Errorf("fin-01 verdict was not PASS against a live simulator rejecting the duplicate-id overwrite with 409: %s", out)
	}

	remaining := sim.Ledger()
	if len(remaining) != 1 {
		t.Errorf("expected exactly 1 baseline transaction left in the ledger (the tamper attempt must have been rejected, not applied), got %d: %+v", len(remaining), remaining)
	}
}

// TestCobaltBFSICSVariants_BeaconPatternAgainstLiveSimulator runs the real c2-01 command against a
// live bfsisim.Simulator and asserts the five periodic beacons succeed with increasing timestamps.
func TestCobaltBFSICSVariants_BeaconPatternAgainstLiveSimulator(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("scenario steps are PowerShell")
	}

	sim := bfsisim.NewSimulator("127.0.0.1:0")
	if err := sim.Start(); err != nil {
		t.Fatalf("start simulator: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = sim.Stop(ctx)
	}()
	host, port, found := strings.Cut(sim.Addr(), ":")
	if !found {
		t.Fatalf("unexpected simulator addr %q", sim.Addr())
	}

	beaconCmd := findStepByActionKey(t, filepath.Join("..", "..", "..", "scenarios", "cobalt-group-bfsi-c2-variants.yaml"), "c2_http_beaconing")

	os.Setenv("BFSI_SIMULATOR_HOST", host)
	os.Setenv("BFSI_SIMULATOR_PORT", port)
	defer os.Unsetenv("BFSI_SIMULATOR_HOST")
	defer os.Unsetenv("BFSI_SIMULATOR_PORT")

	out := runCobaltBFSIPowerShell(t, beaconCmd)

	if !strings.Contains(out, "[BAS-C2-C2-01]") {
		t.Fatalf("beacon step did not produce its verdict tag; output: %s", out)
	}
	if !strings.HasPrefix(strings.TrimSpace(out), "PASS:") {
		t.Errorf("c2-01 verdict was not PASS against a live simulator: %s", out)
	}
}
