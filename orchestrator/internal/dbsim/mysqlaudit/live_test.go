package mysqlaudit

import (
	"context"
	"os"
	"testing"

	"github.com/audspect/bas/internal/dbsim"
)

// TestLiveHarnessEvidenceCovered runs only on the lab host. It is skipped unless
// DBSIM_HARNESS_LIVE=1 and the three lab paths are set. It must report covered.
func TestLiveHarnessEvidenceCovered(t *testing.T) {
	if os.Getenv("DBSIM_HARNESS_LIVE") != "1" {
		t.Skip("live lab check: set DBSIM_HARNESS_LIVE=1 on the lab host")
	}
	cfg := LabConfig{
		PasswordFile: os.Getenv("DBSIM_HARNESS_PW"),
		Addr:         os.Getenv("DBSIM_HARNESS_ADDR"),
		AuditFile:    os.Getenv("DBSIM_HARNESS_AUDIT"),
	}
	ev, err := Evidence(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Evidence: %v", err)
	}
	if ev.AuditCoverage != "covered" {
		t.Fatalf("want covered, got %q", ev.AuditCoverage)
	}
}

// TestLiveAuthEvent03 runs test 03 on the lab host. It needs the same DBSIM_HARNESS_*
// variables and DBSIM_HARNESS_RUN (a run ID: letters, digits, hyphens). It must PASS.
func TestLiveAuthEvent03(t *testing.T) {
	if os.Getenv("DBSIM_HARNESS_LIVE") != "1" {
		t.Skip("live lab check: set DBSIM_HARNESS_LIVE=1 on the lab host")
	}
	cfg := LabConfig{
		PasswordFile: os.Getenv("DBSIM_HARNESS_PW"),
		Addr:         os.Getenv("DBSIM_HARNESS_ADDR"),
		AuditFile:    os.Getenv("DBSIM_HARNESS_AUDIT"),
	}
	res, why, err := RunAuthEvent(context.Background(), cfg, os.Getenv("DBSIM_HARNESS_RUN"))
	if err != nil {
		t.Fatalf("RunAuthEvent: %v", err)
	}
	t.Logf("result=%s reason=%s", res, why)
	if res != "PASS" {
		t.Fatalf("test 03 must PASS on the lab, got %s (%s)", res, why)
	}
}

// TestLiveFailedLogin04 runs test 04 on the lab host. Same variables as test 03, with
// DBSIM_HARNESS_RUN up to 22 letters or digits. It must PASS.
func TestLiveFailedLogin04(t *testing.T) {
	if os.Getenv("DBSIM_HARNESS_LIVE") != "1" {
		t.Skip("live lab check: set DBSIM_HARNESS_LIVE=1 on the lab host")
	}
	cfg := LabConfig{
		PasswordFile: os.Getenv("DBSIM_HARNESS_PW"),
		Addr:         os.Getenv("DBSIM_HARNESS_ADDR"),
		AuditFile:    os.Getenv("DBSIM_HARNESS_AUDIT"),
	}
	res, why, err := RunFailedLogin(context.Background(), cfg, os.Getenv("DBSIM_HARNESS_RUN"))
	if err != nil {
		t.Fatalf("RunFailedLogin: %v", err)
	}
	t.Logf("result=%s reason=%s", res, why)
	if res != "PASS" {
		t.Fatalf("test 04 must PASS on the lab, got %s (%s)", res, why)
	}
}

// TestLiveFixtureTests05to08 runs tests 05-08 on the lab host. It needs the harness
// variables plus DBSIM_FIXTURE_PW (the dbsim_fixture password file). Each test gets its
// own run ID: DBSIM_HARNESS_RUN with a two-digit suffix, so it must stay under 21
// characters. Every test must PASS.
func TestLiveFixtureTests05to08(t *testing.T) {
	if os.Getenv("DBSIM_HARNESS_LIVE") != "1" {
		t.Skip("live lab check: set DBSIM_HARNESS_LIVE=1 on the lab host")
	}
	base := os.Getenv("DBSIM_HARNESS_RUN")
	cfg := LabConfig{
		PasswordFile:        os.Getenv("DBSIM_HARNESS_PW"),
		FixturePasswordFile: os.Getenv("DBSIM_FIXTURE_PW"),
		Addr:                os.Getenv("DBSIM_HARNESS_ADDR"),
		AuditFile:           os.Getenv("DBSIM_HARNESS_AUDIT"),
	}
	ctx := context.Background()
	cases := []struct {
		name string
		run  func(context.Context, LabConfig, string) (dbsim.RunResult, string, error)
	}{
		{"05", RunPrivilegedFlush},
		{"06", RunGrantRevoke},
		{"07", RunSensitiveRead},
		{"08", RunDDL},
	}
	for _, c := range cases {
		res, why, err := c.run(ctx, cfg, base+c.name)
		if err != nil {
			t.Errorf("test %s: %v", c.name, err)
			continue
		}
		t.Logf("test %s: result=%s reason=%s", c.name, res, why)
		if res != dbsim.ResultPass {
			t.Errorf("test %s must PASS on the lab, got %s (%s)", c.name, res, why)
		}
	}
}

// TestLiveSkippedWhenPluginOff expects every MySQL test (03-08) to report SKIPPED. Run it
// only while the audit_log plugin is UNINSTALLED on the lab. Each runner checks the plugin
// before any operation, so a SKIPPED result means no operation ran.
func TestLiveSkippedWhenPluginOff(t *testing.T) {
	if os.Getenv("DBSIM_HARNESS_LIVE") != "1" || os.Getenv("DBSIM_HARNESS_PLUGIN_OFF") != "1" {
		t.Skip("set DBSIM_HARNESS_LIVE=1 and DBSIM_HARNESS_PLUGIN_OFF=1 (only while audit_log is uninstalled)")
	}
	base := os.Getenv("DBSIM_HARNESS_RUN")
	cfg := LabConfig{
		PasswordFile:        os.Getenv("DBSIM_HARNESS_PW"),
		FixturePasswordFile: os.Getenv("DBSIM_FIXTURE_PW"),
		Addr:                os.Getenv("DBSIM_HARNESS_ADDR"),
		AuditFile:           os.Getenv("DBSIM_HARNESS_AUDIT"),
	}
	ctx := context.Background()
	type run func(context.Context, LabConfig, string) (dbsim.RunResult, string, error)
	cases := map[string]run{
		"03": RunAuthEvent,
		"04": RunFailedLogin,
		"05": RunPrivilegedFlush,
		"06": RunGrantRevoke,
		"07": RunSensitiveRead,
		"08": RunDDL,
	}
	for _, name := range []string{"03", "04", "05", "06", "07", "08"} {
		res, why, err := cases[name](ctx, cfg, base+name)
		if err != nil {
			t.Errorf("test %s: %v", name, err)
			continue
		}
		t.Logf("test %s: result=%s reason=%s", name, res, why)
		if res != dbsim.ResultSkipped {
			t.Errorf("test %s must be SKIPPED while the plugin is off, got %s (%s)", name, res, why)
		}
	}
}
