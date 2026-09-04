package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The macOS inventory is exercised entirely through injected command output and
// an injected filesystem root, so it is verifiable from a non-macOS build host.
// Nothing here runs a real macOS binary.

// fakeMac records what was executed and replays canned output.
type fakeMac struct {
	out   map[string][]byte
	errs  map[string]error
	calls []string
}

func newFakeMac() *fakeMac {
	return &fakeMac{out: map[string][]byte{}, errs: map[string]error{}}
}

func (f *fakeMac) run(name string, args ...string) ([]byte, error) {
	key := name
	if len(args) > 0 {
		key = name + " " + args[0]
	}
	f.calls = append(f.calls, key)
	if err, ok := f.errs[key]; ok {
		return nil, err
	}
	return f.out[key], nil
}

func (f *fakeMac) ran(key string) int {
	n := 0
	for _, c := range f.calls {
		if c == key {
			n++
		}
	}
	return n
}

// A healthy Mac: every platform control on, nothing third-party installed.
func healthyMac(f *fakeMac) {
	f.out["csrutil status"] = []byte("System Integrity Protection status: enabled.\n")
	f.out["spctl --status"] = []byte("assessments enabled\n")
	f.out[socketfilterfwPath+" --getglobalstate"] = []byte("Firewall is enabled. (State = 1)\n")
	f.out["fdesetup status"] = []byte("FileVault is On.\n")
	f.out["systemextensionsctl list"] = []byte("0 extension(s)\n")
	f.out["ps -axco"] = []byte("COMMAND\nlaunchd\nkernel_task\n")
}

func productsContaining(products []string, sub string) string {
	for _, p := range products {
		if strings.Contains(p, sub) {
			return p
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Platform controls: a control that is OFF is a finding, never an omission.
// ---------------------------------------------------------------------------

func TestDarwinInventory_ReportsPlatformControlsWhenEnabled(t *testing.T) {
	f := newFakeMac()
	healthyMac(f)
	products, diag := enumerateDarwinSecurityProducts(t.TempDir(), f.run)
	for _, want := range []string{"System Integrity Protection (enabled)",
		"Gatekeeper (assessments enabled)", "Application Firewall (enabled)",
		"FileVault (on)"} {
		if productsContaining(products, want) == "" {
			t.Errorf("missing %q in %v", want, products)
		}
	}
	if len(diag) != 0 {
		t.Errorf("healthy host should produce no diagnostics, got %v", diag)
	}
}

// The whole point of the honesty contract: a weakened Mac must not read as a
// clean one. Disabled controls are reported explicitly and prominently.
func TestDarwinInventory_DisabledControlsAreReportedNotOmitted(t *testing.T) {
	f := newFakeMac()
	healthyMac(f)
	f.out["csrutil status"] = []byte("System Integrity Protection status: disabled.\n")
	f.out["spctl --status"] = []byte("assessments disabled\n")
	f.out[socketfilterfwPath+" --getglobalstate"] = []byte("Firewall is disabled. (State = 0)\n")
	f.out["fdesetup status"] = []byte("FileVault is Off.\n")

	products, _ := enumerateDarwinSecurityProducts(t.TempDir(), f.run)
	for _, want := range []string{
		"System Integrity Protection (DISABLED)",
		"Gatekeeper (DISABLED)",
		"Application Firewall (DISABLED)",
		"FileVault (OFF)",
	} {
		if productsContaining(products, want) == "" {
			t.Errorf("a disabled control must be reported, missing %q in %v", want, products)
		}
	}
}

// "We could not look" must never collapse into "nothing is installed".
func TestDarwinInventory_UnreadableControlGoesToDiagNotSilence(t *testing.T) {
	f := newFakeMac()
	healthyMac(f)
	f.errs["csrutil status"] = errors.New("csrutil: command not found")

	products, diag := enumerateDarwinSecurityProducts(t.TempDir(), f.run)
	if productsContaining(products, "System Integrity Protection") != "" {
		t.Error("SIP must not be reported when it could not be read")
	}
	if len(diag) == 0 || !strings.Contains(strings.Join(diag, " "), "System Integrity Protection") {
		t.Errorf("an unreadable control must appear in diag, got %v", diag)
	}
}

// Output we do not recognise is a diagnostic, not a guess. A future macOS
// release rewording csrutil must not silently become "enabled".
func TestDarwinInventory_UnrecognisedOutputIsNotGuessed(t *testing.T) {
	f := newFakeMac()
	healthyMac(f)
	f.out["csrutil status"] = []byte("System Integrity Protection status: custom configuration.\n")

	products, diag := enumerateDarwinSecurityProducts(t.TempDir(), f.run)
	if productsContaining(products, "System Integrity Protection (enabled)") != "" {
		t.Error("unrecognised SIP output must not be reported as enabled")
	}
	if !strings.Contains(strings.Join(diag, " "), "System Integrity Protection") {
		t.Errorf("unrecognised output belongs in diag, got %v", diag)
	}
}

// ---------------------------------------------------------------------------
// Product detection: running / installed / activated are different claims.
// ---------------------------------------------------------------------------

func TestDarwinInventory_RunningProcessIsReportedAsRunning(t *testing.T) {
	f := newFakeMac()
	healthyMac(f)
	f.out["ps -axco"] = []byte("COMMAND\nlaunchd\nfalcond\n")

	products, _ := enumerateDarwinSecurityProducts(t.TempDir(), f.run)
	got := productsContaining(products, "CrowdStrike Falcon")
	if got == "" {
		t.Fatalf("CrowdStrike not reported, got %v", products)
	}
	if !strings.Contains(got, "running") {
		t.Errorf("want a 'running' claim, got %q", got)
	}
	if !strings.HasPrefix(got, string(kindEDR)+":") {
		t.Errorf("want the EDR kind prefix, got %q", got)
	}
}

// An app bundle on disk proves installation, not that anything is running. The
// distinction is the difference between a control and a leftover.
func TestDarwinInventory_InstalledButNotRunningSaysSo(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "Applications", "Falcon.app"), 0o755); err != nil {
		t.Fatal(err)
	}
	f := newFakeMac()
	healthyMac(f)

	products, _ := enumerateDarwinSecurityProducts(root, f.run)
	got := productsContaining(products, "CrowdStrike Falcon")
	if got == "" {
		t.Fatalf("CrowdStrike not reported from its install path, got %v", products)
	}
	if !strings.Contains(got, "installed at") || !strings.Contains(got, "not running") {
		t.Errorf("want an 'installed, not running' claim, got %q", got)
	}
}

// An activated endpoint-security extension is the strongest macOS evidence
// that a product is wired into the kernel's security path.
func TestDarwinInventory_ActivatedSystemExtensionIsReported(t *testing.T) {
	f := newFakeMac()
	healthyMac(f)
	f.out["systemextensionsctl list"] = []byte(`1 extension(s)
--- com.apple.system_extension.endpoint_security
enabled	active	teamID	bundleID (version)	name	[state]
*	*	X9E956P446	com.crowdstrike.falcon.Agent (7.11/7.11.0.0)	Falcon	[activated enabled]
`)
	products, _ := enumerateDarwinSecurityProducts(t.TempDir(), f.run)
	got := productsContaining(products, "CrowdStrike Falcon")
	if got == "" {
		t.Fatalf("CrowdStrike not reported from its system extension, got %v", products)
	}
	if !strings.Contains(got, "endpoint security extension activated") {
		t.Errorf("want the extension claim, got %q", got)
	}
}

// An extension listed but NOT activated is the "installed, not protecting"
// case. Reporting it as activated would overstate the endpoint's defences.
func TestDarwinInventory_NonActivatedExtensionIsNotClaimedActive(t *testing.T) {
	f := newFakeMac()
	healthyMac(f)
	f.out["systemextensionsctl list"] = []byte(`1 extension(s)
--- com.apple.system_extension.endpoint_security
enabled	active	teamID	bundleID (version)	name	[state]
		X9E956P446	com.crowdstrike.falcon.Agent (7.11/7.11.0.0)	Falcon	[terminated waiting to uninstall on reboot]
`)
	products, _ := enumerateDarwinSecurityProducts(t.TempDir(), f.run)
	if got := productsContaining(products, "extension activated"); got != "" {
		t.Errorf("a non-activated extension must not be claimed active: %q", got)
	}
}

// macOS truncates the ps accounting name. A long product name must still match.
func TestDarwinInventory_MatchesTruncatedProcessName(t *testing.T) {
	f := newFakeMac()
	healthyMac(f)
	// "com.crowdstrike.falcon.Agent" truncated the way ps -c reports it.
	f.out["ps -axco"] = []byte("COMMAND\nRTProtectionDaem\n")

	products, _ := enumerateDarwinSecurityProducts(t.TempDir(), f.run)
	if productsContaining(products, "Malwarebytes") == "" {
		t.Errorf("truncated process name should still match, got %v", products)
	}
}

func TestDarwinInventory_TelemetryIsNotReportedAsEDR(t *testing.T) {
	f := newFakeMac()
	healthyMac(f)
	f.out["ps -axco"] = []byte("COMMAND\nosqueryd\n")

	products, _ := enumerateDarwinSecurityProducts(t.TempDir(), f.run)
	got := productsContaining(products, "osquery")
	if got == "" {
		t.Fatalf("osquery not reported, got %v", products)
	}
	if !strings.HasPrefix(got, string(kindTelemetry)+":") {
		t.Errorf("a log shipper must not read as a preventive control: %q", got)
	}
}

// ---------------------------------------------------------------------------
// Observation footprint
// ---------------------------------------------------------------------------

// One spawn per control, never one per candidate. A burst of process creations
// is exactly what a watching EDR blocks -- which would make a better-defended
// Mac report LESS protection than an undefended one.
func TestDarwinInventory_SpawnsOncePerControl(t *testing.T) {
	f := newFakeMac()
	healthyMac(f)
	enumerateDarwinSecurityProducts(t.TempDir(), f.run)

	if len(f.calls) > 6 {
		t.Errorf("want at most one spawn per control (6), got %d: %v", len(f.calls), f.calls)
	}
	for _, key := range []string{"csrutil status", "spctl --status", "fdesetup status",
		"systemextensionsctl list", "ps -axco"} {
		if n := f.ran(key); n != 1 {
			t.Errorf("%s ran %d times, want exactly 1", key, n)
		}
	}
	if n := len(darwinSignatures); n < 15 {
		t.Fatalf("catalogue has only %d entries; the spawn bound is only meaningful "+
			"if it holds across a real catalogue", n)
	}
}

// A Mac with nothing installed and every control readable must report the
// platform controls and no products -- never an empty inventory that would
// read as "we found nothing, so nothing is there".
func TestDarwinInventory_CleanHostStillReportsPlatformControls(t *testing.T) {
	f := newFakeMac()
	healthyMac(f)
	products, _ := enumerateDarwinSecurityProducts(t.TempDir(), f.run)
	if len(products) < 4 {
		t.Fatalf("want the four platform controls at minimum, got %v", products)
	}
}

// systemextensionsctl's column layout has shifted between macOS releases.
// Locating the bundle ID by its reverse-DNS shape rather than by column index
// keeps the parse working when a column is added or dropped.
func TestParseSystemExtensions_ToleratesColumnDrift(t *testing.T) {
	cases := map[string]string{
		"with name column": "*\t*\tX9E956P446\tcom.crowdstrike.falcon.Agent (7.11/7.11.0.0)\tFalcon\t[activated enabled]",
		"no name column":   "*\t*\tX9E956P446\tcom.crowdstrike.falcon.Agent (7.11/7.11.0.0)\t[activated enabled]",
		"no version":       "*\t*\tX9E956P446\tcom.crowdstrike.falcon.Agent\tFalcon\t[activated enabled]",
	}
	for name, line := range cases {
		exts := parseSystemExtensions([]byte(line + "\n"))
		e, ok := exts["com.crowdstrike.falcon.Agent"]
		if !ok {
			t.Errorf("%s: bundle ID not found, got %v", name, exts)
			continue
		}
		if !e.activated {
			t.Errorf("%s: want activated", name)
		}
		if e.teamID != "X9E956P446" {
			t.Errorf("%s: teamID = %q", name, e.teamID)
		}
	}
}

// The header row must never become a phantom extension.
func TestParseSystemExtensions_SkipsHeader(t *testing.T) {
	out := "1 extension(s)\n--- com.apple.system_extension.endpoint_security\nenabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n"
	if exts := parseSystemExtensions([]byte(out)); len(exts) != 0 {
		t.Errorf("want no extensions from a header-only listing, got %v", exts)
	}
}
