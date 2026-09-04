package main

import (
	"io/fs"
	"strings"
	"testing"
)

// Section B of the POSIX posture coverage map: checks that are net-new on both
// Linux and macOS. The evaluators are shared between the two platforms and
// carry no build tag, so both platforms' thresholds are verified here.

// ---------------------------------------------------------------------------
// T1552.001 -- credentials in files
// ---------------------------------------------------------------------------

func TestCredentialFileTargets_CoversTheUsualStores(t *testing.T) {
	targets := credentialFileTargets("/home/asha")
	var paths []string
	for _, tg := range targets {
		paths = append(paths, tg.path)
	}
	joined := strings.Join(paths, " ")
	for _, want := range []string{
		"/home/asha/.ssh", "/home/asha/.aws/credentials", "/home/asha/.netrc",
		"/home/asha/.pgpass", "/home/asha/.kube/config", "/home/asha/.git-credentials",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("credential targets missing %q", want)
		}
	}
}

func TestEvalCredentialFiles_OwnerOnlyPasses(t *testing.T) {
	f := []credFinding{
		{Path: "/home/asha/.ssh/id_ed25519", Mode: 0o600, Kind: "SSH private key"},
		{Path: "/home/asha/.aws/credentials", Mode: 0o600, Kind: "cloud credentials"},
	}
	r, d := evalCredentialFiles(f, 2)
	wantResult(t, r, "pass", d)
}

func TestEvalCredentialFiles_GroupReadableFails(t *testing.T) {
	f := []credFinding{
		{Path: "/home/asha/.ssh/id_rsa", Mode: 0o640, Kind: "SSH private key"},
		{Path: "/home/asha/.aws/credentials", Mode: 0o600, Kind: "cloud credentials"},
	}
	r, d := evalCredentialFiles(f, 2)
	wantResult(t, r, "fail", d)
	if !strings.Contains(d, "id_rsa") {
		t.Errorf("details must name the exposed file, got %q", d)
	}
	if strings.Contains(d, "credentials") && strings.Contains(d, "0600") {
		t.Errorf("a correctly-permissioned file must not be listed as exposed: %q", d)
	}
}

func TestEvalCredentialFiles_WorldReadableFails(t *testing.T) {
	r, d := evalCredentialFiles([]credFinding{
		{Path: "/home/asha/.pgpass", Mode: 0o644, Kind: "database credentials"},
	}, 1)
	wantResult(t, r, "fail", d)
	if !strings.Contains(d, "0644") {
		t.Errorf("details must state the observed mode, got %q", d)
	}
}

// No credential files at all is not evidence of good hygiene, and must not be
// reported as a pass that implies the endpoint was assessed and found clean.
func TestEvalCredentialFiles_NothingFoundIsWithheld(t *testing.T) {
	r, d := evalCredentialFiles(nil, 0)
	wantResult(t, r, "skipped", d)
	if !strings.Contains(strings.ToLower(d), "no credential") {
		t.Errorf("details must say nothing was found to assess, got %q", d)
	}
}

// A .pub file is meant to be world-readable. Flagging it would bury the real
// finding under noise on every endpoint that has ever generated a key.
func TestCredentialFileTargets_ExcludesPublicKeys(t *testing.T) {
	if isSSHPrivateKeyName("id_ed25519.pub") {
		t.Error("a .pub file must not be treated as a private key")
	}
	if isSSHPrivateKeyName("known_hosts") || isSSHPrivateKeyName("config") {
		t.Error("SSH housekeeping files are not private keys")
	}
	if !isSSHPrivateKeyName("id_rsa") || !isSSHPrivateKeyName("id_ed25519") {
		t.Error("standard private key names must be recognised")
	}
}

// ---------------------------------------------------------------------------
// T1219 -- unsanctioned remote access software
// ---------------------------------------------------------------------------

func TestEvalRemoteAccessSoftware_NoneFoundPasses(t *testing.T) {
	r, d := evalRemoteAccessSoftware(nil)
	wantResult(t, r, "pass", d)
}

func TestEvalRemoteAccessSoftware_FoundFails(t *testing.T) {
	r, d := evalRemoteAccessSoftware([]string{"AnyDesk (anydesk running)", "TeamViewer (installed at /Applications/TeamViewer.app)"})
	wantResult(t, r, "fail", d)
	for _, want := range []string{"AnyDesk", "TeamViewer"} {
		if !strings.Contains(d, want) {
			t.Errorf("details must name %q, got %q", want, d)
		}
	}
}

func TestRemoteAccessCatalogue_SeparatesRunningFromInstalled(t *testing.T) {
	running := map[string]bool{"anydesk": true}
	found := matchRemoteAccess(running, func(string) bool { return false })
	if len(found) != 1 || !strings.Contains(found[0], "running") {
		t.Fatalf("want a running claim, got %v", found)
	}
	found = matchRemoteAccess(map[string]bool{}, func(p string) bool {
		return strings.Contains(p, "TeamViewer")
	})
	if len(found) == 0 {
		t.Fatal("an installed-only product must still be reported")
	}
	if strings.Contains(found[0], "running") {
		t.Errorf("an installed-only product must not claim to be running: %q", found[0])
	}
}

// ---------------------------------------------------------------------------
// T1553.004 -- trust store
// ---------------------------------------------------------------------------

func TestEvalTrustStore_NoCustomRootsPasses(t *testing.T) {
	r, d := evalTrustStore(nil, true)
	wantResult(t, r, "pass", d)
}

func TestEvalTrustStore_CustomRootIsAFinding(t *testing.T) {
	r, d := evalTrustStore([]string{"corp-proxy-ca.crt", "internal-root.crt"}, true)
	wantResult(t, r, "fail", d)
	if !strings.Contains(d, "corp-proxy-ca.crt") {
		t.Errorf("details must name the root, got %q", d)
	}
	if !strings.Contains(d, "2") {
		t.Errorf("details must count them, got %q", d)
	}
}

// If the anchor directory does not exist we did not look, which is not the
// same as looking and finding nothing.
func TestEvalTrustStore_NoAnchorDirIsWithheld(t *testing.T) {
	r, d := evalTrustStore(nil, false)
	wantResult(t, r, "skipped", d)
}

// ---------------------------------------------------------------------------
// T1543.001 / .002 -- service persistence directories
// ---------------------------------------------------------------------------

func TestEvalWritableDirs_NonRootWritableFails(t *testing.T) {
	r, d := evalWritableDirs("systemd unit", map[string]fs.FileMode{
		"/etc/systemd/system": 0o777,
		"/lib/systemd/system": 0o755,
	}, "runs as root at boot")
	wantResult(t, r, "fail", d)
	if !strings.Contains(d, "/etc/systemd/system") {
		t.Errorf("details must name the directory, got %q", d)
	}
	if strings.Contains(d, "/lib/systemd/system") {
		t.Errorf("a correctly-permissioned directory must not be listed: %q", d)
	}
}

func TestEvalWritableDirs_RootOnlyPasses(t *testing.T) {
	r, d := evalWritableDirs("systemd unit", map[string]fs.FileMode{
		"/etc/systemd/system": 0o755,
	}, "runs as root at boot")
	wantResult(t, r, "pass", d)
}

func TestEvalWritableDirs_NoneReadableIsWithheld(t *testing.T) {
	r, d := evalWritableDirs("systemd unit", nil, "runs as root at boot")
	wantResult(t, r, "skipped", d)
}

// Section A's launchd check delegates to the shared evaluator, so its
// behaviour must not have shifted.
func TestEvalLaunchDirPerms_StillDelegatesCorrectly(t *testing.T) {
	r, d := evalLaunchDirPerms(map[string]fs.FileMode{"/Library/LaunchAgents": 0o775})
	wantResult(t, r, "fail", d)
	if !strings.Contains(d, "LaunchAgents") {
		t.Errorf("details must still name the directory, got %q", d)
	}
}

// ---------------------------------------------------------------------------
// Cross-cutting
// ---------------------------------------------------------------------------

func TestSectionBEvaluators_ProduceOnlyKnownVerdicts(t *testing.T) {
	valid := map[string]bool{"pass": true, "fail": true, "skipped": true}
	var got []string
	r, _ := evalCredentialFiles(nil, 0)
	got = append(got, r)
	r, _ = evalRemoteAccessSoftware(nil)
	got = append(got, r)
	r, _ = evalTrustStore(nil, true)
	got = append(got, r)
	r, _ = evalWritableDirs("x", nil, "y")
	got = append(got, r)
	for i, v := range got {
		if !valid[v] {
			t.Errorf("evaluator %d returned %q, outside pass|fail|skipped", i, v)
		}
	}
}
