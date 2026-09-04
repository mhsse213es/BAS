package main

import (
	"strings"
	"testing"
)

// Section B, second tranche: recovery readiness, cleartext services, macOS
// consent grants, and the three rows the coverage map marked Constrained --
// removable media, browser credential stores and browser extensions.
//
// The Constrained rows share one rule: when the condition they depend on is
// not met, they report that condition rather than a verdict. An MDM-managed
// restriction this agent cannot see must never be reported as "unrestricted".

// ---------------------------------------------------------------------------
// T1486 / T1490 -- recovery readiness
// ---------------------------------------------------------------------------

func TestEvalBackupMechanism_FoundPasses(t *testing.T) {
	r, d := evalBackupMechanism([]string{"restic (restic running)"}, true)
	wantResult(t, r, "pass", d)
	if !strings.Contains(d, "restic") {
		t.Errorf("details must name the mechanism, got %q", d)
	}
}

// Nothing visible on the endpoint is NOT proof there is no backup. Datacentre
// endpoints are routinely protected at the hypervisor or array level, which
// leaves no trace inside the guest -- so failing here would be wrong on
// exactly the estates most likely to be well protected.
func TestEvalBackupMechanism_NoneVisibleIsWithheld(t *testing.T) {
	r, d := evalBackupMechanism(nil, true)
	wantResult(t, r, "skipped", d)
	low := strings.ToLower(d)
	if !strings.Contains(low, "hypervisor") && !strings.Contains(low, "outside") {
		t.Errorf("details must explain what this cannot see, got %q", d)
	}
}

func TestEvalBackupMechanism_NotDetectableIsWithheld(t *testing.T) {
	r, _ := evalBackupMechanism(nil, false)
	if r != "skipped" {
		t.Errorf("result = %q, want skipped", r)
	}
}

func TestEvalLocalSnapshots_PresentPasses(t *testing.T) {
	r, d := evalLocalSnapshots([]string{"com.apple.TimeMachine.2026-09-04-100000.local"}, true)
	wantResult(t, r, "pass", d)
}

func TestEvalLocalSnapshots_NonePresentFails(t *testing.T) {
	r, d := evalLocalSnapshots(nil, true)
	wantResult(t, r, "fail", d)
	if !strings.Contains(strings.ToLower(d), "no local") {
		t.Errorf("details must say none exist, got %q", d)
	}
}

func TestEvalLocalSnapshots_UndetectableIsWithheld(t *testing.T) {
	r, _ := evalLocalSnapshots(nil, false)
	if r != "skipped" {
		t.Errorf("result = %q, want skipped", r)
	}
}

// ---------------------------------------------------------------------------
// T1048.003 -- cleartext services
// ---------------------------------------------------------------------------

func TestEvalCleartextServices_NoneLoadedPasses(t *testing.T) {
	r, d := evalCleartextServices(nil, true)
	wantResult(t, r, "pass", d)
}

func TestEvalCleartextServices_TelnetLoadedFails(t *testing.T) {
	r, d := evalCleartextServices([]string{"telnet", "ftp"}, true)
	wantResult(t, r, "fail", d)
	for _, w := range []string{"telnet", "ftp"} {
		if !strings.Contains(d, w) {
			t.Errorf("details must name %q, got %q", w, d)
		}
	}
}

func TestParseLaunchctlCleartext_FindsKnownLabels(t *testing.T) {
	out := `-	0	com.apple.telnetd
-	0	com.openssh.sshd
501	0	com.apple.ftpd`
	found := parseLaunchctlCleartext(out)
	if len(found) != 2 {
		t.Fatalf("want telnetd and ftpd, got %v", found)
	}
	joined := strings.Join(found, " ")
	if strings.Contains(joined, "sshd") {
		t.Errorf("ssh is encrypted and must not be flagged: %v", found)
	}
}

// ---------------------------------------------------------------------------
// T1113 / T1056.001 -- macOS consent grants
// ---------------------------------------------------------------------------

func TestEvalTCCGrants_NoGrantsPasses(t *testing.T) {
	r, d := evalTCCGrants("Screen Recording", nil, true)
	wantResult(t, r, "pass", d)
}

func TestEvalTCCGrants_AllowedClientsAreListed(t *testing.T) {
	rows := []tccGrant{
		{Client: "com.evil.recorder", Allowed: true},
		{Client: "com.apple.screensharing", Allowed: true},
		{Client: "com.some.denied", Allowed: false},
	}
	r, d := evalTCCGrants("Screen Recording", rows, true)
	wantResult(t, r, "fail", d)
	if !strings.Contains(d, "com.evil.recorder") {
		t.Errorf("details must name the granted client, got %q", d)
	}
	if strings.Contains(d, "com.some.denied") {
		t.Errorf("a denied client is not a grant: %q", d)
	}
	if !strings.Contains(d, "2") {
		t.Errorf("details must count the grants, got %q", d)
	}
}

// The TCC database is protected. Without Full Disk Access the agent reads
// nothing, which says nothing about what is granted.
func TestEvalTCCGrants_UnreadableIsWithheld(t *testing.T) {
	r, d := evalTCCGrants("Input Monitoring", nil, false)
	wantResult(t, r, "skipped", d)
	if !strings.Contains(d, "Full Disk Access") {
		t.Errorf("details must name the missing permission, got %q", d)
	}
}

func TestParseTCCRows_ReadsClientAndAuthValue(t *testing.T) {
	rows := parseTCCRows("com.evil.recorder|2\ncom.some.denied|0\ncom.other|2\n")
	if len(rows) != 3 {
		t.Fatalf("want 3 rows, got %d", len(rows))
	}
	if !rows[0].Allowed || rows[1].Allowed {
		t.Errorf("auth_value 2 means allowed, 0 means denied: %+v", rows)
	}
}

// ---------------------------------------------------------------------------
// T1091 -- removable media policy
// ---------------------------------------------------------------------------

func TestEvalRemovableMedia_BlockedPasses(t *testing.T) {
	r, d := evalRemovableMediaPolicy("usb-storage blacklisted in /etc/modprobe.d/usb.conf", true)
	wantResult(t, r, "pass", d)
}

// The Constrained contract: an unmet condition is reported as the condition,
// never as "unrestricted".
func TestEvalRemovableMedia_NoPolicyVisibleIsWithheld(t *testing.T) {
	r, d := evalRemovableMediaPolicy("", false)
	wantResult(t, r, "skipped", d)
	if strings.Contains(strings.ToLower(d), "unrestricted") {
		t.Errorf("must not claim the endpoint is unrestricted: %q", d)
	}
}

func TestEvalRemovableMedia_NoPolicyWhenDetectableFails(t *testing.T) {
	r, d := evalRemovableMediaPolicy("", true)
	wantResult(t, r, "fail", d)
}

// ---------------------------------------------------------------------------
// T1555.003 / T1176 -- browser surfaces
// ---------------------------------------------------------------------------

func TestEvalBrowserCredentialStores_NoneFoundIsWithheld(t *testing.T) {
	r, d := evalBrowserCredentialStores(nil, 0)
	wantResult(t, r, "skipped", d)
}

func TestEvalBrowserCredentialStores_StoresPresentIsAFinding(t *testing.T) {
	r, d := evalBrowserCredentialStores(
		[]string{"/Users/asha/Library/Application Support/Google/Chrome/Default/Login Data"}, 1)
	wantResult(t, r, "fail", d)
	if !strings.Contains(d, "Chrome") {
		t.Errorf("details must name the browser profile, got %q", d)
	}
}

func TestEvalBrowserExtensions_NoneIsPass(t *testing.T) {
	r, d := evalBrowserExtensions(0, true)
	wantResult(t, r, "pass", d)
}

func TestEvalBrowserExtensions_CountIsReported(t *testing.T) {
	r, d := evalBrowserExtensions(7, true)
	wantResult(t, r, "fail", d)
	if !strings.Contains(d, "7") {
		t.Errorf("details must state the count, got %q", d)
	}
}

func TestEvalBrowserExtensions_NotScannedIsWithheld(t *testing.T) {
	r, _ := evalBrowserExtensions(0, false)
	if r != "skipped" {
		t.Errorf("result = %q, want skipped", r)
	}
}

// ---------------------------------------------------------------------------
// Cross-cutting
// ---------------------------------------------------------------------------

func TestTrancheTwoEvaluators_ProduceOnlyKnownVerdicts(t *testing.T) {
	valid := map[string]bool{"pass": true, "fail": true, "skipped": true}
	var got []string
	for _, fn := range []func() (string, string){
		func() (string, string) { return evalBackupMechanism(nil, true) },
		func() (string, string) { return evalLocalSnapshots(nil, true) },
		func() (string, string) { return evalCleartextServices(nil, true) },
		func() (string, string) { return evalTCCGrants("x", nil, true) },
		func() (string, string) { return evalRemovableMediaPolicy("", true) },
		func() (string, string) { return evalBrowserCredentialStores(nil, 0) },
		func() (string, string) { return evalBrowserExtensions(0, true) },
	} {
		r, _ := fn()
		got = append(got, r)
	}
	for i, v := range got {
		if !valid[v] {
			t.Errorf("evaluator %d returned %q, outside pass|fail|skipped", i, v)
		}
	}
}
