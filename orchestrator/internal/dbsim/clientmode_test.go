package dbsim

import (
	"sort"
	"strings"
	"testing"
)

// clientIn builds an AuthInput for a client-mode dispatch with the given gate.
func clientIn(g ClientModeGate) AuthInput {
	i := in(false, false)
	i.ClientGate = g
	return i
}

func TestClientModeRefusedWhenSettingOff(t *testing.T) {
	tg := goodTarget(ModeClient)
	// Fail closed: no gate injected, a gate saying off, and a gate that panics
	// are all refusals; only an explicit "on" lets the dispatch through.
	if err := Authorize(tg, roEntry(), clientIn(nil)); err == nil {
		t.Fatal("client mode with no gate injected must be refused (fail closed)")
	}
	if err := Authorize(tg, roEntry(), clientIn(StaticClientGate(false))); err == nil {
		t.Fatal("client mode with the setting off must be refused")
	}
	if err := Authorize(tg, roEntry(), clientIn(ClientGateFunc(func() bool { panic("settings store down") }))); err == nil {
		t.Fatal("a gate that fails must be treated as OFF")
	}
	if err := Authorize(tg, roEntry(), clientIn(StaticClientGate(true))); err != nil {
		t.Fatalf("setting on + verified identity + registered identity must pass: %v", err)
	}
}

func TestClientModeRequiresPassedIdentityCheckAndRegisteredIdentity(t *testing.T) {
	on := StaticClientGate(true)
	tg := goodTarget(ModeClient)
	tg.ReadOnlyIdentityVerified = false
	if err := Authorize(tg, roEntry(), clientIn(on)); err == nil {
		t.Fatal("a target without a PASSED read-only identity check must be refused")
	}
	for _, id := range []string{"", " ", "\t\n"} {
		tg = goodTarget(ModeClient)
		tg.ExpectedIdentity = id
		if err := Authorize(tg, roEntry(), clientIn(on)); err == nil {
			t.Fatalf("expected identity %q supplied at registration is required (R6: no trust on first use)", id)
		}
	}
}

// Exactly these probes may run in client mode; everything else is refused.
// A new probe must be added here deliberately.
var clientAllowedProbes = []string{
	"auth_check", "check_readonly_identity", "read_audit_config", "read_grants", "read_restricted_table", "read_roles",
}

func TestClientModeAllowedProbeSetIsExact(t *testing.T) {
	var got []string
	for _, id := range ProbeIDs() {
		e, _ := LookupProbeEntry(id)
		tg := goodTarget(ModeClient)
		tg.LabConfirmed = false
		err := Authorize(tg, e, clientIn(StaticClientGate(true)))
		if err == nil {
			got = append(got, id)
			if e.Class != ClassReadOnly || e.LabOnly || e.FixtureParam != "" || e.RequiredFixture != "" {
				t.Errorf("probe %q was allowed in client mode but is not a plain read-only probe", id)
			}
			continue
		}
		if !strings.Contains(err.Error(), "authorize") {
			t.Errorf("probe %q refusal not from Authorize: %v", id, err)
		}
		// The refusal must hold with the gate on, the identity verified and lab
		// approvals present: no flag combination unlocks it in client mode.
		tg.LabConfirmed = true
		i := clientIn(StaticClientGate(true))
		i.MutationApproved, i.Fixture = true, e.FixtureParam != "" || e.RequiredFixture != ""
		if Authorize(tg, e, i) == nil {
			t.Errorf("probe %q must stay refused in client mode even with lab approvals", id)
		}
	}
	sort.Strings(got)
	want := append([]string(nil), clientAllowedProbes...)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("client-mode probe set\n got  %v\n want %v", got, want)
	}
}
