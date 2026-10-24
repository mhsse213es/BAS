package dbsim

import (
	"strings"
	"testing"
	"time"
)

// registerTestEntry temporarily adds a probe to the registry so non-read-only
// classes can be exercised. Test-only and unexported; removed on cleanup.
func registerTestEntry(t *testing.T, id string, class ProbeClass) ProbeRegistryEntry {
	t.Helper()
	if _, exists := probeRegistry[id]; exists {
		t.Fatalf("test probe %q collides with a real probe", id)
	}
	e := ProbeRegistryEntry{ID: id, Class: class, Engines: []string{"postgresql", "mysql"}, ParamSchema: map[string]string{}}
	probeRegistry[id] = e
	t.Cleanup(func() { delete(probeRegistry, id) })
	return e
}

func goodTarget(mode ExecMode) Target {
	return Target{ID: "t1", Engine: "postgresql", Host: "10.0.0.5", Port: 5432, Mode: mode,
		ExpectedIdentity: "7001", ReadOnlyIdentityVerified: true, LabConfirmed: true, AgentID: "0123456789abcdef"}
}

func roEntry() ProbeRegistryEntry {
	e, _ := LookupProbeEntry("read_roles")
	return e
}

var fixedNow = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

func in(clientEnabled, mutationApproved bool) AuthInput {
	return AuthInput{ClientGate: StaticClientGate(clientEnabled), MutationApproved: mutationApproved,
		RunExpiry: fixedNow.Add(time.Hour), Now: fixedNow}
}

func TestAuthorizeRefusesClientModeWhenDisabled(t *testing.T) {
	if err := Authorize(goodTarget(ModeClient), roEntry(), in(false, true)); err == nil {
		t.Fatal("client mode must be refused when disabled")
	}
	if err := Authorize(goodTarget(ModeClient), roEntry(), in(true, false)); err != nil {
		t.Fatalf("enabled + verified read-only client must pass: %v", err)
	}
}

func TestAuthorizeClientModeRequiresVerifiedReadOnlyIdentity(t *testing.T) {
	tg := goodTarget(ModeClient)
	tg.ReadOnlyIdentityVerified = false
	if err := Authorize(tg, roEntry(), in(true, false)); err == nil {
		t.Fatal("unverified read-only identity must be refused")
	}
	tg = goodTarget(ModeClient)
	tg.ExpectedIdentity = ""
	if err := Authorize(tg, roEntry(), in(true, false)); err == nil {
		t.Fatal("client mode must not be trust-on-first-use")
	}
}

func TestAuthorizeRejectsEmptyIdentityInLabMode(t *testing.T) {
	tg := goodTarget(ModeLab)
	tg.ExpectedIdentity = ""
	if err := Authorize(tg, roEntry(), in(false, true)); err == nil {
		t.Fatal("lab target without registered identity must be refused")
	}
}

func TestAuthorizeRejectsUnknownProbeInEveryMode(t *testing.T) {
	forged := ProbeRegistryEntry{ID: "x", Class: ClassReadOnly, Engines: []string{"postgresql"}}
	for _, m := range []ExecMode{ModeLab, ModeClient} {
		if err := Authorize(goodTarget(m), forged, in(true, true)); err == nil {
			t.Fatalf("forged unknown probe must be refused in %s mode", m)
		}
	}
}

func TestAuthorizeClientModeRejectsMutationAndBoundedByRealClass(t *testing.T) {
	for _, class := range []ProbeClass{ClassMutation, ClassBoundedSynthetic} {
		real := registerTestEntry(t, "t_c_"+string(class), class)
		err := Authorize(goodTarget(ModeClient), real, in(true, true))
		if err == nil || !strings.Contains(err.Error(), string(class)) {
			t.Fatalf("want %s rejection citing class, got %v", class, err)
		}
		// Mislabel: entry claims read_only for a probe whose registry class is not.
		label := real
		label.Class = ClassReadOnly
		if err := Authorize(goodTarget(ModeClient), label, in(true, true)); err == nil {
			t.Fatalf("mislabelled %s entry must be refused", class)
		}
	}
}

func TestAuthorizeLabModeNonReadOnlyNeedsLabConfirmedAndApproval(t *testing.T) {
	for _, class := range []ProbeClass{ClassMutation, ClassBoundedSynthetic} {
		e := registerTestEntry(t, "t_l_"+string(class), class)
		unconfirmed := goodTarget(ModeLab)
		unconfirmed.LabConfirmed = false
		if err := Authorize(unconfirmed, e, in(false, true)); err == nil {
			t.Fatalf("%s on unconfirmed lab target must be refused", class)
		}
		if err := Authorize(goodTarget(ModeLab), e, in(false, false)); err == nil {
			t.Fatalf("%s without scenario approval must be refused", class)
		}
		if err := Authorize(goodTarget(ModeLab), e, in(false, true)); err != nil {
			t.Fatalf("%s with lab confirmation and approval must pass: %v", class, err)
		}
	}
	// read_only in lab needs neither.
	tg := goodTarget(ModeLab)
	tg.LabConfirmed = false
	if err := Authorize(tg, roEntry(), in(false, false)); err != nil {
		t.Fatalf("read-only lab probe needs only identity: %v", err)
	}
}

func TestAuthorizeRefusesInvalidMode(t *testing.T) {
	for _, m := range []ExecMode{"", "prod"} {
		if err := Authorize(goodTarget(m), roEntry(), in(true, true)); err == nil {
			t.Fatalf("mode %q must be refused", m)
		}
	}
}

func TestAuthorizeRefusesExpiredRun(t *testing.T) {
	i := in(false, false)
	i.RunExpiry = fixedNow.Add(-time.Second)
	if err := Authorize(goodTarget(ModeLab), roEntry(), i); err == nil {
		t.Fatal("expired run must be refused")
	}
	i.RunExpiry = fixedNow
	if err := Authorize(goodTarget(ModeLab), roEntry(), i); err == nil {
		t.Fatal("run expiring exactly now must be refused")
	}
	i.RunExpiry = time.Time{}
	if err := Authorize(goodTarget(ModeLab), roEntry(), i); err == nil {
		t.Fatal("zero expiry must be refused (no unbounded runs)")
	}
}

func TestAuthorizeRefusesUnsupportedEngine(t *testing.T) {
	tg := goodTarget(ModeLab)
	tg.Engine = "oracle"
	if err := Authorize(tg, roEntry(), in(false, false)); err == nil {
		t.Fatal("engine not supported by probe must be refused")
	}
}
