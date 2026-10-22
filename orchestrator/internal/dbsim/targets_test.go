package dbsim

import (
	"strings"
	"testing"
	"time"
)

func goodTarget(mode ExecMode) Target {
	return Target{ID: "t1", Engine: "postgresql", Host: "10.0.0.5", Port: 5432, Mode: mode,
		ExpectedIdentity: "7001", ReadOnlyIdentityVerified: true}
}

func roEntry() ProbeRegistryEntry {
	e, _ := LookupProbeEntry("read_roles")
	return e
}

func future() time.Time { return time.Now().Add(time.Hour) }

func TestAuthorizeRefusesClientModeWhenDisabled(t *testing.T) {
	if err := Authorize(goodTarget(ModeClient), roEntry(), false, future()); err == nil {
		t.Fatal("client mode must be refused when disabled")
	}
	if err := Authorize(goodTarget(ModeClient), roEntry(), true, future()); err != nil {
		t.Fatalf("enabled + verified read-only client must pass: %v", err)
	}
}

func TestAuthorizeClientModeRequiresVerifiedReadOnlyIdentity(t *testing.T) {
	tg := goodTarget(ModeClient)
	tg.ReadOnlyIdentityVerified = false
	if err := Authorize(tg, roEntry(), true, future()); err == nil {
		t.Fatal("unverified read-only identity must be refused")
	}
	tg = goodTarget(ModeClient)
	tg.ExpectedIdentity = ""
	if err := Authorize(tg, roEntry(), true, future()); err == nil {
		t.Fatal("client mode must not be trust-on-first-use")
	}
}

func TestAuthorizeClientModeRejectsMutationByRealClass(t *testing.T) {
	mut := ProbeRegistryEntry{ID: "drop_fixture", Class: ClassMutation, Engines: []string{"postgresql"}}
	err := Authorize(goodTarget(ModeClient), mut, true, future())
	if err == nil || !strings.Contains(err.Error(), "mutation") {
		t.Fatalf("want mutation rejection, got %v", err)
	}
	// An entry disagreeing with the registry's class for a known id is refused.
	forged := roEntry()
	forged.Class = ClassMutation
	if err := Authorize(goodTarget(ModeClient), forged, true, future()); err == nil {
		t.Fatal("entry disagreeing with registry class must be refused")
	}
	if err := Authorize(goodTarget(ModeLab), mut, false, future()); err != nil {
		t.Fatalf("lab mode may run mutation class: %v", err)
	}
}

func TestAuthorizeRefusesExpiredRun(t *testing.T) {
	if err := Authorize(goodTarget(ModeLab), roEntry(), false, time.Now().Add(-time.Second)); err == nil {
		t.Fatal("expired run must be refused")
	}
	if err := Authorize(goodTarget(ModeLab), roEntry(), false, time.Time{}); err == nil {
		t.Fatal("zero expiry must be refused (no unbounded runs)")
	}
}

func TestAuthorizeRefusesUnsupportedEngine(t *testing.T) {
	tg := goodTarget(ModeLab)
	tg.Engine = "oracle"
	if err := Authorize(tg, roEntry(), false, future()); err == nil {
		t.Fatal("engine not supported by probe must be refused")
	}
}
