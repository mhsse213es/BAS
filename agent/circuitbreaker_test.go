package main

import (
	"testing"

	"audspect/agent/sched"
)

func TestCircuitBreaker_OpensAfterConsecutiveFailures(t *testing.T) {
	b := newCircuitBreaker(3)
	if b.isOpen("technique:T1055") {
		t.Fatal("breaker should start closed")
	}
	if justOpened := b.recordOutcome("technique:T1055", false); justOpened {
		t.Fatal("1st of 3 failures should not report a just-opened transition")
	}
	if justOpened := b.recordOutcome("technique:T1055", false); justOpened {
		t.Fatal("2nd of 3 failures should not report a just-opened transition")
	}
	if b.isOpen("technique:T1055") {
		t.Fatal("breaker should still be closed after only 2 of 3 failures")
	}
	if justOpened := b.recordOutcome("technique:T1055", false); !justOpened {
		t.Fatal("3rd failure should report the just-opened transition")
	}
	if !b.isOpen("technique:T1055") {
		t.Fatal("breaker should be open after 3 consecutive failures")
	}
}

func TestCircuitBreaker_RecordOutcomeOnlyReportsTransitionOnce(t *testing.T) {
	b := newCircuitBreaker(3)
	b.recordOutcome("technique:T1055", false)
	b.recordOutcome("technique:T1055", false)
	b.recordOutcome("technique:T1055", false) // opens here
	if justOpened := b.recordOutcome("technique:T1055", false); justOpened {
		t.Fatal("a failure against an already-open key must not report another transition")
	}
}

func TestCircuitBreaker_SuccessResetsConsecutiveCount(t *testing.T) {
	b := newCircuitBreaker(3)
	b.recordOutcome("domain:registry", false)
	b.recordOutcome("domain:registry", false)
	b.recordOutcome("domain:registry", true) // resets
	b.recordOutcome("domain:registry", false)
	b.recordOutcome("domain:registry", false)
	if b.isOpen("domain:registry") {
		t.Fatal("breaker should still be closed -- only 2 consecutive failures since the reset")
	}
	b.recordOutcome("domain:registry", false)
	if !b.isOpen("domain:registry") {
		t.Fatal("breaker should be open after 3 consecutive failures since the reset")
	}
}

func TestCircuitBreaker_KeysAreIndependent(t *testing.T) {
	b := newCircuitBreaker(3)
	b.recordOutcome("technique:T1055", false)
	b.recordOutcome("technique:T1055", false)
	b.recordOutcome("technique:T1055", false)
	if !b.isOpen("technique:T1055") {
		t.Fatal("technique:T1055 should be open")
	}
	if b.isOpen("domain:registry") {
		t.Fatal("domain:registry should be unaffected by technique:T1055's failures")
	}
}

func TestCircuitBreaker_AnyOpenBlocksIfAnyKeyOpen(t *testing.T) {
	b := newCircuitBreaker(3)
	b.recordOutcome("technique:T1055", false)
	b.recordOutcome("technique:T1055", false)
	b.recordOutcome("technique:T1055", false)
	if !b.anyOpen([]string{"domain:registry", "technique:T1055", "domain:filesystem"}) {
		t.Fatal("anyOpen should be true -- technique:T1055 is open even though the others aren't")
	}
	if b.anyOpen([]string{"domain:registry", "domain:filesystem"}) {
		t.Fatal("anyOpen should be false -- neither of these keys is open")
	}
}

func TestBreakerKeysForStep(t *testing.T) {
	cases := []struct {
		name string
		id   string
		p    *sched.ResourceProfile
		want []string
	}{
		{"nil profile", "T1055", nil, []string{"technique:T1055"}},
		{"empty domains", "T1055", &sched.ResourceProfile{}, []string{"technique:T1055"}},
		{"two domains", "T1055", &sched.ResourceProfile{Domains: []sched.ResourceLock{{Domain: "registry"}, {Domain: "filesystem"}}},
			[]string{"technique:T1055", "domain:registry", "domain:filesystem"}},
	}
	for _, c := range cases {
		got := breakerKeysForStep(c.id, c.p)
		if len(got) != len(c.want) {
			t.Fatalf("%s: breakerKeysForStep() = %v, want %v", c.name, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("%s: breakerKeysForStep() = %v, want %v", c.name, got, c.want)
			}
		}
	}
}
