package sched

import "testing"

func serialLockSet(reqs []lockReq) bool { return isFullySerial(keyMode(reqs)) }

// A declaration the agent cannot verify must escalate to the exclusive global
// barrier, never to a domain-level lock and never be trusted as written.
//
// Validation runs HERE, at the lock boundary, rather than only server-side where
// profiles are authored: profiles cross a version boundary, and trusting a key
// this build cannot parse would make the core invariant a property of version
// alignment instead of a property of the enforcement point.
func TestResolve_EscalatesInvalidDeclarations(t *testing.T) {
	cases := []struct {
		name string
		p    *ResourceProfile
	}{
		{"unregistered domain", &ResourceProfile{
			Domains: []ResourceLock{{Domain: "nonsense"}}, Scope: "local", Risk: RiskObservation}},
		{"keyed access to a whole-domain domain", &ResourceProfile{
			Domains: []ResourceLock{{Domain: "process", Key: "1234"}}, Scope: "local", Risk: RiskObservation}},
		{"one bad resource among good ones", &ResourceProfile{
			Domains: []ResourceLock{{Domain: "process"}, {Domain: "nonsense"}},
			Scope:   "local", Risk: RiskObservation}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := resolve(c.p)
			if !serialLockSet(got) {
				t.Errorf("invalid declaration must escalate to the exclusive global barrier, got %v", keyMode(got))
			}
		})
	}
}

// Today's shipped shape must keep its shared per-domain lock, or the existing
// parallelism regresses.
func TestResolve_WholeDomainObservationStaysShared(t *testing.T) {
	got := resolve(&ResourceProfile{
		Domains: []ResourceLock{{Domain: "process"}}, Scope: "local", Risk: RiskObservation})
	if serialLockSet(got) {
		t.Fatal("a whole-domain observation must not serialize; that is today's behaviour")
	}
	if !hasLock(got, "process", false) {
		t.Errorf("want a shared lock on \"process\", got %v", keyMode(got))
	}
}

// Escalation must not drop the footprint barrier — an escalated step still
// perturbs the surface, so an observer must still exclude it.
func TestResolve_EscalationKeepsFootprintHold(t *testing.T) {
	got := resolve(&ResourceProfile{
		Domains: []ResourceLock{{Domain: "nonsense"}}, Scope: "local", Risk: RiskObservation})
	if !hasLock(got, footprintKey, false) {
		t.Errorf("escalated step must still hold %s shared, got %v", footprintKey, keyMode(got))
	}
}
