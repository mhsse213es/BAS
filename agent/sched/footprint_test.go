package sched

import "testing"

func hasLock(reqs []lockReq, key string, write bool) bool {
	for _, r := range reqs {
		if r.key == key && r.write == write {
			return true
		}
	}
	return false
}

// Ordinary atomics take a SHARED footprint hold so they stay compatible with
// each other. If this were exclusive, every pair of atomics would conflict on
// the barrier and no two could ever overlap -- the whole parallelism feature
// silently disabled while still looking correct.
func TestFootprint_OrdinaryStepTakesSharedHold(t *testing.T) {
	reqs := resolve(&ResourceProfile{
		Domains: []ResourceLock{{Domain: "process"}}, Scope: "local", Risk: RiskObservation,
	})
	if !hasLock(reqs, footprintKey, false) {
		t.Errorf("ordinary step must hold %s SHARED, got %+v", footprintKey, reqs)
	}
	if hasLock(reqs, footprintKey, true) {
		t.Error("ordinary step must NOT hold the footprint exclusively — that serializes everything")
	}
}

// A footprint observer needs the surface quiet, so it takes the EXCLUSIVE hold.
func TestFootprint_ObserverTakesExclusiveHold(t *testing.T) {
	reqs := resolve(&ResourceProfile{
		Domains: []ResourceLock{{Domain: "process"}}, Scope: "local", Risk: RiskObservation,
		ObservesFootprint: true,
	})
	if !hasLock(reqs, footprintKey, true) {
		t.Errorf("footprint observer must hold %s EXCLUSIVE, got %+v", footprintKey, reqs)
	}
	if hasLock(reqs, footprintKey, false) {
		t.Error("observer must not also hold it shared")
	}
}

// The polarity guard. Fails loudly if anyone re-derives the barrier as ordinary
// read/write semantics ("everyone writes it, the observer reads it"), which
// inverts both modes and disables parallelism entirely.
func TestFootprint_TwoOrdinaryStepsDoNotConflictOnFootprint(t *testing.T) {
	a := resolve(&ResourceProfile{Domains: []ResourceLock{{Domain: "process"}}, Scope: "local", Risk: RiskObservation})
	b := resolve(&ResourceProfile{Domains: []ResourceLock{{Domain: "network"}}, Scope: "local", Risk: RiskObservation})
	if hasLock(a, footprintKey, true) || hasLock(b, footprintKey, true) {
		t.Fatal("two ordinary steps must be able to overlap on the footprint barrier")
	}
}

// Even a fully-serial step participates in the barrier, shared -- so an observer
// still excludes it. Without this an unlabeled step could run alongside an
// observer and contaminate its evidence.
func TestFootprint_UnlabeledStepStillParticipates(t *testing.T) {
	if !hasLock(resolve(nil), footprintKey, false) {
		t.Errorf("unlabeled step must still hold %s SHARED, got %+v", footprintKey, resolve(nil))
	}
}
