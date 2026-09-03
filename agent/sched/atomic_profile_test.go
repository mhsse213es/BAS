package sched

import "testing"

// The case a single Risk cannot express: reads one domain, writes another.
// Under Risk=observation the write is under-locked (unsafe); under
// Risk=modification the read is over-locked (safe but needlessly serial).
func TestResolve_SplitReadWriteSets(t *testing.T) {
	got := resolve(&ResourceProfile{
		Reads:  []ResourceLock{{Domain: "process"}},
		Writes: []ResourceLock{{Domain: "network"}},
	})
	if !hasLock(got, "process", false) {
		t.Errorf("declared read must take a SHARED lock, got %v", keyMode(got))
	}
	if !hasLock(got, "network", true) {
		t.Errorf("declared write must take an EXCLUSIVE lock, got %v", keyMode(got))
	}
	if serialLockSet(got) {
		t.Error("a fully declared profile must not fall back to the global barrier")
	}
}

// Writes dominate reads of the same resource: one exclusive hold, never a shared
// and an exclusive hold on the same key.
func TestResolve_WriteDominatesReadOfSameResource(t *testing.T) {
	got := resolve(&ResourceProfile{
		Reads:  []ResourceLock{{Domain: "network"}},
		Writes: []ResourceLock{{Domain: "network"}},
	})
	if hasLock(got, "network", false) {
		t.Error("must not hold the same resource shared AND exclusive")
	}
	if !hasLock(got, "network", true) {
		t.Errorf("the write must dominate, got %v", keyMode(got))
	}
}

// The payoff: two atomics writing distinct keys in a keyed domain overlap.
func TestResolve_DistinctKeyedWritesDoNotConflict(t *testing.T) {
	a := keyMode(resolve(&ResourceProfile{Writes: []ResourceLock{{Domain: "filesystem", Key: "/tmp/a"}}}))
	b := keyMode(resolve(&ResourceProfile{Writes: []ResourceLock{{Domain: "filesystem", Key: "/tmp/b"}}}))

	for k, aw := range a {
		if k == footprintKey || k == globalKey {
			continue
		}
		if bw, both := b[k]; both && (aw || bw) {
			t.Errorf("distinct keyed writes must not conflict; both hold %q (a write=%v, b write=%v)", k, aw, bw)
		}
	}
	if !hasLock(resolve(&ResourceProfile{Writes: []ResourceLock{{Domain: "filesystem", Key: "/tmp/a"}}}),
		"filesystem//tmp/a", true) {
		t.Error("expected an exclusive lock on the canonical keyed path")
	}
}

// And two atomics writing the SAME fixed path must serialize — the collision
// that otherwise produces an error a control-block signature can misread as a
// security outcome.
func TestResolve_SameKeyedWriteConflicts(t *testing.T) {
	a := resolve(&ResourceProfile{Writes: []ResourceLock{{Domain: "filesystem", Key: "/tmp/T1234.txt"}}})
	b := resolve(&ResourceProfile{Writes: []ResourceLock{{Domain: "filesystem", Key: "/tmp/./T1234.txt"}}})

	const want = "filesystem//tmp/T1234.txt"
	if !hasLock(a, want, true) || !hasLock(b, want, true) {
		t.Errorf("equivalent spellings must resolve to the same exclusive key %q:\n a=%v\n b=%v",
			want, keyMode(a), keyMode(b))
	}
}

// An invalid resource anywhere in either set condemns the whole profile.
func TestResolve_InvalidInReadsOrWritesEscalates(t *testing.T) {
	for name, p := range map[string]*ResourceProfile{
		"bad read":  {Reads: []ResourceLock{{Domain: "nonsense"}}, Writes: []ResourceLock{{Domain: "process"}}},
		"bad write": {Reads: []ResourceLock{{Domain: "process"}}, Writes: []ResourceLock{{Domain: "process", Key: "1234"}}},
	} {
		if !serialLockSet(resolve(p)) {
			t.Errorf("%s: must escalate to the global barrier, got %v", name, keyMode(resolve(p)))
		}
	}
}

// Legacy Domains/Risk profiles keep working unchanged while atomics are migrated.
func TestResolve_LegacyProfileStillHonoured(t *testing.T) {
	got := resolve(&ResourceProfile{
		Domains: []ResourceLock{{Domain: "process"}}, Scope: "local", Risk: RiskObservation,
	})
	if !hasLock(got, "process", false) {
		t.Errorf("legacy observation profile must still take a shared lock, got %v", keyMode(got))
	}
}
