package sched

import "testing"

func TestLookupDomain_UnregisteredIsRejected(t *testing.T) {
	if _, ok := LookupDomain("not-a-real-domain"); ok {
		t.Error("unregistered domain must not resolve; it has to escalate to the global barrier")
	}
}

// Every profile shipped today is observe(domain) with no Key, so every domain
// must stay whole-domain. Registering one as keyed would make today's
// declarations invalid and silently serialize them.
func TestLookupDomain_CurrentDomainsAreWholeDomain(t *testing.T) {
	// The exact set in orchestrator/internal/scenario/resource.go.
	for _, d := range []string{"registry", "filesystem", "process", "network", "wmi-secpolicy"} {
		kind, ok := LookupDomain(d)
		if !ok {
			t.Errorf("domain %q is not registered", d)
			continue
		}
		if kind != KindWholeDomain {
			t.Errorf("domain %q kind = %v, want KindWholeDomain (today's profiles address it whole)", d, kind)
		}
	}
}

func TestCanonicaliseKey_RejectsUnstableForms(t *testing.T) {
	for _, k := range []string{"", "relative/path", "/etc/../etc/foo", "%TEMP%/x", "$HOME/x"} {
		if got, ok := CanonicaliseKey("filesystem", k); ok {
			t.Errorf("CanonicaliseKey(filesystem, %q) = %q, ok — a key with no stable identity must be rejected", k, got)
		}
	}
}

func TestCanonicaliseKey_NormalisesEquivalentSpellings(t *testing.T) {
	a, okA := CanonicaliseKey("filesystem", "/tmp/a")
	b, okB := CanonicaliseKey("filesystem", "/tmp/./a/")
	if !okA || !okB {
		t.Fatalf("expected both spellings to canonicalise, got ok=%v/%v", okA, okB)
	}
	if a != b {
		t.Errorf("equivalent paths produced different keys: %q vs %q — they would not conflict", a, b)
	}
}
