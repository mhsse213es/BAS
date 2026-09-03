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
	// Exactly the domains shipped profiles declare, per
	// orchestrator/internal/scenario/resource.go.
	for _, d := range []string{"registry", "process", "network", "wmi-secpolicy"} {
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

// filesystem is keyed rather than whole-domain: no shipped profile declares it,
// and it is where per-atomic keys earn their keep — two atomics writing distinct
// temp paths should overlap, two writing the same fixed path must not.
func TestLookupDomain_FilesystemIsKeyed(t *testing.T) {
	kind, ok := LookupDomain("filesystem")
	if !ok || kind != KindKeyed {
		t.Errorf("filesystem kind = %v ok=%v, want KindKeyed", kind, ok)
	}
}

// The agent runs on Windows as well as POSIX, so absolute Windows paths must
// canonicalise. NTFS is case-insensitive, so spellings must fold to one key or
// they would not conflict.
func TestCanonicaliseKey_WindowsAbsolutePaths(t *testing.T) {
	a, okA := CanonicaliseKey("filesystem", "C:\\temp")
	b, okB := CanonicaliseKey("filesystem", "c:/Temp/")
	if !okA || !okB {
		t.Fatalf("expected both Windows spellings to canonicalise, got ok=%v/%v", okA, okB)
	}
	if a != b {
		t.Errorf("case/separator variants produced different keys: %q vs %q", a, b)
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
