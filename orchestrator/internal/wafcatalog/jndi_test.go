package wafcatalog

import (
	"regexp"
	"strings"
	"testing"
)

var jndiHostPattern = regexp.MustCompile(`://([^/}\s]+)`)

func jndiVectors(t *testing.T) []AttackVector {
	t.Helper()
	return inFamily(depthCatalog(t), FamilyJNDIInjection)
}

// Positive: the family exists with its three vectors, and each carries CVE provenance and a benign twin.
func TestJNDI_FamilyHasThreeCatalogEntriesWithProvenance(t *testing.T) {
	vs := jndiVectors(t)
	if len(vs) != 3 {
		t.Fatalf("JNDI family has %d vectors, want 3", len(vs))
	}
	for _, v := range vs {
		if !strings.Contains(v.Provenance, "CVE-2021-44228") {
			t.Errorf("%s provenance does not cite the advisory: %q", v.ID, v.Provenance)
		}
		if !strings.Contains(v.Provenance, "catalog-only") {
			t.Errorf("%s provenance does not state the catalog-only restriction", v.ID)
		}
		if v.BenignCounterpart == nil {
			t.Errorf("%s has no benign counterpart", v.ID)
		}
	}
}

// Negative: every JNDI callback host must be the reserved canary name. A payload pointing anywhere else fails here.
func TestJNDI_EveryPayloadCallsBackOnlyToTheReservedCanary(t *testing.T) {
	for _, v := range jndiVectors(t) {
		m := jndiHostPattern.FindStringSubmatch(v.Malicious.Payload)
		if m == nil {
			t.Errorf("%s payload has no protocol host: %q", v.ID, v.Malicious.Payload)
			continue
		}
		if m[1] != jndiCanaryHost {
			t.Errorf("%s calls back to %q, want only %q", v.ID, m[1], jndiCanaryHost)
		}
	}
}

// Negative: the family must not carry an executable probe. A probe would need a runner, a listener or a real callback
// target, so refuse any reference to them.
func TestJNDI_NoExecutionOrCallbackMachineryInTheFamily(t *testing.T) {
	for _, v := range jndiVectors(t) {
		for _, s := range []string{v.Malicious.Payload, v.BenignCounterpart.Payload, v.Malicious.Path} {
			for _, bad := range []string{"rmi:", "iiop:", "http://", "https://", "exec", "curl", "wget", "nc "} {
				if strings.Contains(strings.ToLower(s), bad) {
					t.Errorf("%s contains %q, which is outside the catalog-only scope: %q", v.ID, bad, s)
				}
			}
		}
	}
}

// Negative: the benign twin of a JNDI vector must not itself contain a lookup expression.
func TestJNDI_BenignTwinsAreNotLookups(t *testing.T) {
	for _, v := range jndiVectors(t) {
		if strings.Contains(v.BenignCounterpart.Payload, "${") {
			t.Errorf("%s benign twin contains a lookup expression: %q", v.ID, v.BenignCounterpart.Payload)
		}
	}
}
