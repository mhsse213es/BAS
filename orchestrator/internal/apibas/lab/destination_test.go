package lab

import "testing"

func TestNormalizeDestination(t *testing.T) {
	cases := map[string]string{
		"https://Hooks.Partner.Example/cb":  "https://hooks.partner.example:443",
		"HTTP://Attacker.Example:8080/steal": "http://attacker.example:8080",
		"https://attacker.example":           "https://attacker.example:443",
		"/orders/ORD-2001":                   "", // relative: same origin, no destination
	}
	for raw, want := range cases {
		got, err := normalizeDestination(raw)
		if err != nil {
			t.Fatalf("%q: %v", raw, err)
		}
		if got != want {
			t.Errorf("normalizeDestination(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestDestinationPolicyByKind(t *testing.T) {
	cases := []struct {
		name, kind, raw, want string
	}{
		{"relative redirect stays on this origin", DestRedirect, "/orders/ORD-2001", PolicyAllowed},
		{"absolute redirect off this origin", DestRedirect, "https://attacker.example/phish", PolicyOutside},
		{"allowlisted callback host", DestCallback, "https://hooks.partner.example/cb", PolicyAllowed},
		{"callback host not allowlisted", DestCallback, "https://attacker.example/cb", PolicyOutside},
		{"callback to a loopback address", DestCallback, "http://127.0.0.1/cb", PolicyInternal},
		{"webhook test to a public host (no allowlist: not a violation)", DestWebhook, "https://example.org/hook", PolicyAllowed},
		{"webhook test to a private address", DestWebhook, "http://10.0.0.5/admin", PolicyInternal},
		{"webhook test to the metadata address", DestWebhook, "http://169.254.169.254/latest/meta-data", PolicyInternal},
		{"webhook test to localhost", DestWebhook, "http://localhost:8080/", PolicyInternal},
	}
	for _, c := range cases {
		if got := DestinationPolicy(c.kind, c.raw); got != c.want {
			t.Errorf("%s: DestinationPolicy(%s, %q) = %q, want %q", c.name, c.kind, c.raw, got, c.want)
		}
	}
}

func TestDestinationPolicyUnknownKindIsNotEvaluated(t *testing.T) {
	if got := DestinationPolicy("upstream", "https://rogue.example/"); got != policyNotEvaled {
		t.Errorf("a kind with no policy got verdict %q; it must stay unevaluated", got)
	}
}
