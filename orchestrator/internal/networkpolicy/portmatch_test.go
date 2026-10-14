package networkpolicy

import "testing"

func TestParsePortRange_EmptyMatchesAny(t *testing.T) {
	matchAny, _, _, err := ParsePortRange("")
	if err != nil {
		t.Fatalf("ParsePortRange: %v", err)
	}
	if !matchAny {
		t.Fatal("want matchAny true for an empty PortRange")
	}
}

func TestParsePortRange_BareNumberMatchesExactOnly(t *testing.T) {
	matchAny, low, high, err := ParsePortRange("443")
	if err != nil {
		t.Fatalf("ParsePortRange: %v", err)
	}
	if matchAny || low != 443 || high != 443 {
		t.Fatalf("got matchAny=%v low=%d high=%d, want matchAny=false low=443 high=443", matchAny, low, high)
	}
}

func TestParsePortRange_RangeParsesInclusiveBounds(t *testing.T) {
	matchAny, low, high, err := ParsePortRange("1024-65535")
	if err != nil {
		t.Fatalf("ParsePortRange: %v", err)
	}
	if matchAny || low != 1024 || high != 65535 {
		t.Fatalf("got matchAny=%v low=%d high=%d, want matchAny=false low=1024 high=65535", matchAny, low, high)
	}
}

func TestParsePortRange_RejectsMalformed(t *testing.T) {
	cases := []string{"abc", "100-abc", "100-50", "0", "70000", "-5", "100-"}
	for _, c := range cases {
		if _, _, _, err := ParsePortRange(c); err == nil {
			t.Errorf("ParsePortRange(%q): want error, got none", c)
		}
	}
}

func TestRule_MatchesPort_EmptyRangeMatchesAnyPort(t *testing.T) {
	r := Rule{PortRange: ""}
	ok, err := r.MatchesPort(1)
	if err != nil || !ok {
		t.Fatalf("MatchesPort(1) = %v, %v; want true, nil", ok, err)
	}
	ok, err = r.MatchesPort(65535)
	if err != nil || !ok {
		t.Fatalf("MatchesPort(65535) = %v, %v; want true, nil", ok, err)
	}
}

func TestRule_MatchesPort_ExactPort(t *testing.T) {
	r := Rule{PortRange: "443"}
	if ok, err := r.MatchesPort(443); err != nil || !ok {
		t.Fatalf("MatchesPort(443) = %v, %v; want true, nil", ok, err)
	}
	if ok, err := r.MatchesPort(444); err != nil || ok {
		t.Fatalf("MatchesPort(444) = %v, %v; want false, nil", ok, err)
	}
}

func TestRule_MatchesPort_RangeInclusiveBoundaries(t *testing.T) {
	r := Rule{PortRange: "1024-65535"}
	if ok, err := r.MatchesPort(1024); err != nil || !ok {
		t.Fatalf("MatchesPort(1024) = %v, %v; want true, nil (lower boundary)", ok, err)
	}
	if ok, err := r.MatchesPort(65535); err != nil || !ok {
		t.Fatalf("MatchesPort(65535) = %v, %v; want true, nil (upper boundary)", ok, err)
	}
	if ok, err := r.MatchesPort(1023); err != nil || ok {
		t.Fatalf("MatchesPort(1023) = %v, %v; want false, nil (just below lower boundary)", ok, err)
	}
	if ok, err := r.MatchesPort(65536); err != nil || ok {
		t.Fatalf("MatchesPort(65536) = %v, %v; want false, nil (just above upper boundary)", ok, err)
	}
}

func TestRule_MatchesPort_MalformedReturnsError(t *testing.T) {
	r := Rule{PortRange: "not-a-port"}
	if _, err := r.MatchesPort(443); err == nil {
		t.Fatal("want error for a malformed PortRange")
	}
}
