package waforigin

import "testing"

func TestWeaknessType_Kind_MapsAllFiveKnownValues(t *testing.T) {
	cases := []struct {
		weakness WeaknessType
		want     WeaknessKind
	}{
		{WeaknessRoutingCoverageGap, KindBypassPair},
		{WeaknessDirectOriginReachability, KindBypassPair},
		{WeaknessFailOpenOnUnavailability, KindBypassPair},
		{WeaknessTLSProxyBehavior, KindProtocolClaim},
		{WeaknessConfigurationConsistency, KindCrossNodeConsistency},
	}
	for _, c := range cases {
		if got := c.weakness.Kind(); got != c.want {
			t.Errorf("%q.Kind() = %q, want %q", c.weakness, got, c.want)
		}
	}
}

func TestWeaknessType_Kind_UnknownValueReturnsEmpty(t *testing.T) {
	if got := WeaknessType("bogus_weakness").Kind(); got != "" {
		t.Errorf("Kind() for unknown WeaknessType = %q, want \"\"", got)
	}
}
