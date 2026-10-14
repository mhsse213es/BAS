package otsafety

import (
	"testing"

	"github.com/audspect/bas/internal/networktopology"
)

func zonesFixture() []networktopology.Zone {
	return []networktopology.Zone{
		{Name: "corporate", CIDRs: []string{"10.0.1.0/24"}},
		{Name: "ot", CIDRs: []string{"10.0.2.0/24"}},
	}
}

func TestCheckActiveTestAuthorization_TargetInSensitiveZone_NoAuth_Rejected(t *testing.T) {
	topo := &networktopology.TopologyImport{Zones: zonesFixture()}
	safety := &OTSafetyImport{SensitiveZones: []SensitiveZone{{ZoneName: "ot", Tier: TierOT}}}
	_, err := CheckActiveTestAuthorization([]string{"10.0.2.5"}, topo, safety, nil)
	if err == nil {
		t.Fatal("want an error -- a target in a declared sensitive zone with no authorization must be rejected")
	}
}

func TestCheckActiveTestAuthorization_TargetInSensitiveZone_AuthorizedWithSignOff_Accepted(t *testing.T) {
	topo := &networktopology.TopologyImport{Zones: zonesFixture()}
	safety := &OTSafetyImport{SensitiveZones: []SensitiveZone{{ZoneName: "ot", Tier: TierOT}}}
	matched, err := CheckActiveTestAuthorization([]string{"10.0.2.5"}, topo, safety, &ActiveTestAuthorization{Authorized: true, SignOff: "approved by J.Singh, CHG-1234"})
	if err != nil {
		t.Fatalf("want no error with a valid authorization, got %v", err)
	}
	if len(matched) != 1 || matched[0] != "ot" {
		t.Fatalf("matchedZones = %v, want [\"ot\"]", matched)
	}
}

func TestCheckActiveTestAuthorization_AuthorizedButEmptySignOff_Rejected(t *testing.T) {
	topo := &networktopology.TopologyImport{Zones: zonesFixture()}
	safety := &OTSafetyImport{SensitiveZones: []SensitiveZone{{ZoneName: "ot", Tier: TierOT}}}
	_, err := CheckActiveTestAuthorization([]string{"10.0.2.5"}, topo, safety, &ActiveTestAuthorization{Authorized: true, SignOff: ""})
	if err == nil {
		t.Fatal("want an error -- Authorized alone is not sufficient, SignOff must be non-empty")
	}
}

// TestCheckActiveTestAuthorization_UnresolvableTarget_FailsOpen pins
// Review Focus #2: a target that does not resolve to any declared
// zone at all must never be gated.
func TestCheckActiveTestAuthorization_UnresolvableTarget_FailsOpen(t *testing.T) {
	topo := &networktopology.TopologyImport{Zones: zonesFixture()}
	safety := &OTSafetyImport{SensitiveZones: []SensitiveZone{{ZoneName: "ot", Tier: TierOT}}}
	matched, err := CheckActiveTestAuthorization([]string{"192.168.99.99"}, topo, safety, nil)
	if err != nil {
		t.Fatalf("want no error -- an unresolvable target must fail open, got %v", err)
	}
	if len(matched) != 0 {
		t.Fatalf("matchedZones = %v, want empty", matched)
	}
}

func TestCheckActiveTestAuthorization_ResolvedZoneNotSensitive_FailsOpen(t *testing.T) {
	topo := &networktopology.TopologyImport{Zones: zonesFixture()}
	safety := &OTSafetyImport{SensitiveZones: []SensitiveZone{{ZoneName: "ot", Tier: TierOT}}}
	matched, err := CheckActiveTestAuthorization([]string{"10.0.1.5"}, topo, safety, nil) // resolves to "corporate", not sensitive
	if err != nil {
		t.Fatalf("want no error -- a non-sensitive zone must never be gated, got %v", err)
	}
	if len(matched) != 0 {
		t.Fatalf("matchedZones = %v, want empty", matched)
	}
}

// TestCheckActiveTestAuthorization_OnlyOneOfMultipleTargetsSensitive_StillGated
// pins Review Focus #3.
func TestCheckActiveTestAuthorization_OnlyOneOfMultipleTargetsSensitive_StillGated(t *testing.T) {
	topo := &networktopology.TopologyImport{Zones: zonesFixture()}
	safety := &OTSafetyImport{SensitiveZones: []SensitiveZone{{ZoneName: "ot", Tier: TierOT}}}
	_, err := CheckActiveTestAuthorization([]string{"10.0.1.5", "10.0.2.5"}, topo, safety, nil)
	if err == nil {
		t.Fatal("want an error -- even one sensitive-zone target among several must gate the whole set")
	}
}

// TestCheckActiveTestAuthorization_AuthorizedButNoSensitiveMatch_Harmless
// pins Review Focus #4: an over-cautious caller is never penalized,
// and matchedZones correctly reports nothing was actually exercised.
func TestCheckActiveTestAuthorization_AuthorizedButNoSensitiveMatch_Harmless(t *testing.T) {
	topo := &networktopology.TopologyImport{Zones: zonesFixture()}
	safety := &OTSafetyImport{SensitiveZones: []SensitiveZone{{ZoneName: "ot", Tier: TierOT}}}
	matched, err := CheckActiveTestAuthorization([]string{"10.0.1.5"}, topo, safety, &ActiveTestAuthorization{Authorized: true, SignOff: "pre-approved just in case"})
	if err != nil {
		t.Fatalf("want no error, got %v", err)
	}
	if len(matched) != 0 {
		t.Fatalf("matchedZones = %v, want empty -- nothing was actually sensitive, so nothing was exercised", matched)
	}
}

func TestCheckActiveTestAuthorization_NoSensitiveZonesDeclaredAtAll_NeverGates(t *testing.T) {
	topo := &networktopology.TopologyImport{Zones: zonesFixture()}
	safety := &OTSafetyImport{} // no SensitiveZones at all
	matched, err := CheckActiveTestAuthorization([]string{"10.0.2.5"}, topo, safety, nil)
	if err != nil {
		t.Fatalf("want no error -- a zone can be undeclared-sensitive even if the topology knows it, got %v", err)
	}
	if len(matched) != 0 {
		t.Fatalf("matchedZones = %v, want empty", matched)
	}
}
