package networktopology

import "testing"

func TestResolveZoneCIDRs_ReturnsCIDRsForNamedZone(t *testing.T) {
	zones := []Zone{{Name: "dmz", CIDRs: []string{"10.0.1.0/24"}}}
	cidrs, err := ResolveZoneCIDRs("dmz", zones)
	if err != nil {
		t.Fatalf("ResolveZoneCIDRs: %v", err)
	}
	if len(cidrs) != 1 || cidrs[0] != "10.0.1.0/24" {
		t.Fatalf("got %v, want [10.0.1.0/24]", cidrs)
	}
}

func TestResolveZoneCIDRs_UnknownZoneNameErrors(t *testing.T) {
	zones := []Zone{{Name: "dmz", CIDRs: []string{"10.0.1.0/24"}}}
	if _, err := ResolveZoneCIDRs("does-not-exist", zones); err == nil {
		t.Fatal("want error for a zone name absent from this topology")
	}
}

func TestResolveZoneCIDRs_AmbiguousZoneNameErrors(t *testing.T) {
	zones := []Zone{{Name: "dup", CIDRs: []string{"10.0.1.0/24"}}, {Name: "dup", CIDRs: []string{"10.0.9.0/24"}}}
	if _, err := ResolveZoneCIDRs("dup", zones); err == nil {
		t.Fatal("want error -- two zones sharing a name must never be silently resolved to one of them")
	}
}

func TestZoneForHost_ReturnsMatchingZoneName(t *testing.T) {
	zones := []Zone{{Name: "dmz", CIDRs: []string{"10.0.1.0/24"}}, {Name: "internal", CIDRs: []string{"10.0.2.0/24"}}}
	name, err := ZoneForHost("10.0.1.50", zones)
	if err != nil {
		t.Fatalf("ZoneForHost: %v", err)
	}
	if name != "dmz" {
		t.Fatalf("got %q, want dmz", name)
	}
}

func TestZoneForHost_NoMatchErrors(t *testing.T) {
	zones := []Zone{{Name: "dmz", CIDRs: []string{"10.0.1.0/24"}}}
	if _, err := ZoneForHost("192.168.1.1", zones); err == nil {
		t.Fatal("want error when no declared zone contains this host")
	}
}

func TestZoneForHost_AmbiguousMatchErrors(t *testing.T) {
	zones := []Zone{{Name: "a", CIDRs: []string{"10.0.0.0/8"}}, {Name: "b", CIDRs: []string{"10.0.1.0/24"}}}
	if _, err := ZoneForHost("10.0.1.50", zones); err == nil {
		t.Fatal("want error -- host falls inside two overlapping zones, ambiguous")
	}
}

func TestZoneForHost_NonIPHostErrors(t *testing.T) {
	zones := []Zone{{Name: "dmz", CIDRs: []string{"10.0.1.0/24"}}}
	if _, err := ZoneForHost("not-an-ip", zones); err == nil {
		t.Fatal("want error for a non-literal-IP host")
	}
}
