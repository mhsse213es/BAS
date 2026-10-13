package networkgraph

import "testing"

func TestLoadVantagePoint_BothSetReturnsConfiguredVantagePoint(t *testing.T) {
	t.Setenv("NETWORK_VANTAGE_POINT_ID", "test-vp-1")
	t.Setenv("NETWORK_VANTAGE_POINT_POSITION", "test-dc1-mgmt-vlan")

	vp, err := LoadVantagePoint()
	if err != nil {
		t.Fatalf("LoadVantagePoint: %v", err)
	}
	if vp.ID != "test-vp-1" || vp.NetworkPosition != "test-dc1-mgmt-vlan" {
		t.Fatalf("got %+v, want ID=test-vp-1 NetworkPosition=test-dc1-mgmt-vlan", vp)
	}
	if !vp.Configured() {
		t.Fatal("want Configured() true when both env vars are set")
	}
}

func TestLoadVantagePoint_EitherUnsetReturnsError(t *testing.T) {
	cases := []struct {
		name    string
		id, pos string
	}{
		{"both unset", "", ""},
		{"id unset", "", "some-position"},
		{"position unset", "some-id", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("NETWORK_VANTAGE_POINT_ID", c.id)
			t.Setenv("NETWORK_VANTAGE_POINT_POSITION", c.pos)

			vp, err := LoadVantagePoint()
			if err == nil {
				t.Fatalf("want error, got vp=%+v", vp)
			}
			if vp.Configured() {
				t.Fatal("want Configured() false on error")
			}
		})
	}
}
