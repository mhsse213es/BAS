package dbsim

import "testing"

func TestGrantsFromProbeKeepsEveryGrant(t *testing.T) {
	res := DBProbeResult{Grants: []DBProbeGrant{
		{Role: "app", Object: "public.accounts", Privilege: "SELECT"},
		{Role: "app", Object: "public.accounts", Privilege: "DELETE"},
	}}
	got := GrantsFromProbe(res)
	if len(got) != 2 || got[1].Privilege != "DELETE" {
		t.Fatalf("grants dropped or altered: %+v", got)
	}
}

func TestPolicyFromJSONRefusesUnnamedOrEmptyPolicy(t *testing.T) {
	cases := map[string]string{
		"no source": `{"roles":{"app":{"allow":{"public.accounts":["SELECT"]}}}}`,
		"no roles":  `{"source":"ticket-1"}`,
		"bad json":  `{`,
	}
	for name, body := range cases {
		if _, err := PolicyFromJSON([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	p, err := PolicyFromJSON([]byte(`{"source":"ticket-1","roles":{"app":{"allow":{"public.accounts":["SELECT"]}}}}`))
	if err != nil || p.Source != "ticket-1" {
		t.Fatalf("valid policy refused: %v %+v", err, p)
	}
}
