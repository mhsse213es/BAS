package main

import (
	"reflect"
	"testing"
)

func TestLicenseFileName(t *testing.T) {
	cases := []struct {
		id, tier, want string
	}{
		{"hdfc-prod-001", "Enterprise", "hdfc-enterprise-001.lic"},
		{"hdfc-prod-001", "Core", "hdfc-core-001.lic"},
		{"hdfc-prod-001", "Advanced", "hdfc-advanced-001.lic"},
		{"acme-corp-uat-12", "Core", "acme-corp-core-12.lic"}, // a multi-word customer keeps all its words
		{"hdfc-001", "Core", "hdfc-core-001.lic"},             // no environment word to drop
		{"hdfc", "Core", "hdfc-core.lic"},                     // no sequence number: none is invented
		{"hdfc-prod-001", "", "hdfc-001.lic"},                 // a pre-tier licence carries no tier word
		{"HDFC Prod 001", "Enterprise", "hdfc-enterprise-001.lic"},
		{"prod-001", "Core", "prod-core-001.lic"}, // an ID that is only an environment word keeps it
		{"../etc/passwd-001", "Core", "etc-passwd-core-001.lic"},
		{"", "Core", "license-core.lic"},
	}
	for _, c := range cases {
		if got := licenseFileName(c.id, c.tier); got != c.want {
			t.Errorf("licenseFileName(%q, %q) = %q, want %q", c.id, c.tier, got, c.want)
		}
	}
}

func TestBuildFeatures(t *testing.T) {
	got, err := buildFeatures("full", "")
	if err != nil || !reflect.DeepEqual(got, []string{"full"}) {
		t.Fatalf("no add-ons: %v %v", got, err)
	}
	got, err = buildFeatures("full", "aleef,aleef")
	if err != nil || !reflect.DeepEqual(got, []string{"full", "addon:aleef"}) {
		t.Fatalf("aleef: %v %v", got, err)
	}
	for _, bad := range []string{"Aleef", "aleef2", "other", " aleef", "addon:aleef"} {
		if _, err := buildFeatures("full", bad); err == nil {
			t.Fatalf("add-on %q accepted", bad)
		}
	}
}
