package cvelab

import "testing"

func TestAllowedLabTargets_ExactMatchOnly(t *testing.T) {
	a := AllowedLabTargets{Hosts: []string{"10.50.0.12:8080"}}
	if !a.IsAllowed("10.50.0.12:8080") {
		t.Fatal("the exact allow-listed target must be allowed")
	}
	if a.IsAllowed("10.50.0.12:8081") {
		t.Fatal("a different port must not be allowed")
	}
	if a.IsAllowed("10.50.0.120:8080") {
		t.Fatal("a prefix match on the host must not be allowed")
	}
	if a.IsAllowed("evil.invalid:8080") {
		t.Fatal("a hostname not on the list must not be allowed")
	}
}

func TestAllowedLabTargets_EmptyAllowsNothing(t *testing.T) {
	var a AllowedLabTargets
	if a.IsAllowed("10.50.0.12:8080") {
		t.Fatal("an empty AllowedLabTargets must allow nothing")
	}
}

func TestIsPublicAddress_PrivateIPv4IsNotPublic(t *testing.T) {
	for _, target := range []string{"10.50.0.12:8080", "192.168.1.5:80", "172.16.0.1:443", "127.0.0.1:9000"} {
		pub, err := IsPublicAddress(target)
		if err != nil {
			t.Fatalf("IsPublicAddress(%q): %v", target, err)
		}
		if pub {
			t.Fatalf("IsPublicAddress(%q) = true, want false (private/loopback)", target)
		}
	}
}

func TestIsPublicAddress_PublicIPv4IsPublic(t *testing.T) {
	pub, err := IsPublicAddress("8.8.8.8:443")
	if err != nil {
		t.Fatalf("IsPublicAddress: %v", err)
	}
	if !pub {
		t.Fatal("IsPublicAddress(8.8.8.8:443) = false, want true -- this is a real public address")
	}
}

func TestIsPublicAddress_RefusesHostname(t *testing.T) {
	_, err := IsPublicAddress("example.com:443")
	if err == nil {
		t.Fatal("a hostname target must be refused (error), never silently resolved")
	}
}

func TestIsPublicAddress_RefusesMissingPort(t *testing.T) {
	_, err := IsPublicAddress("10.50.0.12")
	if err == nil {
		t.Fatal("a target with no port must be refused")
	}
}
