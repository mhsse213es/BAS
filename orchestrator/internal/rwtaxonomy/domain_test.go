package rwtaxonomy

import "testing"

func TestAllDomains_HasExactlyTwelveEntriesInRoadmapOrder(t *testing.T) {
	want := []Domain{
		DomainInitialAccess,
		DomainPreparationAndPersistence,
		DomainCredentialAccess,
		DomainLateralMovement,
		DomainDefenseEvasion,
		DomainDataDiscoveryAndStaging,
		DomainExfiltration,
		DomainEncryptionAndDestruction,
		DomainRecoveryInhibition,
		DomainContainmentAndResponse,
		DomainRecoveryAndResilience,
		DomainPostIncidentAssurance,
	}
	if len(AllDomains) != len(want) {
		t.Fatalf("len(AllDomains) = %d, want %d", len(AllDomains), len(want))
	}
	for i, d := range want {
		if AllDomains[i] != d {
			t.Errorf("AllDomains[%d] = %q, want %q -- order must match ransomware.txt's own table exactly, not just contain the same values", i, AllDomains[i], d)
		}
	}
}

func TestDomain_ValidAcceptsEveryMemberOfAllDomains(t *testing.T) {
	for _, d := range AllDomains {
		if !d.Valid() {
			t.Errorf("Domain(%q).Valid() = false, want true -- every member of AllDomains must be valid", d)
		}
	}
}

func TestDomain_ValidRejectsUnknownValue(t *testing.T) {
	if Domain("not_a_real_domain").Valid() {
		t.Fatal("Valid() = true for an unknown domain string, want false")
	}
	if Domain("").Valid() {
		t.Fatal("Valid() = true for an empty string, want false")
	}
}

func TestDomainConstants_HaveExpectedStringValues(t *testing.T) {
	cases := map[Domain]string{
		DomainInitialAccess:             "initial_access",
		DomainPreparationAndPersistence: "preparation_and_persistence",
		DomainCredentialAccess:          "credential_access",
		DomainLateralMovement:           "lateral_movement",
		DomainDefenseEvasion:            "defense_evasion",
		DomainDataDiscoveryAndStaging:   "data_discovery_and_staging",
		DomainExfiltration:              "exfiltration",
		DomainEncryptionAndDestruction:  "encryption_and_destruction",
		DomainRecoveryInhibition:        "recovery_inhibition",
		DomainContainmentAndResponse:    "containment_and_response",
		DomainRecoveryAndResilience:     "recovery_and_resilience",
		DomainPostIncidentAssurance:     "post_incident_assurance",
	}
	for constVal, want := range cases {
		if string(constVal) != want {
			t.Errorf("const %q, want string value %q", constVal, want)
		}
	}
}
