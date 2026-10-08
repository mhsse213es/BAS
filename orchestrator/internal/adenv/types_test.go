package adenv

import (
	"encoding/json"
	"reflect"
	"testing"
)

// fullEnvironment is a representative Environment touching every field in
// every sub-struct, so a missing field, a typo'd json tag, or a wrong enum
// type fails this test.
func fullEnvironment() Environment {
	return Environment{
		Forest: Forest{
			Domains:             []Domain{{Name: "corp.example.com", SID: "S-1-5-21-1", NetBIOS: "CORP"}},
			Trusts:              []Trust{{SourceDomain: "corp.example.com", TargetDomain: "child.corp.example.com", Direction: TrustBidirectional, Type: TrustTypeParentChild, Transitive: true}},
			ForestRelationships: []string{"child-domain"},
		},
		Identity: Identity{
			Users:              []User{{Name: "jdoe", SID: "S-1-5-21-1-1001", Enabled: true, SPNs: []string{"HTTP/svc01"}}},
			Groups:             []Group{{Name: "Domain Admins", SID: "S-1-5-21-1-512", Members: []string{"S-1-5-21-1-500"}}},
			ServiceAccounts:    []User{{Name: "svc_sql", SID: "S-1-5-21-1-1100", Enabled: true}},
			ComputerAccounts:   []User{{Name: "WORKSTATION01$", SID: "S-1-5-21-1-1200", Enabled: true}},
			PrivilegedAccounts: []string{"S-1-5-21-1-500"},
		},
		Machines: Machines{
			DomainControllers: []Machine{{Hostname: "DC01", SID: "S-1-5-21-1-1000", OS: "Windows Server 2022"}},
			Servers:           []Machine{{Hostname: "SRV01", SID: "S-1-5-21-1-1300"}},
			Workstations:      []Machine{{Hostname: "WS01", SID: "S-1-5-21-1-1400"}},
			AdminWorkstations: []Machine{{Hostname: "PAW01", SID: "S-1-5-21-1-1500"}},
		},
		Authentication: Authentication{
			Kerberos: KerberosConfig{Enabled: true, PreAuthRequired: true},
			NTLM:     true,
			LDAP:     LDAPConfig{SigningRequired: false, ChannelBindingRequired: false},
			SMB:      SMBConfig{SigningRequired: true},
			RDP:      true,
			WinRM:    true,
		},
		Delegation: Delegation{
			Unconstrained: []string{"SRV01$"},
			Constrained:   []ConstrainedDelegation{{Principal: "svc_sql", Targets: []string{"MSSQLSvc/db01"}, ProtocolTransition: true}},
			RBCD:          []RBCDEntry{{Target: "SRV02$", AllowedPrincipals: []string{"svc_deploy"}}},
		},
		Authorization: Authorization{
			ACLs: []ACLEntry{{Principal: "jdoe", Target: "svc_sql", Right: ACLGenericWrite}},
		},
		Policy: Policy{
			GPOs:             []GPO{{Name: "Default Domain Policy", LinkedOUs: []string{"OU=Corp"}}},
			RestrictedGroups: []string{"Administrators"},
			LAPSEnabled:      true,
			SecurityPolicies: []string{"password-complexity"},
		},
		PKI: PKI{
			CAs:       []CertificateAuthority{{Name: "CORP-CA"}},
			Templates: []CertTemplate{{Name: "User", EnrollmentRights: []string{"Domain Users"}, ManagerApprovalRequired: false, AuthenticationEKU: true}},
		},
	}
}

func TestEnvironment_JSONRoundTrip_FullyPopulated(t *testing.T) {
	env := fullEnvironment()

	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got Environment
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(env, got) {
		t.Fatalf("round-trip mismatch:\n got  %+v\n want %+v", got, env)
	}
}

func TestACLRight_MatchesAttackpathEdgeKindValues(t *testing.T) {
	// These 4 constants must carry the exact string values
	// attackpath.EdgeKind already uses for the same SharpHound ACE
	// RightName, so a future mapper can convert one to the other by
	// value, not by a hand-maintained lookup table.
	cases := map[ACLRight]string{
		ACLOwns:                 "owns",
		ACLAllExtendedRights:    "all-extended-rights",
		ACLAddKeyCredentialLink: "add-key-credential-link",
		ACLReadLAPSPassword:     "read-laps-password",
	}
	for right, want := range cases {
		if string(right) != want {
			t.Errorf("ACLRight %v: got %q, want %q", right, string(right), want)
		}
	}
}

func TestEnvironment_JSONRoundTrip_ZeroValue(t *testing.T) {
	var env Environment // nothing discovered yet

	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got Environment
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(env, got) {
		t.Fatalf("zero-value round-trip mismatch:\n got  %+v\n want %+v", got, env)
	}
}
