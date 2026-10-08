# AD-M01 Knowledge Model Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (execution method already decided — native/inline, no subagent dispatch; see Execution Handoff). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Define the AD environment knowledge model — a pure Go type system representing an Active Directory environment's structure (forest, identity, machines, authentication, delegation, authorization, policy, PKI), with zero behavior.

**Architecture:** One new package, `orchestrator/internal/adenv`, holding a single `Environment` struct that aggregates one sub-struct per category from AD.txt's own ontology diagram. Kept separate from `orchestrator/internal/attackpath` (which is graph-structural, for traversal algorithms over nodes/edges) — `adenv` is the richer entity model that a later phase (AD-M02) will populate from discovery data, and a later phase (AD-M03) will project into `attackpath`'s graph. This task adds no collection logic and no graph projection; it only establishes the shared vocabulary those later phases will read and write.

**Tech Stack:** Go (matches `orchestrator`'s existing stdlib-only `encoding/json` convention; no new dependencies).

**Spec:** This plan is Wave 1 / phase 1 of the user-approved AD Mastery sequencing (no separate written spec document — the design was approved conversationally in chat per the user's explicit "wave → short design → bounded implementation plan → execute → verify → stop" process; see AD.txt at the repo root for the source ontology diagram this type system mirrors).

## Global Constraints

- Go stdlib only — no new third-party dependencies (matches every other `internal/*` package in this repo).
- `go 1.26.6` (from `orchestrator/go.mod`), module path `github.com/audspect/bas`.
- JSON field names are camelCase (matches `internal/attackpath/graph.go`'s existing convention, e.g. `json:"highValue,omitempty"`).
- Closed enumerated sets named in AD.txt (ACL rights, trust direction/type) become typed Go string constants, not bare strings — matches `internal/attackpath`'s `NodeKind`/`HostRole` pattern.
- No collection/discovery logic, no graph projection, no scenario/primitive linkage in this package — purely data types. (Deferred to AD-M02 and AD-M03, each its own future plan.)

## Review Focus

This phase has no behavior — it is a type system with one serialization concern (JSON round-trip), so the failure modes worth testing are narrower than a typical feature. The two most likely to bite a future consumer (AD-M02's discovery mapper, which will construct `Environment` values from real BloodHound/SharpHound data):

- A **zero-value `Environment`** (nothing discovered yet, or a category genuinely empty) must marshal and round-trip without panicking or producing a shape a consumer can't parse back — `omitempty` must not silently change a `nil` slice into something a strict consumer barely distinguishes from "wasn't populated." Tested in Task 1, Step 1b.
- A **fully-populated `Environment`** covering every field in every sub-struct must round-trip byte-for-byte equal — the test most likely to catch a missing field, a typo'd json tag, or a wrong enum type. Tested in Task 1, Step 1a.

---

### Task 1: Define the `adenv.Environment` type system with a JSON round-trip test

**Files:**
- Create: `orchestrator/internal/adenv/types.go`
- Test: `orchestrator/internal/adenv/types_test.go`

**Interfaces:**
- Consumes: nothing (first file in a new package).
- Produces: `adenv.Environment` and its sub-struct types (`Forest`, `Domain`, `Trust`, `TrustDirection`, `TrustType`, `Identity`, `User`, `Group`, `Machines`, `Machine`, `Authentication`, `KerberosConfig`, `LDAPConfig`, `SMBConfig`, `Delegation`, `ConstrainedDelegation`, `RBCDEntry`, `Authorization`, `ACLRight`, `ACLEntry`, `Policy`, `GPO`, `PKI`, `CertificateAuthority`, `CertTemplate`) — later AD-M02/AD-M03 plans will import `github.com/audspect/bas/internal/adenv` and construct/read these exact names and fields.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/adenv/types_test.go
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/adenv/... -v`
Expected: FAIL — `package adenv is not in std` / `undefined: Environment` (the package doesn't exist yet).

- [ ] **Step 3: Write the minimal implementation**

```go
// orchestrator/internal/adenv/types.go

// Package adenv is the AD environment knowledge model (AD-M01): a typed
// representation of an Active Directory environment's structure, mirroring
// the ontology in AD.txt's own diagram (Forest, Identity, Machines,
// Authentication, Delegation, Authorization, Policy, PKI).
//
// This package holds pure data types only — no discovery/collection logic
// (AD-M02 will populate an Environment from SharpHound/BloodHound output)
// and no graph projection (AD-M03's internal/attackpath graph is built FROM
// an Environment, not the other way around). Keeping this package free of
// behavior keeps it the stable, shared vocabulary every later AD-M phase
// reads and writes, instead of each phase inventing its own shape.
package adenv

// Environment is the full AD environment knowledge model: one forest's
// worth of structure, as reconstructed from discovery data.
type Environment struct {
	Forest         Forest         `json:"forest"`
	Identity       Identity       `json:"identity"`
	Machines       Machines       `json:"machines"`
	Authentication Authentication `json:"authentication"`
	Delegation     Delegation     `json:"delegation"`
	Authorization  Authorization  `json:"authorization"`
	Policy         Policy         `json:"policy"`
	PKI            PKI            `json:"pki"`
}

// Forest is the forest/domain/trust layer.
type Forest struct {
	Domains             []Domain `json:"domains,omitempty"`
	Trusts              []Trust  `json:"trusts,omitempty"`
	ForestRelationships []string `json:"forestRelationships,omitempty"` // e.g. "child-domain", "cross-forest"
}

// Domain is one domain within the forest.
type Domain struct {
	Name    string `json:"name"`              // DNS name, e.g. "corp.example.com"
	SID     string `json:"sid"`                // domain SID
	NetBIOS string `json:"netbios,omitempty"`
}

// TrustDirection is the direction of trust flow between two domains/forests.
type TrustDirection string

const (
	TrustInbound       TrustDirection = "inbound"
	TrustOutbound      TrustDirection = "outbound"
	TrustBidirectional TrustDirection = "bidirectional"
)

// TrustType names the kind of trust relationship.
type TrustType string

const (
	TrustTypeParentChild TrustType = "parent-child"
	TrustTypeCrossLink   TrustType = "cross-link"
	TrustTypeExternal    TrustType = "external"
	TrustTypeForest      TrustType = "forest"
	TrustTypeRealm       TrustType = "realm"
)

// Trust is one trust relationship between two domains.
type Trust struct {
	SourceDomain string         `json:"sourceDomain"`
	TargetDomain string         `json:"targetDomain"`
	Direction    TrustDirection `json:"direction"`
	Type         TrustType      `json:"type"`
	Transitive   bool           `json:"transitive"`
}

// Identity is the user/group/account layer.
type Identity struct {
	Users              []User   `json:"users,omitempty"`
	Groups             []Group  `json:"groups,omitempty"`
	ServiceAccounts    []User   `json:"serviceAccounts,omitempty"`
	ComputerAccounts   []User   `json:"computerAccounts,omitempty"`
	PrivilegedAccounts []string `json:"privilegedAccounts,omitempty"` // SIDs/names flagged privileged
}

// User is one user, service, or computer account.
type User struct {
	Name    string   `json:"name"`
	SID     string   `json:"sid"`
	Enabled bool     `json:"enabled"`
	SPNs    []string `json:"spns,omitempty"` // service principal names (Kerberoastable if non-empty)
}

// Group is one AD group.
type Group struct {
	Name    string   `json:"name"`
	SID     string   `json:"sid"`
	Members []string `json:"members,omitempty"` // member SIDs/names
}

// Machines is the host inventory layer.
type Machines struct {
	DomainControllers []Machine `json:"domainControllers,omitempty"`
	Servers           []Machine `json:"servers,omitempty"`
	Workstations      []Machine `json:"workstations,omitempty"`
	AdminWorkstations []Machine `json:"adminWorkstations,omitempty"`
}

// Machine is one computer in the environment.
type Machine struct {
	Hostname string `json:"hostname"`
	SID      string `json:"sid"`
	OS       string `json:"os,omitempty"`
}

// Authentication is per-environment protocol configuration — not live
// session state, just which protocols/config are present.
type Authentication struct {
	Kerberos KerberosConfig `json:"kerberos"`
	NTLM     bool           `json:"ntlm"`
	LDAP     LDAPConfig     `json:"ldap"`
	SMB      SMBConfig      `json:"smb"`
	RDP      bool           `json:"rdp"`
	WinRM    bool           `json:"winrm"`
}

// KerberosConfig is the environment's Kerberos-relevant configuration.
type KerberosConfig struct {
	Enabled bool `json:"enabled"`
	// PreAuthRequired false on an account makes it AS-REP-roastable; this
	// field is the environment-level default an AD-M02 mapper observes,
	// not a per-user override (per-user exceptions live on User later if
	// a future phase needs them).
	PreAuthRequired bool `json:"preAuthRequired"`
}

// LDAPConfig is the environment's LDAP hardening configuration.
type LDAPConfig struct {
	SigningRequired        bool `json:"signingRequired"`
	ChannelBindingRequired bool `json:"channelBindingRequired"`
}

// SMBConfig is the environment's SMB hardening configuration.
type SMBConfig struct {
	SigningRequired bool `json:"signingRequired"`
}

// Delegation is the Kerberos delegation layer.
type Delegation struct {
	Unconstrained []string                `json:"unconstrained,omitempty"` // principal names/SIDs with unconstrained delegation
	Constrained   []ConstrainedDelegation `json:"constrained,omitempty"`
	RBCD          []RBCDEntry             `json:"rbcd,omitempty"`
}

// ConstrainedDelegation is one principal's constrained-delegation grant.
type ConstrainedDelegation struct {
	Principal          string   `json:"principal"`
	Targets            []string `json:"targets"`            // SPNs this principal can delegate to
	ProtocolTransition bool     `json:"protocolTransition"` // true = S4U2Self allowed
}

// RBCDEntry is one resource-based constrained delegation grant.
type RBCDEntry struct {
	Target            string   `json:"target"` // the resource/computer accepting delegation
	AllowedPrincipals []string `json:"allowedPrincipals"`
}

// Authorization is the ACL layer.
type Authorization struct {
	ACLs []ACLEntry `json:"acls,omitempty"`
}

// ACLRight names one of AD.txt's closed set of abuse-relevant ACL rights.
type ACLRight string

const (
	ACLGenericAll          ACLRight = "GenericAll"
	ACLGenericWrite        ACLRight = "GenericWrite"
	ACLWriteDACL           ACLRight = "WriteDACL"
	ACLWriteOwner          ACLRight = "WriteOwner"
	ACLForceChangePassword ACLRight = "ForceChangePassword"
	ACLAddMember           ACLRight = "AddMember"
	ACLAddSelf             ACLRight = "AddSelf"
)

// ACLEntry is one ACL grant from a principal onto a target object.
type ACLEntry struct {
	Principal string   `json:"principal"` // the SID/name holding the right
	Target    string   `json:"target"`    // the SID/name the right applies to
	Right     ACLRight `json:"right"`
}

// Policy is the GPO/security-policy layer.
type Policy struct {
	GPOs             []GPO    `json:"gpos,omitempty"`
	RestrictedGroups []string `json:"restrictedGroups,omitempty"`
	LAPSEnabled      bool     `json:"lapsEnabled"`
	SecurityPolicies []string `json:"securityPolicies,omitempty"` // free-form policy names/IDs
}

// GPO is one Group Policy Object.
type GPO struct {
	Name      string   `json:"name"`
	LinkedOUs []string `json:"linkedOUs,omitempty"`
}

// PKI is the ADCS layer.
type PKI struct {
	CAs       []CertificateAuthority `json:"cas,omitempty"`
	Templates []CertTemplate         `json:"templates,omitempty"`
}

// CertificateAuthority is one enterprise/standalone CA.
type CertificateAuthority struct {
	Name string `json:"name"`
}

// CertTemplate is one certificate template, carrying the fields AD.txt
// names as ESC-relevant (manager approval, authentication EKU, enrollment
// rights) so a later phase can compute ESC1/ESC2/etc. applicability without
// re-deriving this data.
type CertTemplate struct {
	Name                    string   `json:"name"`
	EnrollmentRights        []string `json:"enrollmentRights,omitempty"` // principals who can enroll
	ManagerApprovalRequired bool     `json:"managerApprovalRequired"`
	AuthenticationEKU       bool     `json:"authenticationEku"` // template's EKU includes Client Authentication
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/adenv/... -v`
Expected: PASS — both `TestEnvironment_JSONRoundTrip_FullyPopulated` and `TestEnvironment_JSONRoundTrip_ZeroValue`.

- [ ] **Step 5: Run `go vet` and `gofmt` (this repo's CI gate for every Go package)**

Run: `cd orchestrator && gofmt -l internal/adenv/ && go vet ./internal/adenv/...`
Expected: `gofmt -l` prints nothing (no unformatted files); `go vet` prints nothing.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/adenv/types.go orchestrator/internal/adenv/types_test.go
git commit -m "$(cat <<'EOF'
feat(adenv): add AD environment knowledge model (AD-M01)

Pure Go type system for the AD Mastery initiative's Wave 1 / phase 1:
Environment aggregates Forest, Identity, Machines, Authentication,
Delegation, Authorization, Policy, and PKI, mirroring AD.txt's own
ontology diagram. No discovery/collection logic and no graph
projection -- those are AD-M02 and AD-M03, each a separate bounded
plan. Verified via two JSON round-trip tests (fully-populated and
zero-value) rather than a build/smoke gate, since this phase has no
behavior to exercise beyond serialization.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Execution Handoff

**Execution method: Native (inline, this session), per the user's standing preference and the wave/phase process they set for this initiative — no subagent dispatch, no independent review gate per phase.** This is a single bounded task defining pure data types with no cross-task interfaces to coordinate and no destructive/external effects, so the inline+final-review tradeoff the plan would normally weigh doesn't apply here; proceeding directly to execution via `superpowers:executing-plans`.
