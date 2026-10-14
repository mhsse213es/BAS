# AD-M02 attackpath-to-adenv Mapping Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (execution method already decided — native/inline, no subagent dispatch). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Map the existing `attackpath` graph (SharpHound-derived `Node`/`Edge` data, already in production) into AD-M01's richer `adenv.Environment` ontology — a mapping task, not a parser redesign, per the user's standing correction on the wave sequencing.

**Architecture:** One new function, `adenv.FromGraph(g *attackpath.Graph) Environment`, in a new file `orchestrator/internal/adenv/fromattackpath.go`. `adenv` gains a one-way dependency on `attackpath` (the reverse never happens — `attackpath` stays graph-structural and self-contained). The mapping is deliberately honest about what it can and cannot populate: several of `adenv`'s categories (Forest, Authentication, Policy, PKI) have **zero** corresponding data anywhere in `attackpath` today and are left at their Go zero-value on purpose, not approximated or fabricated. This is documented in the function's own doc comment so a future reader never mistakes "no source data yet" for "verified empty."

**Tech Stack:** Go (matches `orchestrator`'s existing stdlib-only convention; no new dependencies).

**Spec:** No separate written spec document — this is a bounded, conversationally-approved task per the user's "wave → short design → bounded implementation plan → execute → verify → stop" process (see `project_ad_mastery_initiative.md` in memory). The source types this plan maps between are `orchestrator/internal/adenv/types.go` (AD-M01) and `orchestrator/internal/attackpath/graph.go`+`build.go` (AD-M03).

## Global Constraints

- Go stdlib only — no new third-party dependencies.
- `go 1.26.6`, module path `github.com/audspect/bas`.
- `adenv` may import `attackpath`; `attackpath` must never import `adenv` (one-way dependency, enforced by not adding the import, not by a lint rule — there is no existing import-direction linter in this repo to hook into, and adding one is out of scope for this plan).
- Every `adenv.Environment` field this mapping leaves at zero-value because `attackpath` has no source data for it (Forest, Authentication, Policy, PKI, Identity.ServiceAccounts, Identity.ComputerAccounts, Machines.AdminWorkstations, User.Enabled, User.SPNs, ConstrainedDelegation.ProtocolTransition) gets a one-line doc comment inside `FromGraph` explaining why, grouped by category — not scattered as a vague top-level disclaimer.

## Review Focus

- `Node.HasSPN == true` must NOT cause `FromGraph` to fabricate a placeholder string in `User.SPNs` — a reasonable future reader of `User.SPNs` would expect real SPN values there, and a fake placeholder is worse than an honestly empty slice. Tested in Task 1, Step 1 (a user with `HasSPN: true` asserted to have `SPNs == nil`).
- A `KindGroup` node with members from TWO different source edges (not just one) must collect ALL of them into `Group.Members`, not just the last one seen — grouping bugs (overwrite instead of append) are the most likely mistake in this kind of edge-to-struct aggregation. Tested in Task 1, Step 1.
- `EdgeAllowedToDelegate` and `EdgeAllowedToAct` have OPPOSITE grantee positions (documented at `attackpath/sharphound.go:266-280`) — a mapping that reuses the same `From`/`To` assignment for both would silently invert one of Constrained/RBCD delegation's principal/target semantics. Tested in Task 1, Step 1 (both delegation types present in the same fixture, asserted on the correct side each).

---

### Task 1: `adenv.FromGraph`

**Files:**
- Create: `orchestrator/internal/adenv/fromattackpath.go`
- Test: `orchestrator/internal/adenv/fromattackpath_test.go`

**Interfaces:**
- Consumes: `attackpath.Graph` — specifically `g.Nodes() []attackpath.Node` and `g.Edges() []attackpath.Edge` (both already exported, `orchestrator/internal/attackpath/graph.go:149,170`), and `attackpath.BuildGraph(cols ...attackpath.Collection) *attackpath.Graph` (`build.go:32`) to construct a graph from fixture data in the test.
- Produces: `adenv.FromGraph(g *attackpath.Graph) Environment` — the first consumer of this will be a future phase (not scoped here) that wires a live SharpHound collection into an API response or report.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/adenv/fromattackpath_test.go
package adenv

import (
	"reflect"
	"testing"

	"github.com/audspect/bas/internal/attackpath"
)

func TestFromGraph_MapsEveryDerivableCategory(t *testing.T) {
	col := attackpath.Collection{
		AgentID: "agent1", Hostname: "host1", Source: "sharphound",
		Nodes: []attackpath.Node{
			{ID: "DC01", Kind: attackpath.KindHost, Label: "DC01.CORP.LOCAL", Role: attackpath.RoleDC},
			{ID: "SRV01", Kind: attackpath.KindHost, Label: "SRV01.CORP.LOCAL", Role: attackpath.RoleServer},
			{ID: "WS01", Kind: attackpath.KindHost, Label: "WS01.CORP.LOCAL", Role: attackpath.RoleEndpoint},
			{ID: "SVCACCT", Kind: attackpath.KindUser, Label: "svc_sql@CORP.LOCAL", HasSPN: true},
			{ID: "NORMALUSER", Kind: attackpath.KindUser, Label: "NORMALUSER@CORP.LOCAL", DontRequirePreauth: true},
			{ID: "LEGACY01", Kind: attackpath.KindHost, Label: "LEGACY01.CORP.LOCAL", Role: attackpath.RoleEndpoint, UnconstrainedDelegation: true},
			{ID: "DAGROUP", Kind: attackpath.KindGroup, Label: "Domain Admins", HighValue: true},
		},
		Edges: []attackpath.Edge{
			// Two members of the same group -- must both survive.
			{From: "SVCACCT", To: "DAGROUP", Kind: attackpath.EdgeMemberOf},
			{From: "NORMALUSER", To: "DAGROUP", Kind: attackpath.EdgeMemberOf},
			// ACL abuse: NORMALUSER holds GenericWrite over SVCACCT.
			{From: "NORMALUSER", To: "SVCACCT", Kind: attackpath.EdgeGenericWrite},
			// Constrained delegation: SRV01 can delegate to the SPN on WS01.
			{From: "SRV01", To: "WS01", Kind: attackpath.EdgeAllowedToDelegate},
			// RBCD: SVCACCT is allowed to act on behalf of others toward SRV01.
			{From: "SVCACCT", To: "SRV01", Kind: attackpath.EdgeAllowedToAct},
		},
	}
	g := attackpath.BuildGraph(col)

	env := FromGraph(g)

	// Machines, bucketed by role.
	if len(env.Machines.DomainControllers) != 1 || env.Machines.DomainControllers[0].Hostname != "DC01.CORP.LOCAL" {
		t.Fatalf("expected 1 DC (DC01.CORP.LOCAL), got %+v", env.Machines.DomainControllers)
	}
	if len(env.Machines.Servers) != 1 || env.Machines.Servers[0].Hostname != "SRV01.CORP.LOCAL" {
		t.Fatalf("expected 1 server (SRV01.CORP.LOCAL), got %+v", env.Machines.Servers)
	}
	// WS01 and LEGACY01 are both RoleEndpoint -> both Workstations.
	if len(env.Machines.Workstations) != 2 {
		t.Fatalf("expected 2 workstations, got %+v", env.Machines.Workstations)
	}

	// Users: Name/SID mapped, Enabled/SPNs deliberately left at zero-value.
	svc := mustFindUser(t, env.Identity.Users, "SVCACCT")
	if svc.Name != "svc_sql@CORP.LOCAL" || svc.SID != "SVCACCT" {
		t.Fatalf("expected SVCACCT Name/SID mapped, got %+v", svc)
	}
	if svc.Enabled {
		t.Fatalf("expected Enabled to stay false (unknown, not verified-disabled) when attackpath has no enabled/disabled data, got %+v", svc)
	}
	if svc.SPNs != nil {
		t.Fatalf("expected SPNs to stay nil (HasSPN is a bool, not real SPN strings) even though HasSPN was true, got %+v", svc.SPNs)
	}

	// Groups: both members present, not just the last one seen.
	da := mustFindGroup(t, env.Identity.Groups, "DAGROUP")
	wantMembers := map[string]bool{"SVCACCT": true, "NORMALUSER": true}
	if len(da.Members) != 2 || !wantMembers[da.Members[0]] || !wantMembers[da.Members[1]] {
		t.Fatalf("expected DAGROUP to have both SVCACCT and NORMALUSER as members, got %+v", da.Members)
	}

	// PrivilegedAccounts from HighValue.
	if len(env.Identity.PrivilegedAccounts) != 1 || env.Identity.PrivilegedAccounts[0] != "DAGROUP" {
		t.Fatalf("expected PrivilegedAccounts == [DAGROUP], got %+v", env.Identity.PrivilegedAccounts)
	}

	// Delegation: all 3 sub-categories.
	if len(env.Delegation.Unconstrained) != 1 || env.Delegation.Unconstrained[0] != "LEGACY01" {
		t.Fatalf("expected Unconstrained == [LEGACY01], got %+v", env.Delegation.Unconstrained)
	}
	if len(env.Delegation.Constrained) != 1 || env.Delegation.Constrained[0].Principal != "SRV01" || len(env.Delegation.Constrained[0].Targets) != 1 || env.Delegation.Constrained[0].Targets[0] != "WS01" {
		t.Fatalf("expected Constrained == [{Principal:SRV01 Targets:[WS01]}], got %+v", env.Delegation.Constrained)
	}
	if len(env.Delegation.RBCD) != 1 || env.Delegation.RBCD[0].Target != "SRV01" || len(env.Delegation.RBCD[0].AllowedPrincipals) != 1 || env.Delegation.RBCD[0].AllowedPrincipals[0] != "SVCACCT" {
		t.Fatalf("expected RBCD == [{Target:SRV01 AllowedPrincipals:[SVCACCT]}], got %+v", env.Delegation.RBCD)
	}

	// Authorization: the ACL edge, with Right values matching exactly
	// (adenv.ACLRight and attackpath.EdgeKind share string values after
	// the AD-M03 fix).
	if len(env.Authorization.ACLs) != 1 {
		t.Fatalf("expected 1 ACL entry, got %+v", env.Authorization.ACLs)
	}
	acl := env.Authorization.ACLs[0]
	if acl.Principal != "NORMALUSER" || acl.Target != "SVCACCT" || acl.Right != ACLGenericWrite {
		t.Fatalf("expected {NORMALUSER SVCACCT GenericWrite}, got %+v", acl)
	}

	// Categories with zero source data anywhere in attackpath stay at the
	// Go zero-value, not approximated.
	zero := Environment{}
	if !reflect.DeepEqual(env.Forest, zero.Forest) {
		t.Fatalf("expected Forest to stay zero-value (attackpath has no domain/trust data), got %+v", env.Forest)
	}
	if !reflect.DeepEqual(env.Authentication, zero.Authentication) {
		t.Fatalf("expected Authentication to stay zero-value (SMB/WinRM/RDP edges are reachability, not hardening config), got %+v", env.Authentication)
	}
	if !reflect.DeepEqual(env.Policy, zero.Policy) {
		t.Fatalf("expected Policy to stay zero-value (no GPO/LAPS-policy data in attackpath), got %+v", env.Policy)
	}
	if !reflect.DeepEqual(env.PKI, zero.PKI) {
		t.Fatalf("expected PKI to stay zero-value (no ADCS data in attackpath), got %+v", env.PKI)
	}
}

func mustFindUser(t *testing.T, users []User, sid string) User {
	t.Helper()
	for _, u := range users {
		if u.SID == sid {
			return u
		}
	}
	t.Fatalf("no user with SID %q in %+v", sid, users)
	return User{}
}

func mustFindGroup(t *testing.T, groups []Group, sid string) Group {
	t.Helper()
	for _, g := range groups {
		if g.SID == sid {
			return g
		}
	}
	t.Fatalf("no group with SID %q in %+v", sid, groups)
	return Group{}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/adenv/... -run TestFromGraph_MapsEveryDerivableCategory -v`
Expected: FAIL — compile error, `undefined: FromGraph` (the function doesn't exist yet).

- [ ] **Step 3: Write the minimal implementation**

```go
// orchestrator/internal/adenv/fromattackpath.go
package adenv

import "github.com/audspect/bas/internal/attackpath"

// aclEdgeKinds maps each attackpath.EdgeKind that represents an ACL grant
// (as opposed to reachability, group membership, or delegation) to its
// ACLRight. This is an explicit table, not a string cast: only the 4
// constants added by the AD-M03 fix (Owns, AllExtendedRights,
// AddKeyCredentialLink, ReadLAPSPassword) happen to share EdgeKind's
// kebab-case value -- the original 7 from AD-M01 use PascalCase
// ("GenericWrite") while attackpath uses kebab-case ("generic-write"), so
// casting one to the other would silently produce an ACLRight value that
// matches no defined constant. (Discovered by the Step 1 test itself --
// the first implementation attempt used a bare cast and the test caught
// it immediately: `generic-write` != `GenericWrite`.)
var aclEdgeKinds = map[attackpath.EdgeKind]ACLRight{
	attackpath.EdgeGenericAll:           ACLGenericAll,
	attackpath.EdgeGenericWrite:         ACLGenericWrite,
	attackpath.EdgeWriteOwner:           ACLWriteOwner,
	attackpath.EdgeWriteDacl:            ACLWriteDACL,
	attackpath.EdgeOwns:                 ACLOwns,
	attackpath.EdgeAllExtendedRights:    ACLAllExtendedRights,
	attackpath.EdgeForceChangePassword:  ACLForceChangePassword,
	attackpath.EdgeAddMember:            ACLAddMember,
	attackpath.EdgeAddSelf:              ACLAddSelf,
	attackpath.EdgeAddKeyCredentialLink: ACLAddKeyCredentialLink,
	attackpath.EdgeReadLAPSPassword:     ACLReadLAPSPassword,
}

// FromGraph maps an attackpath.Graph (SharpHound-derived Node/Edge data,
// AD-M03) into an Environment (AD-M01's richer ontology) -- a mapping of
// EXISTING data, never a redesign of attackpath's own SharpHound parsing.
//
// Several Environment categories have NO corresponding data anywhere in
// attackpath today and are left at their Go zero-value here on purpose,
// not approximated:
//   - Forest (Domains/Trusts/ForestRelationships): attackpath has no
//     domain or trust data at all.
//   - Authentication (Kerberos/NTLM/LDAP/SMB/RDP/WinRM config flags):
//     attackpath's SMB/WinRM/RDP edges are host-to-host REACHABILITY
//     relationships, not "is this protocol's signing/hardening enabled"
//     environment config -- a different concept entirely.
//   - Policy (GPOs/RestrictedGroups/SecurityPolicies) and PKI (CAs/
//     Templates): zero source data; SharpHound's gpos.json/domains.json
//     files are not parsed by attackpath at all yet.
//   - Identity.ServiceAccounts / Identity.ComputerAccounts: attackpath
//     does not distinguish a service account from a regular user, and a
//     computer account is already reported as a Machine, not separately
//     as an Identity -- mapping it to both would duplicate the same
//     object under two different shapes.
//   - Machines.AdminWorkstations: attackpath has no PAW (privileged
//     access workstation) classification distinct from a regular
//     workstation.
//
// Within the categories this DOES map, two fields also stay at zero-value
// for the same "no source data" reason, not because they were forgotten:
//   - User.Enabled: attackpath never tracks enabled/disabled state. This
//     field is always false here, and that MUST be read as "unknown",
//     never as "this account is disabled".
//   - User.SPNs: attackpath only tracks whether a user HAS an SPN
//     (Node.HasSPN, a bool), never the actual SPN string values. This
//     field stays nil rather than holding a fabricated placeholder.
//   - ConstrainedDelegation.ProtocolTransition: attackpath's
//     EdgeAllowedToDelegate carries no S4U2Self flag; always false here.
func FromGraph(g *attackpath.Graph) Environment {
	var env Environment

	groupMembers := map[string][]string{}
	constrained := map[string]*ConstrainedDelegation{}
	var constrainedOrder []string
	rbcd := map[string]*RBCDEntry{}
	var rbcdOrder []string

	for _, e := range g.Edges() {
		if right, ok := aclEdgeKinds[e.Kind]; ok {
			env.Authorization.ACLs = append(env.Authorization.ACLs, ACLEntry{
				Principal: e.From, Target: e.To, Right: right,
			})
			continue
		}
		switch e.Kind {
		case attackpath.EdgeMemberOf:
			groupMembers[e.To] = append(groupMembers[e.To], e.From)
		case attackpath.EdgeAllowedToDelegate:
			// From = the delegating computer (Principal), To = the target
			// SPN's service/computer (collected into Targets).
			cd, ok := constrained[e.From]
			if !ok {
				cd = &ConstrainedDelegation{Principal: e.From}
				constrained[e.From] = cd
				constrainedOrder = append(constrainedOrder, e.From)
			}
			cd.Targets = append(cd.Targets, e.To)
		case attackpath.EdgeAllowedToAct:
			// From = the principal allowed to act, To = the resource
			// computer accepting delegation (Target). OPPOSITE grantee
			// position from EdgeAllowedToDelegate above.
			r, ok := rbcd[e.To]
			if !ok {
				r = &RBCDEntry{Target: e.To}
				rbcd[e.To] = r
				rbcdOrder = append(rbcdOrder, e.To)
			}
			r.AllowedPrincipals = append(r.AllowedPrincipals, e.From)
		}
	}
	for _, principal := range constrainedOrder {
		env.Delegation.Constrained = append(env.Delegation.Constrained, *constrained[principal])
	}
	for _, target := range rbcdOrder {
		env.Delegation.RBCD = append(env.Delegation.RBCD, *rbcd[target])
	}

	for _, n := range g.Nodes() {
		switch n.Kind {
		case attackpath.KindUser:
			env.Identity.Users = append(env.Identity.Users, User{Name: n.Label, SID: n.ID})
			if n.HighValue {
				env.Identity.PrivilegedAccounts = append(env.Identity.PrivilegedAccounts, n.ID)
			}
			if n.UnconstrainedDelegation {
				env.Delegation.Unconstrained = append(env.Delegation.Unconstrained, n.ID)
			}
		case attackpath.KindGroup:
			env.Identity.Groups = append(env.Identity.Groups, Group{
				Name: n.Label, SID: n.ID, Members: groupMembers[n.ID],
			})
			if n.HighValue {
				env.Identity.PrivilegedAccounts = append(env.Identity.PrivilegedAccounts, n.ID)
			}
		case attackpath.KindHost:
			m := Machine{Hostname: n.Label, SID: n.ID}
			switch n.Role {
			case attackpath.RoleDC:
				env.Machines.DomainControllers = append(env.Machines.DomainControllers, m)
			case attackpath.RoleServer:
				env.Machines.Servers = append(env.Machines.Servers, m)
			default:
				env.Machines.Workstations = append(env.Machines.Workstations, m)
			}
			if n.UnconstrainedDelegation {
				env.Delegation.Unconstrained = append(env.Delegation.Unconstrained, n.ID)
			}
		}
	}

	return env
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd orchestrator && go test ./internal/adenv/... -v`
Expected: PASS — all tests in the package, including the 3 pre-existing ones from AD-M01/AD-M03 (`TestEnvironment_JSONRoundTrip_FullyPopulated`, `TestEnvironment_JSONRoundTrip_ZeroValue`, `TestACLRight_MatchesAttackpathEdgeKindValues`) plus the new `TestFromGraph_MapsEveryDerivableCategory`.

- [ ] **Step 5: Run gofmt, go vet, and confirm no import cycle**

Run: `cd orchestrator && gofmt -l internal/adenv/ && go vet ./internal/adenv/... && go build ./...`
Expected: `gofmt -l` and `go vet` print nothing; `go build ./...` succeeds (proves `adenv → attackpath` is a valid one-way dependency with no cycle, and nothing else in the module broke).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/adenv/fromattackpath.go orchestrator/internal/adenv/fromattackpath_test.go
git commit -m "$(cat <<'EOF'
feat(adenv): map attackpath's graph into the AD-M01 ontology (AD-M02)

FromGraph(g *attackpath.Graph) Environment populates Identity
(Users/Groups/PrivilegedAccounts, partial -- Enabled/SPNs have no
source data), Machines, Delegation (all 3 types), and
Authorization.ACLs from the existing SharpHound-derived graph.
Forest/Authentication/Policy/PKI stay at zero-value: attackpath has
no domain/trust/GPO/PKI data and SMB/WinRM/RDP edges are reachability,
not hardening config -- a mapping task per the user's standing
correction, not a parser redesign.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Execution Handoff

**Execution method: Native (inline, this session), per the user's standing preference and the wave/phase process they set for this initiative — no subagent dispatch.** One task, one new file, mapping already-tested data between two already-tested packages; proceeding directly to execution via `superpowers:executing-plans`.
