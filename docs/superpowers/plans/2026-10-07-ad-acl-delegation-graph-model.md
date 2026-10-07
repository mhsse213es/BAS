# AD ACL + Kerberos Delegation Graph Model Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend Audspect's native attack-path engine (`orchestrator/internal/attackpath`) so it parses ACL rights and Kerberos delegation relationships that SharpHound already collects but the parser currently discards, making real AD privilege-escalation paths (e.g. `User --GenericWrite--> ServiceAccount --Kerberoastable--> DomainAdmin`) discoverable through the existing path-finding functions with zero changes to those functions.

**Architecture:** Three additive extensions to one existing package: (1) new `EdgeKind` constants + a `Node.UnconstrainedDelegation` flag in `graph.go`, (2) new SharpHound JSON fields parsed into those edges/flag in `sharphound.go`, (3) two existing node-merge functions (`build.go`'s `mergeNode`, `reconcile.go`'s `enrichHost`) updated so the new flag survives multi-collection merging and host reconciliation — both discovered by reading the real merge code, not assumed from the spec. No changes to `ShortestPath`/`ShortestPathToDomainAdmin`/`CanReachDomainAdmin` (traversal is already edge-kind-agnostic) and no frontend changes (the UI already renders `edge.kind` generically).

**Tech Stack:** Go (stdlib `encoding/json`, `strings`), Go's built-in `testing` package, following this package's existing test conventions exactly.

**Spec:** `docs/superpowers/specs/2026-10-07-ad-acl-delegation-graph-model-design.md`

## Global Constraints

- Every new edge's `From`/`To` direction must match the spec's direction table exactly: `From` = the node an attacker must already control, `To` = the node control flows to. Get `allowed-to-delegate` vs `allowed-to-act` backwards and the engine reports the wrong principal can impersonate the wrong target.
- Unconstrained delegation is a `Node` flag, never an `Edge` — no code in this plan may create an edge for it.
- No new `EdgeKind` may be added to `graph.go`'s `reachKinds` map (ACL/delegation edges are identity-escalation, not network-reachability).
- `Edge` (`From string`, `To string`, `Kind EdgeKind`) must remain a comparable type — never add a map/slice field to it. `Edge` is used as a map key in `build.go` and `reconcile.go` for deduplication.
- Out of scope for this plan (per the spec's non-goals): ADCS, GPO abuse edges, domain trust edges, OU nodes, path-classification/reporting, and any executable attack/exploit logic. Do not add any of these even opportunistically.
- All new JSON struct tags follow this package's existing casing convention exactly as SharpHound emits it (e.g. `"PrincipalSID"`, `"RightName"` — PascalCase to match `bhMember`'s `"ObjectIdentifier"`/`"ObjectType"`; `"AllowedToDelegate"`/`"AllowedToAct"` PascalCase on `bhComputer`; `"unconstraineddelegation"` lowercase on `bhProps`, matching the existing `"name"`/`"domain"` lowercase convention on that struct).
- RightName matching must be case-insensitive (`strings.EqualFold`), matching this file's existing pattern for `ObjectType` comparisons (e.g. `strings.EqualFold(m.ObjectType, "Computer")`) — SharpHound's casing is not guaranteed stable across versions.

## Review Focus

- Unrecognized ACE `RightName` (a right this phase doesn't model, or a future BloodHound addition) must be skipped — never crash, never silently miscategorize into the wrong `EdgeKind`. Covered in Task 1.
- An ACE with an empty/missing `PrincipalSID` must not produce a bogus edge with an empty `From` — the parser should skip it explicitly rather than relying on `AddEdge`'s downstream empty-string guard. Covered in Task 1.
- A self-referential ACE or delegation entry (principal == target object) must not hang or crash path-finding — `ShortestPath`'s BFS already marks the start node seen before traversal, so a self-loop edge is structurally inert, but this must be proven by a test, not assumed. Covered in Task 1 and Task 2.
- Duplicate ACE entries for the same (principal, right, object) triple — common in real BloodHound data from inherited ACEs — must not produce visibly duplicated edges in the final built graph. `BuildGraph`'s existing `map[Edge]bool` dedup already handles this structurally; this must be proven end-to-end through the SharpHound parsing path specifically. Covered in Task 1.
- A computer/user object that has `Aces` but no `AllowedToDelegate`/`AllowedToAct`/`unconstraineddelegation` (or vice versa) must populate only what is actually present in its JSON, never crash from a field some other object happened to have. Covered across Tasks 1-3 by fixtures that vary which fields are present per object.

---

### Task 1: ACE-based ACL edges on computers, users, and groups

**Files:**
- Modify: `orchestrator/internal/attackpath/graph.go:52-60` (new `EdgeKind` constants)
- Modify: `orchestrator/internal/attackpath/sharphound.go` (new `bhAce` type, `Aces` field on `bhComputer`/`bhUser`/`bhGroup`, ACE→edge construction)
- Test: `orchestrator/internal/attackpath/sharphound_test.go`

**Interfaces:**
- Consumes: existing `Collection`, `Edge`, `Graph`, `buildSharpHoundCollection(computers []bhComputer, users []bhUser, groups []bhGroup) Collection` (unchanged signature).
- Produces: `EdgeGenericAll`, `EdgeGenericWrite`, `EdgeWriteOwner`, `EdgeWriteDacl`, `EdgeOwns`, `EdgeAllExtendedRights`, `EdgeForceChangePassword`, `EdgeAddMember`, `EdgeAddSelf`, `EdgeAddKeyCredentialLink`, `EdgeReadLAPSPassword` (all `EdgeKind`, consumed by Task 2's and Task 3's tests only incidentally — no other task depends on these beyond their own tests). `bhAce` struct (consumed nowhere else in this plan).

- [ ] **Step 1: Write the failing test for ACE → edge construction (table-driven, all 11 rights)**

Add to `orchestrator/internal/attackpath/sharphound_test.go`:

```go
const shComputersWithAces = `{"meta":{"type":"computers","count":1},"data":[
  {"ObjectIdentifier":"S-1-5-21-1-1-1-2001","Properties":{"name":"FILESRV02.CORP.LOCAL","domain":"CORP.LOCAL"},
   "LocalAdmins":{"Results":[]},"Sessions":{"Results":[]},
   "Aces":[
     {"PrincipalSID":"S-1-5-21-1-1-1-3001","RightName":"GenericAll","IsInherited":false},
     {"PrincipalSID":"S-1-5-21-1-1-1-3002","RightName":"GenericWrite","IsInherited":false},
     {"PrincipalSID":"S-1-5-21-1-1-1-3003","RightName":"WriteOwner","IsInherited":false},
     {"PrincipalSID":"S-1-5-21-1-1-1-3004","RightName":"WriteDacl","IsInherited":false},
     {"PrincipalSID":"S-1-5-21-1-1-1-3005","RightName":"Owns","IsInherited":false},
     {"PrincipalSID":"S-1-5-21-1-1-1-3006","RightName":"AllExtendedRights","IsInherited":false},
     {"PrincipalSID":"S-1-5-21-1-1-1-3007","RightName":"ForceChangePassword","IsInherited":false},
     {"PrincipalSID":"S-1-5-21-1-1-1-3008","RightName":"AddMember","IsInherited":false},
     {"PrincipalSID":"S-1-5-21-1-1-1-3009","RightName":"AddSelf","IsInherited":false},
     {"PrincipalSID":"S-1-5-21-1-1-1-3010","RightName":"AddKeyCredentialLink","IsInherited":false},
     {"PrincipalSID":"S-1-5-21-1-1-1-3011","RightName":"ReadLAPSPassword","IsInherited":false}
   ]}
]}`

func TestParseSharpHoundFiles_AceRights_ProduceCorrectEdgeKinds(t *testing.T) {
	c := parseSharpHoundFiles([][]byte{[]byte(shComputersWithAces)})
	g := BuildGraph(c)

	cases := []struct {
		principal string
		want      EdgeKind
	}{
		{"S-1-5-21-1-1-1-3001", EdgeGenericAll},
		{"S-1-5-21-1-1-1-3002", EdgeGenericWrite},
		{"S-1-5-21-1-1-1-3003", EdgeWriteOwner},
		{"S-1-5-21-1-1-1-3004", EdgeWriteDacl},
		{"S-1-5-21-1-1-1-3005", EdgeOwns},
		{"S-1-5-21-1-1-1-3006", EdgeAllExtendedRights},
		{"S-1-5-21-1-1-1-3007", EdgeForceChangePassword},
		{"S-1-5-21-1-1-1-3008", EdgeAddMember},
		{"S-1-5-21-1-1-1-3009", EdgeAddSelf},
		{"S-1-5-21-1-1-1-3010", EdgeAddKeyCredentialLink},
		{"S-1-5-21-1-1-1-3011", EdgeReadLAPSPassword},
	}
	for _, tc := range cases {
		found := false
		for _, e := range g.Edges() {
			if e.From == tc.principal && e.To == "S-1-5-21-1-1-1-2001" && e.Kind == tc.want {
				found = true
			}
		}
		if !found {
			t.Errorf("expected edge {From: %s, To: FILESRV02, Kind: %s} not found", tc.principal, tc.want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/attackpath/... -run TestParseSharpHoundFiles_AceRights_ProduceCorrectEdgeKinds -v`
Expected: build FAILURE — `EdgeGenericAll` (and the other 10 constants) undefined, and `bhComputer` has no field `Aces` in the composite literal. This is a compile error, which is the correct RED state for a test that references symbols that don't exist yet.

- [ ] **Step 3: Add the new EdgeKind constants**

Modify `orchestrator/internal/attackpath/graph.go` lines 52-60:

```go
const (
	EdgeSMB        EdgeKind = "smb"         // From can reach To over SMB (445)
	EdgeWinRM      EdgeKind = "winrm"       // From can reach To over WinRM (5985/5986)
	EdgeRDP        EdgeKind = "rdp"         // From can reach To over RDP (3389)
	EdgeAdminTo    EdgeKind = "admin-to"    // user/group is local admin on host
	EdgeHasSession EdgeKind = "has-session" // host has an interactive session for user (creds harvestable)
	EdgeMemberOf   EdgeKind = "member-of"   // user/group is a member of group
	EdgeCredential EdgeKind = "credential"  // reusable credential edge (e.g. shared local-admin password)

	// ACL-abuse edges (from SharpHound's Aces arrays). From = the ACE's
	// PrincipalSID (the grantee, who an attacker must control); To = the
	// object the Aces array is attached to (whose rights the grantee holds).
	// See docs/superpowers/specs/2026-10-07-ad-acl-delegation-graph-model-design.md.
	EdgeGenericAll           EdgeKind = "generic-all"
	EdgeGenericWrite         EdgeKind = "generic-write"
	EdgeWriteOwner           EdgeKind = "write-owner"
	EdgeWriteDacl            EdgeKind = "write-dacl"
	EdgeOwns                 EdgeKind = "owns"
	EdgeAllExtendedRights    EdgeKind = "all-extended-rights"
	EdgeForceChangePassword  EdgeKind = "force-change-password"
	EdgeAddMember            EdgeKind = "add-member"
	EdgeAddSelf              EdgeKind = "add-self"
	EdgeAddKeyCredentialLink EdgeKind = "add-key-credential-link"
	EdgeReadLAPSPassword     EdgeKind = "read-laps-password"
)
```

- [ ] **Step 4: Add the `bhAce` type and `Aces` field, and the ACE→edge construction**

Modify `orchestrator/internal/attackpath/sharphound.go`. Add the `bhAce` type near `bhMember` (after line 41):

```go
// bhAce is one Access Control Entry: a principal's right over the object
// whose Aces array this entry appears in.
type bhAce struct {
	PrincipalSID string `json:"PrincipalSID"`
	RightName    string `json:"RightName"`
	IsInherited  bool   `json:"IsInherited"` // parsed, not yet used by any logic
}

// aceRightEdgeKinds maps a BloodHound ACE RightName (case-insensitively) to
// the EdgeKind it represents. An unrecognized RightName is intentionally
// absent and must be skipped by the caller, never fatal.
var aceRightEdgeKinds = map[string]EdgeKind{
	"genericall":          EdgeGenericAll,
	"genericwrite":        EdgeGenericWrite,
	"writeowner":          EdgeWriteOwner,
	"writedacl":           EdgeWriteDacl,
	"owns":                EdgeOwns,
	"allextendedrights":   EdgeAllExtendedRights,
	"forcechangepassword": EdgeForceChangePassword,
	"addmember":           EdgeAddMember,
	"addself":             EdgeAddSelf,
	"addkeycredentiallink": EdgeAddKeyCredentialLink,
	"readlapspassword":    EdgeReadLAPSPassword,
}

// addAceEdges appends one edge per recognized, well-formed ACE in aces,
// where objectID is the object the Aces array is attached to (the ACL
// target). Unrecognized RightName values and ACEs with no PrincipalSID are
// skipped, never fatal — consistent with this file's defensive-parsing
// principle.
func addAceEdges(edges *[]Edge, objectID string, aces []bhAce) {
	for _, ace := range aces {
		if ace.PrincipalSID == "" {
			continue
		}
		kind, ok := aceRightEdgeKinds[strings.ToLower(ace.RightName)]
		if !ok {
			continue
		}
		*edges = append(*edges, Edge{From: ace.PrincipalSID, To: objectID, Kind: kind})
	}
}
```

Add an `Aces []bhAce` field to `bhComputer` (after the `Sessions` field, before its closing brace), `bhUser` (after `Properties`), and `bhGroup` (after `Properties`):

```go
type bhComputer struct {
	ObjectIdentifier string  `json:"ObjectIdentifier"`
	Properties       bhProps `json:"Properties"`
	LocalAdmins      struct {
		Results []bhMember `json:"Results"`
	} `json:"LocalAdmins"`
	Sessions struct {
		Results []struct {
			UserSID     string `json:"UserSID"`
			ComputerSID string `json:"ComputerSID"`
		} `json:"Results"`
	} `json:"Sessions"`
	Aces []bhAce `json:"Aces"`
}

type bhUser struct {
	ObjectIdentifier string  `json:"ObjectIdentifier"`
	Properties       bhProps `json:"Properties"`
	Aces             []bhAce `json:"Aces"`
}

type bhGroup struct {
	ObjectIdentifier string     `json:"ObjectIdentifier"`
	Properties       bhProps    `json:"Properties"`
	Members          []bhMember `json:"Members"`
	Aces             []bhAce    `json:"Aces"`
}
```

In `buildSharpHoundCollection`, call `addAceEdges` for each object type. In the users loop (around line 155-162):

```go
for _, u := range users {
	if u.ObjectIdentifier == "" {
		continue
	}
	c.Nodes = append(c.Nodes, Node{
		ID: u.ObjectIdentifier, Kind: KindUser, Label: labelOf(u.Properties, u.ObjectIdentifier),
	})
	addAceEdges(&c.Edges, u.ObjectIdentifier, u.Aces)
}
```

In the groups loop (around line 164-178), after the existing `Members` loop:

```go
for _, g := range groups {
	if g.ObjectIdentifier == "" {
		continue
	}
	c.Nodes = append(c.Nodes, Node{
		ID: g.ObjectIdentifier, Kind: KindGroup,
		Label: labelOf(g.Properties, g.ObjectIdentifier), HighValue: isHighValue(g.ObjectIdentifier),
	})
	for _, m := range g.Members {
		if m.ObjectIdentifier == "" {
			continue
		}
		c.Edges = append(c.Edges, Edge{From: m.ObjectIdentifier, To: g.ObjectIdentifier, Kind: EdgeMemberOf})
	}
	addAceEdges(&c.Edges, g.ObjectIdentifier, g.Aces)
}
```

In the computers loop (around line 180-208), after the existing `Sessions` loop:

```go
for _, cm := range computers {
	if cm.ObjectIdentifier == "" {
		continue
	}
	role := RoleEndpoint
	if dcSIDs[cm.ObjectIdentifier] {
		role = RoleDC
	} else if isServerName(cm.Properties.Name) {
		role = RoleServer
	}
	c.Nodes = append(c.Nodes, Node{
		ID: cm.ObjectIdentifier, Kind: KindHost,
		Label: labelOf(cm.Properties, cm.ObjectIdentifier), Role: role,
	})
	for _, a := range cm.LocalAdmins.Results {
		if a.ObjectIdentifier == "" {
			continue
		}
		c.Edges = append(c.Edges, Edge{From: a.ObjectIdentifier, To: cm.ObjectIdentifier, Kind: EdgeAdminTo})
	}
	for _, s := range cm.Sessions.Results {
		if s.UserSID == "" {
			continue
		}
		c.Edges = append(c.Edges, Edge{From: cm.ObjectIdentifier, To: s.UserSID, Kind: EdgeHasSession})
	}
	addAceEdges(&c.Edges, cm.ObjectIdentifier, cm.Aces)
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/attackpath/... -run TestParseSharpHoundFiles_AceRights_ProduceCorrectEdgeKinds -v`
Expected: `PASS`

- [ ] **Step 6: Write the failing test proving traversal needs no engine changes**

Add to `sharphound_test.go`:

```go
const shComputersAclPathToDomainAdmin = `{"meta":{"type":"computers","count":1},"data":[
  {"ObjectIdentifier":"S-1-5-21-1-1-1-4001","Properties":{"name":"SVCHOST01.CORP.LOCAL","domain":"CORP.LOCAL"},
   "LocalAdmins":{"Results":[]},"Sessions":{"Results":[]},
   "Aces":[{"PrincipalSID":"S-1-5-21-1-1-1-4100","RightName":"GenericWrite","IsInherited":false}]}
]}`

const shUsersAclPathToDomainAdmin = `{"meta":{"type":"users","count":1},"data":[
  {"ObjectIdentifier":"S-1-5-21-1-1-1-4100","Properties":{"name":"LOWPRIV@CORP.LOCAL","domain":"CORP.LOCAL"}}
]}`

const shGroupsAclPathToDomainAdmin = `{"meta":{"type":"groups","count":1},"data":[
  {"ObjectIdentifier":"S-1-5-21-1-1-1-512","Properties":{"name":"DOMAIN ADMINS@CORP.LOCAL"},
   "Members":[{"ObjectIdentifier":"S-1-5-21-1-1-1-4001","ObjectType":"Computer"}]}
]}`

func TestParseSharpHoundFiles_AclEdge_IsDiscoverableByExistingPathFinding(t *testing.T) {
	c := parseSharpHoundFiles([][]byte{
		[]byte(shComputersAclPathToDomainAdmin),
		[]byte(shUsersAclPathToDomainAdmin),
		[]byte(shGroupsAclPathToDomainAdmin),
	})
	g := BuildGraph(c)

	// LOWPRIV has GenericWrite on SVCHOST01, and SVCHOST01 is a member of
	// Domain Admins. The ONLY path from LOWPRIV to Domain Admins is through
	// the new generic-write edge -- proving ShortestPathToDomainAdmin needs
	// no changes to find an ACL-abuse path.
	path := g.ShortestPathToDomainAdmin("S-1-5-21-1-1-1-4100")
	if path == nil {
		t.Fatal("expected a path from LOWPRIV to Domain Admins via the new generic-write edge, got nil")
	}
	if path[0].Kind != EdgeGenericWrite {
		t.Fatalf("expected the first edge to be generic-write, got %s", path[0].Kind)
	}
	if !g.CanReachDomainAdmin() {
		t.Fatal("CanReachDomainAdmin() should be true once an ACL edge exists in the path")
	}
}
```

- [ ] **Step 7: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/attackpath/... -run TestParseSharpHoundFiles_AclEdge_IsDiscoverableByExistingPathFinding -v`
Expected: `PASS` — confirms zero changes to `analytics.go` were needed.

- [ ] **Step 8: Write the failing tests for the Review Focus edge cases**

Add to `sharphound_test.go`:

```go
const shComputersMalformedAces = `{"meta":{"type":"computers","count":1},"data":[
  {"ObjectIdentifier":"S-1-5-21-1-1-1-5001","Properties":{"name":"SRV99.CORP.LOCAL","domain":"CORP.LOCAL"},
   "LocalAdmins":{"Results":[]},"Sessions":{"Results":[]},
   "Aces":[
     {"PrincipalSID":"","RightName":"GenericAll","IsInherited":false},
     {"PrincipalSID":"S-1-5-21-1-1-1-5100","RightName":"SomeFutureRightWeDontModel","IsInherited":false},
     {"PrincipalSID":"S-1-5-21-1-1-1-5001","RightName":"GenericAll","IsInherited":false},
     {"PrincipalSID":"S-1-5-21-1-1-1-5200","RightName":"genericwrite","IsInherited":true},
     {"PrincipalSID":"S-1-5-21-1-1-1-5200","RightName":"GenericWrite","IsInherited":true}
   ]}
]}`

func TestParseSharpHoundFiles_Aces_SkipsEmptyPrincipalAndUnrecognizedRight(t *testing.T) {
	c := parseSharpHoundFiles([][]byte{[]byte(shComputersMalformedAces)})
	g := BuildGraph(c)

	for _, e := range g.Edges() {
		if e.From == "" {
			t.Fatal("an edge with an empty PrincipalSID must never be created")
		}
		if e.From == "S-1-5-21-1-1-1-5100" {
			t.Fatal("an unrecognized RightName must never produce an edge")
		}
	}
}

func TestParseSharpHoundFiles_Aces_SelfReferentialAceDoesNotHangPathFinding(t *testing.T) {
	// SRV99 has GenericAll on itself (S-1-5-21-1-1-1-5001 -> S-1-5-21-1-1-1-5001).
	c := parseSharpHoundFiles([][]byte{[]byte(shComputersMalformedAces)})
	g := BuildGraph(c)

	// ShortestPath must return promptly (no infinite loop) and correctly
	// report "no path" for an unrelated target.
	if p := g.ShortestPath("S-1-5-21-1-1-1-5001", "nonexistent-target"); p != nil {
		t.Fatalf("expected nil for an unreachable target, got %+v", p)
	}
}

func TestParseSharpHoundFiles_Aces_CaseInsensitiveRightNameMatching(t *testing.T) {
	c := parseSharpHoundFiles([][]byte{[]byte(shComputersMalformedAces)})
	g := BuildGraph(c)

	found := false
	for _, e := range g.Edges() {
		if e.From == "S-1-5-21-1-1-1-5200" && e.Kind == EdgeGenericWrite {
			found = true
		}
	}
	if !found {
		t.Fatal("lowercase RightName \"genericwrite\" must still match EdgeGenericWrite")
	}
}

func TestParseSharpHoundFiles_Aces_DuplicateAceDoesNotDuplicateEdgeAfterBuildGraph(t *testing.T) {
	// shComputersMalformedAces has two identical {5200 -> 5001, GenericWrite}
	// ACEs (the IsInherited:true one and the un-inherited duplicate below it).
	c := parseSharpHoundFiles([][]byte{[]byte(shComputersMalformedAces)})
	g := BuildGraph(c)

	count := 0
	for _, e := range g.Edges() {
		if e.From == "S-1-5-21-1-1-1-5200" && e.To == "S-1-5-21-1-1-1-5001" && e.Kind == EdgeGenericWrite {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 deduplicated generic-write edge from a duplicate ACE pair, got %d", count)
	}
}
```

- [ ] **Step 9: Run tests to verify they fail for the right reason, then pass**

Run: `cd orchestrator && go test ./internal/attackpath/... -run TestParseSharpHoundFiles_Aces -v`
Expected (before Step 4's `strings.ToLower` case-insensitive lookup and `addAceEdges`'s empty-SID/unrecognized-right skip): some of these already pass once Step 4's code is in place, since `addAceEdges` as written in Step 4 already skips empty `PrincipalSID` and unrecognized `RightName`, and already lowercases via `strings.ToLower(ace.RightName)`. Run the tests now (after Step 4's code already exists from this same task) and confirm all four `PASS`. If `TestParseSharpHoundFiles_Aces_CaseInsensitiveRightNameMatching` fails, the lookup map in Step 4 was written with non-lowercase keys or the lookup is missing `strings.ToLower` — fix the lookup, not the test.

- [ ] **Step 10: Run the full package test suite**

Run: `cd orchestrator && go test ./internal/attackpath/... -v`
Expected: all tests `PASS`, including every pre-existing test in the package (`TestParseSharpHoundFiles`, `TestParseSharpHoundZip`, and every `*_test.go` file in the package) — confirms nothing in Task 1 broke the existing lateral-movement/reachability behavior.

- [ ] **Step 11: Commit**

```bash
cd orchestrator
git add internal/attackpath/graph.go internal/attackpath/sharphound.go internal/attackpath/sharphound_test.go
git commit -m "feat(attackpath): parse SharpHound ACEs into ACL-abuse graph edges

Adds 11 new EdgeKind values (generic-all, generic-write, write-owner,
write-dacl, owns, all-extended-rights, force-change-password, add-member,
add-self, add-key-credential-link, read-laps-password) and parses them
from SharpHound's Aces arrays on computers, users, and groups. No changes
to ShortestPath/ShortestPathToDomainAdmin/CanReachDomainAdmin -- traversal
was already edge-kind-agnostic, proven by a test rather than assumed.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 2: Kerberos delegation edges (constrained delegation + RBCD)

**Files:**
- Modify: `orchestrator/internal/attackpath/graph.go` (two new `EdgeKind` constants)
- Modify: `orchestrator/internal/attackpath/sharphound.go` (new fields on `bhComputer`, edge construction)
- Test: `orchestrator/internal/attackpath/sharphound_test.go`

**Interfaces:**
- Consumes: `bhComputer`, `buildSharpHoundCollection`, `Edge`, `Collection` (from Task 1, unchanged).
- Produces: `EdgeAllowedToDelegate`, `EdgeAllowedToAct` (`EdgeKind`). No other task depends on these.

- [ ] **Step 1: Write the failing test for both delegation edge directions**

Add to `sharphound_test.go`:

```go
const shComputersDelegation = `{"meta":{"type":"computers","count":2},"data":[
  {"ObjectIdentifier":"S-1-5-21-1-1-1-6001","Properties":{"name":"WEBSVC01.CORP.LOCAL","domain":"CORP.LOCAL"},
   "LocalAdmins":{"Results":[]},"Sessions":{"Results":[]},
   "AllowedToDelegate":["S-1-5-21-1-1-1-6002"]},
  {"ObjectIdentifier":"S-1-5-21-1-1-1-6002","Properties":{"name":"TARGET01.CORP.LOCAL","domain":"CORP.LOCAL"},
   "LocalAdmins":{"Results":[]},"Sessions":{"Results":[]},
   "AllowedToAct":[{"ObjectIdentifier":"S-1-5-21-1-1-1-6001","ObjectType":"Computer"}]}
]}`

func TestParseSharpHoundFiles_Delegation_ProducesCorrectlyDirectedEdges(t *testing.T) {
	c := parseSharpHoundFiles([][]byte{[]byte(shComputersDelegation)})
	g := BuildGraph(c)

	// AllowedToDelegate: WEBSVC01 (the computer carrying the property) is
	// From; TARGET01 (the listed target) is To -- control WEBSVC01, gain the
	// ability to authenticate to TARGET01 as an arbitrary user.
	foundDelegate := false
	for _, e := range g.Edges() {
		if e.From == "S-1-5-21-1-1-1-6001" && e.To == "S-1-5-21-1-1-1-6002" && e.Kind == EdgeAllowedToDelegate {
			foundDelegate = true
		}
	}
	if !foundDelegate {
		t.Fatal("expected {From: WEBSVC01, To: TARGET01, Kind: allowed-to-delegate}")
	}

	// AllowedToAct: WEBSVC01 (the listed principal) is From; TARGET01 (the
	// computer carrying the property) is To -- control WEBSVC01, gain the
	// ability to impersonate arbitrary users to TARGET01 via RBCD. Note the
	// direction is the OPPOSITE of AllowedToDelegate relative to "the
	// computer carrying the JSON property" -- this is exactly the mistake
	// the spec's direction table exists to prevent.
	foundAct := false
	for _, e := range g.Edges() {
		if e.From == "S-1-5-21-1-1-1-6001" && e.To == "S-1-5-21-1-1-1-6002" && e.Kind == EdgeAllowedToAct {
			foundAct = true
		}
	}
	if !foundAct {
		t.Fatal("expected {From: WEBSVC01, To: TARGET01, Kind: allowed-to-act}")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/attackpath/... -run TestParseSharpHoundFiles_Delegation_ProducesCorrectlyDirectedEdges -v`
Expected: build FAILURE — `EdgeAllowedToDelegate`/`EdgeAllowedToAct` undefined, `bhComputer` has no `AllowedToDelegate`/`AllowedToAct` field.

- [ ] **Step 3: Add the new EdgeKind constants**

Modify `orchestrator/internal/attackpath/graph.go`, appending to the const block added in Task 1:

```go
	// Kerberos delegation-abuse edges. See the spec's direction table --
	// AllowedToDelegate and AllowedToAct have OPPOSITE grantee positions
	// relative to "the computer carrying the JSON property".
	EdgeAllowedToDelegate EdgeKind = "allowed-to-delegate"
	EdgeAllowedToAct      EdgeKind = "allowed-to-act"
```

- [ ] **Step 4: Add the new fields and edge construction**

Modify `orchestrator/internal/attackpath/sharphound.go`. Add fields to `bhComputer` (from Task 1's version):

```go
type bhComputer struct {
	ObjectIdentifier string  `json:"ObjectIdentifier"`
	Properties       bhProps `json:"Properties"`
	LocalAdmins      struct {
		Results []bhMember `json:"Results"`
	} `json:"LocalAdmins"`
	Sessions struct {
		Results []struct {
			UserSID     string `json:"UserSID"`
			ComputerSID string `json:"ComputerSID"`
		} `json:"Results"`
	} `json:"Sessions"`
	Aces              []bhAce    `json:"Aces"`
	AllowedToDelegate []string   `json:"AllowedToDelegate"`
	AllowedToAct      []bhMember `json:"AllowedToAct"`
}
```

In `buildSharpHoundCollection`'s computers loop, after the `addAceEdges` call added in Task 1:

```go
	addAceEdges(&c.Edges, cm.ObjectIdentifier, cm.Aces)
	// AllowedToDelegate: cm (the computer with this property) is From; each
	// listed target is To.
	for _, target := range cm.AllowedToDelegate {
		if target == "" {
			continue
		}
		c.Edges = append(c.Edges, Edge{From: cm.ObjectIdentifier, To: target, Kind: EdgeAllowedToDelegate})
	}
	// AllowedToAct: each listed principal is From; cm (the computer with this
	// property) is To. Direction is the OPPOSITE of AllowedToDelegate above.
	for _, p := range cm.AllowedToAct {
		if p.ObjectIdentifier == "" {
			continue
		}
		c.Edges = append(c.Edges, Edge{From: p.ObjectIdentifier, To: cm.ObjectIdentifier, Kind: EdgeAllowedToAct})
	}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/attackpath/... -run TestParseSharpHoundFiles_Delegation_ProducesCorrectlyDirectedEdges -v`
Expected: `PASS`

- [ ] **Step 6: Write the failing tests for the Review Focus edge cases**

Add to `sharphound_test.go`:

```go
const shComputersDelegationMissingFields = `{"meta":{"type":"computers","count":1},"data":[
  {"ObjectIdentifier":"S-1-5-21-1-1-1-7001","Properties":{"name":"SRV77.CORP.LOCAL","domain":"CORP.LOCAL"},
   "LocalAdmins":{"Results":[]},"Sessions":{"Results":[]}}
]}`

func TestParseSharpHoundFiles_Delegation_MissingFieldsDoNotCrash(t *testing.T) {
	c := parseSharpHoundFiles([][]byte{[]byte(shComputersDelegationMissingFields)})
	g := BuildGraph(c)

	for _, e := range g.Edges() {
		if e.Kind == EdgeAllowedToDelegate || e.Kind == EdgeAllowedToAct {
			t.Fatalf("expected no delegation edges for an object with neither field present, got %+v", e)
		}
	}
}

const shComputersSelfDelegation = `{"meta":{"type":"computers","count":1},"data":[
  {"ObjectIdentifier":"S-1-5-21-1-1-1-8001","Properties":{"name":"SRV88.CORP.LOCAL","domain":"CORP.LOCAL"},
   "LocalAdmins":{"Results":[]},"Sessions":{"Results":[]},
   "AllowedToDelegate":["S-1-5-21-1-1-1-8001"]}
]}`

func TestParseSharpHoundFiles_Delegation_SelfReferentialDoesNotHangPathFinding(t *testing.T) {
	c := parseSharpHoundFiles([][]byte{[]byte(shComputersSelfDelegation)})
	g := BuildGraph(c)

	if p := g.ShortestPath("S-1-5-21-1-1-1-8001", "nonexistent-target"); p != nil {
		t.Fatalf("expected nil for an unreachable target, got %+v", p)
	}
}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/attackpath/... -run TestParseSharpHoundFiles_Delegation -v`
Expected: all `PASS`

- [ ] **Step 8: Run the full package test suite**

Run: `cd orchestrator && go test ./internal/attackpath/... -v`
Expected: all tests `PASS`, including Task 1's tests and every pre-existing test.

- [ ] **Step 9: Commit**

```bash
cd orchestrator
git add internal/attackpath/graph.go internal/attackpath/sharphound.go internal/attackpath/sharphound_test.go
git commit -m "feat(attackpath): parse SharpHound AllowedToDelegate/AllowedToAct into delegation-abuse edges

Adds allowed-to-delegate and allowed-to-act EdgeKinds. Direction is
deliberately opposite between the two relative to which side carries the
JSON property -- see the spec's direction table -- verified by a test
that would fail if the two were accidentally swapped.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 3: Unconstrained delegation flag, survives merge and reconciliation

**Files:**
- Modify: `orchestrator/internal/attackpath/graph.go` (new `Node.UnconstrainedDelegation` field)
- Modify: `orchestrator/internal/attackpath/sharphound.go` (new `bhProps` field, set-on-parse for computers and users)
- Modify: `orchestrator/internal/attackpath/build.go` (`mergeNode` OR-merge, matching the existing `HighValue` pattern)
- Modify: `orchestrator/internal/attackpath/reconcile.go` (`enrichHost` OR-merge, matching the existing `HighValue` pattern)
- Test: `orchestrator/internal/attackpath/sharphound_test.go`, `orchestrator/internal/attackpath/build_test.go`, `orchestrator/internal/attackpath/reconcile_test.go`

**Interfaces:**
- Consumes: `Node`, `bhProps`, `mergeNode`, `enrichHost` (all existing, from Task 1/2 unchanged except as modified here).
- Produces: `Node.UnconstrainedDelegation bool`. No other task depends on this.

- [ ] **Step 1: Write the failing test for the flag itself, and for "no edge is created"**

Add to `sharphound_test.go`:

```go
const shComputersUnconstrainedDelegation = `{"meta":{"type":"computers","count":1},"data":[
  {"ObjectIdentifier":"S-1-5-21-1-1-1-9001","Properties":{"name":"LEGACY01.CORP.LOCAL","domain":"CORP.LOCAL","unconstraineddelegation":true},
   "LocalAdmins":{"Results":[]},"Sessions":{"Results":[]}}
]}`

const shUsersUnconstrainedDelegation = `{"meta":{"type":"users","count":1},"data":[
  {"ObjectIdentifier":"S-1-5-21-1-1-1-9100","Properties":{"name":"SVCACCT@CORP.LOCAL","domain":"CORP.LOCAL","unconstraineddelegation":true}}
]}`

func TestParseSharpHoundFiles_UnconstrainedDelegation_SetsFlagNotEdge(t *testing.T) {
	c := parseSharpHoundFiles([][]byte{
		[]byte(shComputersUnconstrainedDelegation),
		[]byte(shUsersUnconstrainedDelegation),
	})
	before := len(c.Edges)
	g := BuildGraph(c)

	host, ok := g.Node("S-1-5-21-1-1-1-9001")
	if !ok || !host.UnconstrainedDelegation {
		t.Fatalf("expected LEGACY01.UnconstrainedDelegation == true, got %+v (ok=%v)", host, ok)
	}
	user, ok := g.Node("S-1-5-21-1-1-1-9100")
	if !ok || !user.UnconstrainedDelegation {
		t.Fatalf("expected SVCACCT.UnconstrainedDelegation == true, got %+v (ok=%v)", user, ok)
	}
	// The property must never create an edge -- it's a capability flag, not
	// a relationship to a fixed target (see the spec).
	if len(c.Edges) != before {
		t.Fatalf("unconstrained delegation must not add any edges, got %d edges (started with %d)", len(c.Edges), before)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/attackpath/... -run TestParseSharpHoundFiles_UnconstrainedDelegation_SetsFlagNotEdge -v`
Expected: build FAILURE — `bhProps` has no field for it, `Node` has no `UnconstrainedDelegation` field.

- [ ] **Step 3: Add the Node field and bhProps field, and set-on-parse logic**

Modify `orchestrator/internal/attackpath/graph.go`'s `Node` struct (after the `ComplianceScope` field):

```go
	ComplianceScope []string `json:"complianceScope,omitempty"`

	// UnconstrainedDelegation marks a principal (computer or user) configured
	// for unconstrained Kerberos delegation: whoever controls it can harvest
	// and reuse the TGT of ANY user who authenticates to it. Deliberately a
	// flag, not an edge -- there is no single fixed target to draw an edge
	// to. See docs/superpowers/specs/2026-10-07-ad-acl-delegation-graph-model-design.md.
	UnconstrainedDelegation bool `json:"unconstrainedDelegation,omitempty"`
}
```

Modify `orchestrator/internal/attackpath/sharphound.go`'s `bhProps`:

```go
type bhProps struct {
	Name                    string `json:"name"`
	Domain                  string `json:"domain"`
	UnconstrainedDelegation bool   `json:"unconstraineddelegation"`
}
```

In `buildSharpHoundCollection`'s users loop, set the flag on the node literal:

```go
	c.Nodes = append(c.Nodes, Node{
		ID: u.ObjectIdentifier, Kind: KindUser, Label: labelOf(u.Properties, u.ObjectIdentifier),
		UnconstrainedDelegation: u.Properties.UnconstrainedDelegation,
	})
```

In the computers loop, set it on the node literal there too:

```go
	c.Nodes = append(c.Nodes, Node{
		ID: cm.ObjectIdentifier, Kind: KindHost,
		Label: labelOf(cm.Properties, cm.ObjectIdentifier), Role: role,
		UnconstrainedDelegation: cm.Properties.UnconstrainedDelegation,
	})
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/attackpath/... -run TestParseSharpHoundFiles_UnconstrainedDelegation_SetsFlagNotEdge -v`
Expected: `PASS`

- [ ] **Step 5: Write the failing test proving the flag survives multi-collection merge**

This closes a real gap found by reading `build.go`'s `mergeNode`: it only copies specific named fields (`Kind`, `Label`, `Role`, `Segment`, `CrownJewel`, and an OR-merge for `HighValue`) — a new `Node` field is silently dropped on merge unless `mergeNode` is updated too. Add to `build_test.go`:

```go
func TestBuildGraph_MergeNode_PreservesUnconstrainedDelegationAcrossCollections(t *testing.T) {
	first := Collection{Nodes: []Node{{ID: "host1", Kind: KindHost, UnconstrainedDelegation: true}}}
	second := Collection{Nodes: []Node{{ID: "host1", Kind: KindHost, Label: "HOST1.CORP.LOCAL"}}}

	g := BuildGraph(first, second)

	n, ok := g.Node("host1")
	if !ok || !n.UnconstrainedDelegation {
		t.Fatalf("expected host1.UnconstrainedDelegation to survive merging a second collection that doesn't mention it, got %+v (ok=%v)", n, ok)
	}
}
```

- [ ] **Step 6: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/attackpath/... -run TestBuildGraph_MergeNode_PreservesUnconstrainedDelegationAcrossCollections -v`
Expected: FAIL — `n.UnconstrainedDelegation` is `false` because `mergeNode` doesn't copy it yet.

- [ ] **Step 7: Update `mergeNode`**

Modify `orchestrator/internal/attackpath/build.go`'s `mergeNode`, after the existing `if n.HighValue { cur.HighValue = true }` block:

```go
	if n.HighValue {
		cur.HighValue = true
	}
	if n.UnconstrainedDelegation {
		cur.UnconstrainedDelegation = true
	}
	g.nodes[n.ID] = cur
```

- [ ] **Step 8: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/attackpath/... -run TestBuildGraph_MergeNode_PreservesUnconstrainedDelegationAcrossCollections -v`
Expected: `PASS`

- [ ] **Step 9: Write the failing test proving the flag survives host reconciliation**

This closes the same class of gap in a second place: `reconcile.go`'s `enrichHost` (used when two different node IDs are resolved to the same real-world host) has the identical "only copies named fields" problem. Add to `reconcile_test.go`:

```go
func TestEnrichHost_PreservesUnconstrainedDelegation(t *testing.T) {
	var dst Node
	src := Node{UnconstrainedDelegation: true}

	enrichHost(&dst, src)

	if !dst.UnconstrainedDelegation {
		t.Fatalf("expected enrichHost to copy UnconstrainedDelegation, got %+v", dst)
	}
}
```

- [ ] **Step 10: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/attackpath/... -run TestEnrichHost_PreservesUnconstrainedDelegation -v`
Expected: FAIL — `dst.UnconstrainedDelegation` is `false`.

- [ ] **Step 11: Update `enrichHost`**

Modify `orchestrator/internal/attackpath/reconcile.go`'s `enrichHost`, after the existing `if src.HighValue { dst.HighValue = true }` line:

```go
	if src.HighValue {
		dst.HighValue = true
	}
	if src.UnconstrainedDelegation {
		dst.UnconstrainedDelegation = true
	}
}
```

- [ ] **Step 12: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/attackpath/... -run TestEnrichHost_PreservesUnconstrainedDelegation -v`
Expected: `PASS`

- [ ] **Step 13: Write the failing test for the Review Focus "independence of fields" case**

A computer with `Aces` and `AllowedToDelegate` present but `unconstraineddelegation` absent (and vice versa) must populate only what's present. Add to `sharphound_test.go`:

```go
func TestParseSharpHoundFiles_UnconstrainedDelegation_IndependentOfAcesAndDelegationFields(t *testing.T) {
	// shComputersWithAces (Task 1) has Aces but no AllowedToDelegate/unconstraineddelegation.
	c := parseSharpHoundFiles([][]byte{[]byte(shComputersWithAces)})
	g := BuildGraph(c)

	n, ok := g.Node("S-1-5-21-1-1-1-2001")
	if !ok {
		t.Fatal("FILESRV02 node should exist")
	}
	if n.UnconstrainedDelegation {
		t.Fatal("a computer with only Aces present must not have UnconstrainedDelegation set")
	}
}
```

- [ ] **Step 14: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/attackpath/... -run TestParseSharpHoundFiles_UnconstrainedDelegation_IndependentOfAcesAndDelegationFields -v`
Expected: `PASS` (this should already pass given Step 3's implementation — it is here to lock the independence in as a regression test, not to drive new code).

- [ ] **Step 15: Run the full package test suite**

Run: `cd orchestrator && go test ./internal/attackpath/... -v`
Expected: all tests `PASS` — every test from Task 1, Task 2, Task 3, and every pre-existing test in the package.

- [ ] **Step 16: Run the full orchestrator test suite**

Run: `cd orchestrator && go test ./... -race`
Expected: all packages `PASS`. This confirms nothing outside `internal/attackpath` (e.g. `internal/api/attackpath_handlers.go`, `internal/recommend`, `internal/pathcorrelation` — packages noted in `graph.go`'s own comments as consumers of `Edges()`/`EdgesTo()`) broke from the new `EdgeKind` values or the new `Node` field.

- [ ] **Step 17: Commit**

```bash
cd orchestrator
git add internal/attackpath/graph.go internal/attackpath/sharphound.go internal/attackpath/build.go internal/attackpath/reconcile.go internal/attackpath/sharphound_test.go internal/attackpath/build_test.go internal/attackpath/reconcile_test.go
git commit -m "feat(attackpath): parse unconstrained delegation as a node flag, not an edge

Node.UnconstrainedDelegation marks a principal whose compromise lets an
attacker harvest/reuse the TGT of any user who authenticates to it --
deliberately not an edge, since there's no single fixed target. Also
fixes two real gaps found by reading the merge code directly: mergeNode
(build.go) and enrichHost (reconcile.go) both only copy specific named
Node fields, so a new field is silently dropped on multi-collection merge
or host reconciliation unless each is updated -- both are now updated and
covered by a regression test proving the flag survives each path.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Self-Review

**1. Spec coverage:**
- Taxonomy/field-mapping table (all 11 ACL rights + 2 delegation kinds) → Task 1 + Task 2.
- Unconstrained delegation as flag, not edge → Task 3.
- Edge direction convention (including the `allowed-to-delegate`/`allowed-to-act` direction flip) → Task 2, with an explicit test and an explicit comment.
- "No redesign of `graph.go`" / extensibility claim → verified in every task: `EdgeKind`/`NodeKind` additions are pure constants, no changes to `ShortestPath` family, `Edge` stays comparable (no map/slice field added).
- Non-goals (ADCS, GPO, trusts, OU nodes, path-classification, executable primitives) → none appear anywhere in this plan.
- Testing strategy (fixture convention, traversal-is-free proof, unconstrained-delegation regression, defensive parsing) → one task-1-and-2-and-3 step each, matching the spec's Testing section line for line.
- Acceptance criteria's "zero changes to API handlers/scheduler/frontend" → no file under `internal/api/` or `orchestrator/web` appears in any task's Files list; Task 3 Step 16 runs the full orchestrator suite to prove nothing broke.

**2. Placeholder scan:** none found — every step has real code, real commands, real expected output.

**3. Type consistency:** `EdgeKind`/`Node`/`bhAce`/`bhComputer`/`bhUser`/`bhGroup`/`bhProps` are used with identical field names and types across all three tasks (e.g. `bhComputer.Aces []bhAce` introduced in Task 1 is referenced unchanged in Task 2 and Task 3; `Node.UnconstrainedDelegation bool` introduced in Task 3 matches `mergeNode`'s and `enrichHost`'s new code exactly).

**4. Review Focus:** all five items have an owning task and an explicit test (listed above in the Review Focus section with their task numbers already filled in — not empty).

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-10-07-ad-acl-delegation-graph-model.md`. Please review the plan. Which execution approach would you prefer?

- **Subagent-driven** — a fresh subagent implements each task and a fresh reviewer checks it before the next one starts, then a whole-branch review at the end. Most thorough; costs a fresh context per task and per review.
- **Native** — I implement every task myself in this session, then one fresh reviewer on the most capable model checks the whole branch at the end. Cheapest and fastest; no independent review until the end.

For this plan I recommend **Native**: the three tasks share one small package, each later task's interface dependency on the previous is trivial (just the already-existing `bhComputer`/`Node` struct fields), and a shipped mistake here is low-cost (wrong edge direction is caught by Task 2's own direction-flip test, not discovered in production) — so the per-task fresh-reviewer overhead of subagent-driven buys little that TDD doesn't already buy here. Does the plan capture what you want, and which approach should we use?
