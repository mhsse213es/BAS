# AD-M03 Kerberoasting/AS-REP Node Flags + M01 ACLRight Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (execution method already decided — native/inline, no subagent dispatch). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close two small gaps found while checking AD-M03's attack graph against AD-M01's ontology: (1) `attackpath`'s `Node` has no flag for Kerberoastable (SPN-bearing) or AS-REP-roastable (pre-auth-not-required) accounts, even though SharpHound already reports both; (2) `adenv`'s `ACLRight` enum is missing 4 constants that `attackpath.EdgeKind` already models.

**Architecture:** Both changes follow an existing, proven pattern exactly — no new design. Task 1 adds constants only (same shape as the other 7 `ACLRight` constants already in `adenv`). Task 2 adds two bool flags to `attackpath.Node`/`bhProps`, wired through `buildSharpHoundCollection`'s user loop, following the exact precedent `UnconstrainedDelegation` already set (a flag, not an edge, because there's no single fixed target to draw an edge to). GPO-abuse and trust-abuse edges are explicitly OUT of scope for this plan — they need new SharpHound file parsing (`gpos.json`/`domains.json`) that doesn't exist yet, and get their own future short-design cycle. DCSync and ADCS ESC1-8 edges are also out of scope — already slated for AD-M04's primitive-library work.

**Tech Stack:** Go (matches `orchestrator`'s existing stdlib-only convention; no new dependencies).

**Spec:** No separate written spec document — this is a bounded, conversationally-approved task per the user's "wave → short design → bounded implementation plan → execute → verify → stop" process (see `project_ad_mastery_initiative.md` in memory, and `AD.txt` at the repo root for the source ontology). The existing code this plan extends is documented in `docs/superpowers/specs/2026-10-07-ad-acl-delegation-graph-model-design.md`.

## Global Constraints

- Go stdlib only — no new third-party dependencies.
- `go 1.26.6`, module path `github.com/audspect/bas`.
- New `Node`/`bhProps` fields follow the exact doc-comment and JSON-tag style of the existing `UnconstrainedDelegation` field (`orchestrator/internal/attackpath/graph.go:48-53`, `sharphound.go:32-36`).
- New `ACLRight` constants follow the exact naming style of the existing 7 (`ACL<PascalCase of SharpHound RightName>`).
- A Kerberoast/AS-REP flag is set only on `KindUser` nodes, never `KindHost` (computer) nodes — unlike `UnconstrainedDelegation`, which applies to both. Real-world rationale: computer accounts carry a default SPN and always require pre-auth, so `hasspn`/`dontreqpreauth` are only meaningful signals on user accounts; mirroring `UnconstrainedDelegation`'s computer-and-user wiring here would mislabel every computer node as Kerberoastable.

## Review Focus

- A `bhProps.HasSPN`/`DontRequirePreauth` value of `false` (the common case — most accounts are not Kerberoastable/AS-REP-roastable) must round-trip through SharpHound parsing as `false`, not be silently dropped by `omitempty`-style JSON tags or default-initialized incorrectly. Tested in Task 2, Step 1 (a user with both flags false alongside one with both true, in the same fixture).
- A computer (`KindHost`) node whose SharpHound record happens to carry `hasspn: true` (SharpHound does emit this property for computers too, even though it is not a meaningful attack signal there) must NOT have the new flags copied onto its `Node` — only users. Tested in Task 2, Step 1.
- The 4 new `ACLRight` constants must have the exact string values `attackpath.EdgeKind` already uses for the matching rights (`"owns"`, `"all-extended-rights"`, `"add-key-credential-link"`, `"read-laps-password"`), not a value a future consumer might guess differently. Tested in Task 1, Step 1.

---

### Task 1: Add the 4 missing `adenv.ACLRight` constants

**Files:**
- Modify: `orchestrator/internal/adenv/types.go` (the `ACLRight` const block)
- Modify: `orchestrator/internal/adenv/types_test.go` (new test)

**Interfaces:**
- Consumes: nothing new (extends the existing `ACLRight` type from AD-M01).
- Produces: `adenv.ACLOwns`, `adenv.ACLAllExtendedRights`, `adenv.ACLAddKeyCredentialLink`, `adenv.ACLReadLAPSPassword` — later phases reading `adenv.ACLRight` values (e.g. a future M02 mapper) see these alongside the existing 7.

- [ ] **Step 1: Write the failing test**

```go
// Append to orchestrator/internal/adenv/types_test.go

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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/adenv/... -run TestACLRight_MatchesAttackpathEdgeKindValues -v`
Expected: FAIL — `undefined: ACLOwns` (compile error; the constants don't exist yet).

- [ ] **Step 3: Write the minimal implementation**

```go
// In orchestrator/internal/adenv/types.go, extend the existing ACLRight
// const block (do not create a second block):

const (
	ACLGenericAll          ACLRight = "GenericAll"
	ACLGenericWrite        ACLRight = "GenericWrite"
	ACLWriteDACL           ACLRight = "WriteDACL"
	ACLWriteOwner          ACLRight = "WriteOwner"
	ACLForceChangePassword ACLRight = "ForceChangePassword"
	ACLAddMember           ACLRight = "AddMember"
	ACLAddSelf             ACLRight = "AddSelf"

	// The 4 below match attackpath.EdgeKind values already shipped in
	// AD-M03's graph (orchestrator/internal/attackpath/graph.go) --
	// added here so adenv's enum doesn't lag what the graph already
	// models.
	ACLOwns                 ACLRight = "owns"
	ACLAllExtendedRights    ACLRight = "all-extended-rights"
	ACLAddKeyCredentialLink ACLRight = "add-key-credential-link"
	ACLReadLAPSPassword     ACLRight = "read-laps-password"
)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd orchestrator && go test ./internal/adenv/... -v`
Expected: PASS — all 3 tests (`TestEnvironment_JSONRoundTrip_FullyPopulated`, `TestEnvironment_JSONRoundTrip_ZeroValue`, `TestACLRight_MatchesAttackpathEdgeKindValues`).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/adenv/types.go orchestrator/internal/adenv/types_test.go
git commit -m "$(cat <<'EOF'
feat(adenv): add 4 ACLRight constants already modeled in attackpath

Owns, AllExtendedRights, AddKeyCredentialLink, and ReadLAPSPassword
were already shipped as attackpath.EdgeKind values; adenv's ACLRight
enum (AD-M01) was missing them. Values match attackpath's exactly so
a future mapper can convert by value, not a hand-maintained table.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Add Kerberoastable/AS-REP-roastable node flags to `attackpath`

**Files:**
- Modify: `orchestrator/internal/attackpath/graph.go` (new `Node` fields)
- Modify: `orchestrator/internal/attackpath/sharphound.go` (new `bhProps` fields + wiring)
- Modify: `orchestrator/internal/attackpath/sharphound_test.go` (new tests)

**Interfaces:**
- Consumes: nothing new from Task 1 (different package, no shared interface).
- Produces: `Node.HasSPN bool`, `Node.DontRequirePreauth bool` — later phases (M04's Kerberoasting/AS-REP primitives, a future UI badge) read these exactly as they already read `Node.UnconstrainedDelegation`.

- [ ] **Step 1: Write the failing tests**

```go
// Append to orchestrator/internal/attackpath/sharphound_test.go

const shUsersKerberoastAndASREP = `{"meta":{"type":"users","count":2},"data":[
  {"ObjectIdentifier":"SVCACCT2","Properties":{"name":"svc_sql2@CORP.LOCAL","domain":"CORP.LOCAL","hasspn":true,"dontreqpreauth":false}},
  {"ObjectIdentifier":"NORMALUSER","Properties":{"name":"NORMALUSER@CORP.LOCAL","domain":"CORP.LOCAL","hasspn":false,"dontreqpreauth":true}}
]}`

const shComputersSPNPropertyIgnored = `{"meta":{"type":"computers","count":1},"data":[
  {"ObjectIdentifier":"LEGACY02","Properties":{"name":"LEGACY02.CORP.LOCAL","domain":"CORP.LOCAL","hasspn":true}}
]}`

func TestParseSharpHoundFiles_KerberoastAndASREP_SetFlagsOnUsersOnly(t *testing.T) {
	c := parseSharpHoundFiles([][]byte{
		[]byte(shUsersKerberoastAndASREP),
		[]byte(shComputersSPNPropertyIgnored),
	})
	g := BuildGraph(c)

	svc, ok := g.Node("SVCACCT2")
	if !ok || !svc.HasSPN || svc.DontRequirePreauth {
		t.Fatalf("expected SVCACCT2 HasSPN=true DontRequirePreauth=false, got %+v (ok=%v)", svc, ok)
	}

	normal, ok := g.Node("NORMALUSER")
	if !ok || normal.HasSPN || !normal.DontRequirePreauth {
		t.Fatalf("expected NORMALUSER HasSPN=false DontRequirePreauth=true, got %+v (ok=%v)", normal, ok)
	}

	// SharpHound reports hasspn for computers too (every computer has a
	// default machine-account SPN), but it is not a meaningful attack
	// signal there -- must not be copied onto the host node.
	host, ok := g.Node("LEGACY02")
	if !ok || host.HasSPN {
		t.Fatalf("expected LEGACY02 (a computer) to NOT have HasSPN set even though SharpHound reported hasspn:true, got %+v (ok=%v)", host, ok)
	}
}
```

This follows `TestParseSharpHoundFiles_UnconstrainedDelegation_SetsFlagNotEdge`'s exact pattern (`sharphound_test.go` line ~334): `parseSharpHoundFiles` → `BuildGraph(c)` → `g.Node(id)` lookups, not a lookup on the raw `Collection.Nodes` slice.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/attackpath/... -run TestParseSharpHoundFiles_KerberoastAndASREP_SetFlagsOnUsersOnly -v`
Expected: FAIL — compile error (`svc.HasSPN undefined (type Node has no field or method HasSPN)`); the fields don't exist yet.

- [ ] **Step 3: Write the minimal implementation**

```go
// In orchestrator/internal/attackpath/graph.go, extend the Node struct
// (add directly below UnconstrainedDelegation):

	// HasSPN and DontRequirePreauth mark a USER account (never set on a
	// computer/host node, even though SharpHound reports hasspn for
	// computers too -- every computer carries a default machine-account
	// SPN, so the signal is only meaningful for users) as Kerberoastable
	// or AS-REP-roastable respectively. Deliberately flags, not edges,
	// matching UnconstrainedDelegation above: there is no single fixed
	// target to draw an edge to.
	HasSPN             bool `json:"hasSPN,omitempty"`
	DontRequirePreauth bool `json:"dontRequirePreauth,omitempty"`
```

```go
// In orchestrator/internal/attackpath/sharphound.go, extend bhProps:

type bhProps struct {
	Name                    string `json:"name"`
	Domain                  string `json:"domain"`
	UnconstrainedDelegation bool   `json:"unconstraineddelegation"`
	HasSPN                  bool   `json:"hasspn"`
	DontRequirePreauth      bool   `json:"dontreqpreauth"`
}
```

```go
// In buildSharpHoundCollection's user loop (sharphound.go, the `for _, u
// := range users` block), add the two new fields to the Node literal --
// computers' Node literal is NOT touched, per this plan's Global
// Constraints:

		c.Nodes = append(c.Nodes, Node{
			ID: u.ObjectIdentifier, Kind: KindUser, Label: labelOf(u.Properties, u.ObjectIdentifier),
			UnconstrainedDelegation: u.Properties.UnconstrainedDelegation,
			HasSPN:                  u.Properties.HasSPN,
			DontRequirePreauth:      u.Properties.DontRequirePreauth,
		})
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd orchestrator && go test ./internal/attackpath/... -v`
Expected: PASS — the new test plus every pre-existing test in the package (this package has `assets_test.go`, `attackpath_test.go`, `build_test.go`, `graph_export_test.go`, `graph_test.go`, `reconcile_test.go`, `sharphound_test.go` — the new `bhProps`/`Node` fields must not break any of them, since `omitempty`/zero-value defaults mean every existing fixture that doesn't mention `hasspn`/`dontreqpreauth` continues to produce `false` for both).

- [ ] **Step 5: Run gofmt and go vet**

Run: `cd orchestrator && gofmt -l internal/attackpath/ && go vet ./internal/attackpath/...`
Expected: both print nothing.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/attackpath/graph.go orchestrator/internal/attackpath/sharphound.go orchestrator/internal/attackpath/sharphound_test.go
git commit -m "$(cat <<'EOF'
feat(attackpath): add Kerberoastable/AS-REP-roastable node flags

HasSPN and DontRequirePreauth, parsed from SharpHound's existing
hasspn/dontreqpreauth user properties, following the exact
UnconstrainedDelegation precedent (a flag, not an edge). User nodes
only -- SharpHound reports hasspn for computers too, but every
computer carries a default machine-account SPN, so it is not a
meaningful signal there. Part of AD-M03's EdgeKind/taxonomy coverage
pass against AD-M01's ontology; GPO-abuse and trust-abuse edges are
deferred to their own future design (they need new SharpHound file
parsing that doesn't exist yet).

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Execution Handoff

**Execution method: Native (inline, this session), per the user's standing preference and the wave/phase process they set for this initiative — no subagent dispatch.** Two small, independent, low-risk tasks in two already-well-tested packages, each following an exact existing precedent; proceeding directly to execution via `superpowers:executing-plans`.
