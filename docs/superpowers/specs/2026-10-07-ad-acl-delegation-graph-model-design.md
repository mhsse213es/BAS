# AD ACL + Kerberos Delegation Graph Model — Design

**Status:** Approved design, ready for implementation planning.

**Source:** User-driven initiative to bring Audspect's Active Directory attack
simulation to "top-notch, mastered" coverage. Full research into current state
(see conversation) found the real gap is not scenario count — it's that the
existing native attack-path engine (`orchestrator/internal/attackpath/`) only
models network-reachability and basic AD relationships (local-admin, sessions,
group membership), with zero ACL-abuse or Kerberos-delegation-abuse edges, even
though the SharpHound collector already gathers this data today and we simply
discard it.

## Problem

Audspect already has a working, non-trivial attack-path engine:

- `sharphound.go` parses SharpHound/BloodHound collection zips uploaded by
  agents into a normalized `Collection`.
- `graph.go` builds a directed multigraph (`Node`/`Edge`/`Graph`) from that
  collection.
- `analytics.go` computes real path-finding (`ShortestPathToDomainAdmin`,
  `CanReachDomainAdmin`, `BlastRadius`, `ChokePoints`, `CrownJewelExposures`,
  `SegmentationViolations`) over that graph today, wired into the UI.

But the edge vocabulary is only 7 kinds: `smb`, `winrm`, `rdp` (network
reachability), `admin-to`, `has-session`, `member-of`, `credential`. This is
enough to answer "can an attacker move laterally host-to-host," but it cannot
represent the AD-specific attack primitives that make BloodHound-style
analysis valuable in practice — ACL abuse (`GenericAll`, `GenericWrite`,
`WriteDacl`, `WriteOwner`, `ForceChangePassword`, `AddMember`, `AddSelf`,
`AddKeyCredentialLink`, `ReadLAPSPassword`) and Kerberos delegation abuse
(constrained delegation, resource-based constrained delegation, unconstrained
delegation).

SharpHound already collects all of this data in its standard JSON output
(`Aces` arrays on principal objects, `AllowedToDelegate`/`AllowedToAct` on
computer objects, `unconstraineddelegation` as a property flag) — the parser
in `sharphound.go` simply never reads those fields today.

## Goals

- Define AD ACL-abuse and Kerberos-delegation-abuse as first-class primitives
  in Audspect's own taxonomy — not as raw ATT&CK technique IDs. ATT&CK mapping
  is recorded as a secondary reference, never the primary model.
- Extend `sharphound.go` to parse the ACE and delegation fields SharpHound
  already provides but we currently discard.
- Extend `graph.go`'s `EdgeKind` vocabulary (and, only where a primitive is a
  property rather than a relationship, `Node`) to represent these primitives.
- Make real customer attack paths like
  `User --GenericWrite--> ServiceAccount --Kerberoastable--> DomainAdmin`
  discoverable through the *existing* `ShortestPathToDomainAdmin` /
  `CanReachDomainAdmin` functions, with no changes to those functions' logic.
- Leave the model open for ADCS, GPO abuse, and domain-trust edges to be
  added later through the same mechanism (new `EdgeKind`/`NodeKind`
  constants), without requiring a redesign of `graph.go`.

## Explicit non-goals (this phase)

- **ADCS** (certificate template abuse, ESC1–ESC8) is out of scope entirely.
  Per the user's own judgment, ADCS's CA/template/EKU/enrollment-rights model
  is substantial enough to need its own dedicated subsystem and spec, not a
  bolt-on to this graph pass.
- **GPO abuse edges** and **domain trust edges** are out of scope. Both are
  deferred to their own later sub-projects.
- **OU nodes** are out of scope. ACL abuse against OUs is primarily only
  actionable via GPO-linking (already deferred), so introducing a partial OU
  model now would be premature; OUs will be modeled properly alongside the
  GPO subsystem.
- **No executable attack/exploit simulations.** This phase is discovery and
  graph-modeling only: parsing collected data into a richer graph and making
  it path-findable. Walking or exploiting a discovered ACL/delegation edge
  (the "primitive library" and "safe execution" work) is Phase 2.
- **No path-classification/reporting layer** (e.g. tagging a discovered path
  as "used ACL abuse" vs. "pure lateral movement"). The engine finds these
  paths for free once the edges exist (traversal is already edge-kind
  agnostic — see Architecture below); classifying *why* a path matters is a
  reporting concern layered on top later, once the primitive semantics here
  have matured. Keeping it out now prevents premature reporting semantics
  from leaking into the core graph model.

## Architecture

### Why no redesign of `graph.go` is needed

This was verified against the actual code, not assumed:

- `EdgeKind` and `NodeKind` are plain Go string types with named constants —
  not a closed/sealed enum. Adding new constants is a pure addition.
- `Graph.ShortestPath` (and everything built on it —
  `ShortestPathToDomainAdmin`, `CanReachDomainAdmin`) is a plain BFS over
  `g.adj[cur]` with **no filtering by edge kind at all**. Any edge kind
  reaching the graph via `AddEdge` already participates in path-finding.
  Only `reachKinds` (used for `BlastRadius`/`Reachability`'s host-to-host
  lateral-movement counting) filters by kind, and it deliberately stays
  scoped to network-reachability protocols — ACL/delegation edges are
  identity-escalation edges, not network-reachability edges, and must not be
  added to `reachKinds`.
- `Edge` (`From`, `To`, `Kind`, all strings) is used as a map key for
  deduplication in `build.go` and `reconcile.go` (`map[Edge]bool`), so it
  must remain a comparable type. No generic metadata bag (e.g.
  `map[string]string`) can be added to it. This is fine: the established
  pattern (seen on `Node` already — `CrownJewel`, `HighValue`,
  `CriticalityTier`, etc. were all added one at a time as concrete scalar
  fields over time) is to add named, comparable fields when a concrete need
  arises, not to pre-build a generic bag. Future ADCS/GPO/trust work follows
  the same pattern: new named `EdgeKind`/`NodeKind` constants, and new named
  scalar fields on `Edge`/`Node` only when a real need for extra per-edge or
  per-node data actually arises.

Net effect: extensibility is **already structurally satisfied** by the
existing design. This phase's job is taxonomy + parsing + new constants, not
engine changes.

### Edge direction convention (binding for every edge in this spec)

Verified against the actual existing edge-construction code (not just doc
comments), the established convention is:

> **`From` = the node an attacker must already control. `To` = the node that
> control flows to as a result.**

Confirmed from `sharphound.go`'s real `Edge{...}` construction today:

- `EdgeMemberOf{From: <member>, To: <group>}` — control the member, inherit
  the group's rights.
- `EdgeAdminTo{From: <admin principal>, To: <computer>}` — control the
  principal, you're admin on the computer.
- `EdgeHasSession{From: <computer>, To: <user>}` — control the computer,
  harvest the session/credential of the user who is logged into it.

Every new edge in this spec follows the same rule, with a worked example so
direction can never be read backwards:

| EdgeKind | From | To | Worked example |
|---|---|---|---|
| `generic-all`, `generic-write`, `write-owner`, `write-dacl`, `owns`, `all-extended-rights`, `force-change-password`, `add-member`, `add-self`, `add-key-credential-link`, `read-laps-password` | the ACE's `PrincipalSID` (the grantee) | the object the `Aces` array is attached to (the grantee's target) | `Aces` entry on computer `FILESRV01` grants `GenericWrite` to user `HELPDESK`. Edge: `{From: HELPDESK, To: FILESRV01, Kind: generic-write}`. Control `HELPDESK` → gain `GenericWrite` over `FILESRV01`. |
| `allowed-to-delegate` | the computer/service object whose `AllowedToDelegate` property lists the target | each target SPN/object listed in that property | Computer `WEBSVC01` has `AllowedToDelegate: [CIFS/FILESRV01]`. Edge: `{From: WEBSVC01, To: FILESRV01, Kind: allowed-to-delegate}`. Control `WEBSVC01` (constrained delegation configured on it) → gain the ability to authenticate to `FILESRV01` as an arbitrary user via S4U2Proxy. |
| `allowed-to-act` | each principal listed in the computer's `AllowedToAct` property | the computer object whose `AllowedToAct` property lists that principal | Computer `TARGET01` has `AllowedToAct: [WEBSVC01]` (its `msDS-AllowedToActOnBehalfOfOtherIdentity`). Edge: `{From: WEBSVC01, To: TARGET01, Kind: allowed-to-act}`. Control `WEBSVC01` → gain the ability to impersonate arbitrary users to `TARGET01` via RBCD (S4U2Self + S4U2Proxy). |

Note `allowed-to-delegate` and `allowed-to-act` have **opposite** grantee
positions relative to "the computer" in the source JSON: for
`AllowedToDelegate`, the computer carrying the property is the `From`; for
`AllowedToAct`, the computer carrying the property is the `To`. This is
exactly the kind of direction mistake this table exists to prevent — get it
backwards and an attack-path query would claim the wrong principal can
impersonate the wrong target.

### Unconstrained delegation is a flag, not an edge

Unconstrained delegation is a property of a single principal
(`Properties.unconstraineddelegation == true`): if you control that
principal, you can harvest and reuse the TGT of *any* user who happens to
authenticate to it — there is no single fixed target node to draw an edge
to. Modeled as `Node.UnconstrainedDelegation bool`, the same pattern as the
existing `Node.HighValue bool`. **No edge is created for it.** A test locks
this in explicitly (see Testing) so it cannot regress into becoming an edge
later.

### New `EdgeKind` constants (in `graph.go`)

```go
EdgeGenericAll            EdgeKind = "generic-all"
EdgeGenericWrite          EdgeKind = "generic-write"
EdgeWriteOwner            EdgeKind = "write-owner"
EdgeWriteDacl             EdgeKind = "write-dacl"
EdgeOwns                  EdgeKind = "owns"
EdgeAllExtendedRights     EdgeKind = "all-extended-rights"
EdgeForceChangePassword   EdgeKind = "force-change-password"
EdgeAddMember             EdgeKind = "add-member"
EdgeAddSelf               EdgeKind = "add-self"
EdgeAddKeyCredentialLink  EdgeKind = "add-key-credential-link"
EdgeReadLAPSPassword      EdgeKind = "read-laps-password"
EdgeAllowedToDelegate     EdgeKind = "allowed-to-delegate"
EdgeAllowedToAct          EdgeKind = "allowed-to-act"
```

None of these are added to `reachKinds`.

### New `Node` field

```go
UnconstrainedDelegation bool `json:"unconstrainedDelegation,omitempty"`
```

### SharpHound parser extension (`sharphound.go`)

- Extend `bhComputer` and `bhUser` (and `bhGroup`, since groups can hold ACEs
  too) with an `Aces []bhAce` field, where:
  ```go
  type bhAce struct {
      PrincipalSID  string `json:"PrincipalSID"`
      RightName     string `json:"RightName"`
      IsInherited   bool   `json:"IsInherited"`
  }
  ```
  `RightName` values map directly to the new `EdgeKind`s above (a fixed
  lookup table in the parser, e.g. `"GenericAll" -> EdgeGenericAll`). An
  unrecognized `RightName` is skipped, never fatal — consistent with the
  file's existing defensive-parsing principle. `IsInherited` is parsed but
  not yet used for anything in this phase (no filtering, no edge
  suppression) — recorded for completeness since BloodHound always includes
  it, with no behavior attached to it yet.
- Extend `bhComputer` with `AllowedToDelegate []string` and
  `AllowedToAct []bhMember` fields, and `Properties` (`bhProps`) with
  `UnconstrainedDelegation bool \`json:"unconstraineddelegation"\`` on both
  `bhComputer` and `bhUser`.
- `parseSharpHoundFiles` builds the new edges/flag alongside the existing
  `member-of`/`admin-to`/`has-session` construction, following the exact
  `From`/`To` assignment in the table above.

## Testing

Follows the existing `sharphound_test.go` convention — trimmed BloodHound v4
JSON fixture constants, TDD (RED before GREEN for every new behavior):

- One test per new `EdgeKind`: a fixture with that `RightName` (or
  `AllowedToDelegate`/`AllowedToAct` entry) produces exactly the edge the
  direction table above specifies — asserted on `From`/`To`/`Kind`, not just
  "an edge exists."
- A test proving the "traversal is free" claim rather than assuming it: a
  fixture where the *only* path from a starting node to Domain Admins is
  through one of the new edge kinds, asserting `ShortestPathToDomainAdmin`
  finds it with no changes to `analytics.go`.
- A test for unconstrained delegation: a fixture with
  `unconstraineddelegation: true` on a computer asserts
  `Node.UnconstrainedDelegation == true` AND asserts the resulting edge count
  is unchanged from before that property existed (i.e., confirms no edge was
  created for it).
- A defensive-parsing test: a fixture with a malformed/missing `Aces` array,
  an unrecognized `RightName`, or a missing `AllowedToDelegate`/`AllowedToAct`
  field does not crash the parser and does not add a spurious edge/flag.

## Acceptance criteria

- `graph.go` gains the new `EdgeKind` constants and the `Node.
  UnconstrainedDelegation` field; `ShortestPath`/`ShortestPathToDomainAdmin`/
  `CanReachDomainAdmin`/`reachKinds` are unmodified.
- `sharphound.go` parses `Aces`, `AllowedToDelegate`, `AllowedToAct`, and
  `unconstraineddelegation` from SharpHound's existing output into the edges
  and flag defined above, with every direction matching this spec's table.
- All tests in the Testing section pass, including the explicit
  "unconstrained delegation produces no edge" regression test.
- A real customer SharpHound collection containing an ACL or delegation
  chain to Domain Admins is discoverable through the existing
  `ShortestPathToDomainAdmin` API/UI path with zero changes to the API
  handlers, the scheduler, or the frontend (verified structurally: the
  frontend attack-path.js UI already renders `edge.kind` as a generic string
  in its recommendations table — confirmed by reading the code — so new
  kinds display automatically).

## Open items (deferred, not blocking this spec)

- ADCS (ESC1–ESC8), GPO abuse edges, domain trust edges, OU nodes: each its
  own future sub-project, plugging into this same `EdgeKind`/`NodeKind`
  extension mechanism.
- Path classification/reporting (tagging *why* a path is interesting beyond
  "it exists"): deferred until primitive semantics here have matured.
- Phase 2 (composable executable primitives + prerequisites/postconditions +
  safe execution gates for actually exploiting a discovered ACL/delegation
  edge): explicitly out of scope for this phase, per the user's direction.
