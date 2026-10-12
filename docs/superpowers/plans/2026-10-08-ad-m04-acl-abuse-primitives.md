# AD-M04 ACL-Abuse Primitives Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (execution method already decided — native/inline, no subagent dispatch). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fill 4 of AD-M04's named gap categories (ACL-abuse, specifically `ForceChangePassword`, `GenericAll`, `AddMember`, `AddSelf`) with real `Primitive` definitions grounded in established AD attack technique knowledge and cross-referenced to the ACL EdgeKinds `attackpath` already models.

**Architecture:** Unlike the Kerberoasting/AS-REP sub-phase (which backfilled an existing, executable scenario), there is currently **zero scenario YAML coverage** for any ACL-abuse technique (confirmed by grep across `scenarios/*.yaml`) — this sub-phase creates primitive KNOWLEDGE, not a backfill, and must not be mistaken for scenario coverage. `WriteOwner`/`WriteDacl`/`Owns`/`AllExtendedRights`/`AddKeyCredentialLink`/`ReadLAPSPassword` are deliberately deferred to a later pass, keeping this one bounded.

ACL-abuse primitives are graph-shaped — "the attacker holds right R over SOME target T," where T varies per environment — unlike Kerberoasting's uniform "any domain user can attempt this." Rather than reopening AD-M04's schema (which deliberately has no dependency on `attackpath`, since a primitive describes a technique, not a graph), this plan uses the existing `Prerequisites.Conditions` open map with a documented convention: a key of the form `"acl_right_held:<RightName>"` (the `<RightName>` matching `adenv.ACLRight`'s string values, e.g. `"ForceChangePassword"`, `"GenericAll"`) means "the attacker holds this ACL right over some target." *Resolving* which target satisfies that, for a specific environment, is graph traversal — AD-M05's job (the future chain planner), not this schema's.

Two new `CapabilityKind` constants are added (extending the existing open type, same precedent as the Kerberoasting backfill's 2 additions): `CapControlledAccount` (the outcome of `ForceChangePassword`/`GenericAll` — the attacker now has usable credentials for, or full control of, a specific account) and `CapGroupMember` (the outcome of `AddMember`/`AddSelf` — the attacker is now a member of a specific group).

**Tech Stack:** Go (matches `orchestrator`'s existing stdlib-only convention; no new dependencies).

**Spec:** No separate written spec document — bounded, conversationally-approved task. Source material: `orchestrator/internal/adprimitive/types.go` (AD-M04 schema) and `orchestrator/internal/adenv/types.go`'s `ACLRight` constants (the right names these primitives' Conditions keys reference) and `orchestrator/internal/attackpath/graph.go`'s matching `EdgeKind`s (the graph-level representation AD-M05 will eventually traverse to resolve these Conditions).

## Global Constraints

- Go stdlib only — no new third-party dependencies.
- `go 1.26.6`, module path `github.com/audspect/bas`.
- `adprimitive` still has NO dependency on `adenv` or `attackpath` — the `"acl_right_held:<RightName>"` convention is a documented STRING convention, not a typed cross-package reference, preserving this package's existing independence.
- None of these 4 primitives get a `TechniqueID` — ACL-rights abuse via inherited permissions has no clean 1:1 ATT&CK sub-technique (the closest, T1098 Account Manipulation, describes an adversary modifying their OWN account, not using inherited rights to take over someone else's — a different technique), and AD.txt is explicit that not every primitive needs one. Leaving it empty here is more honest than forcing an imprecise tag.
- Every primitive's doc comment states explicitly that no corresponding scenario YAML exists yet — this is primitive-schema knowledge, not scenario coverage, and must never be read as "ACL-abuse scenarios exist" (per the "Scoring Must Be Genuine" standing principle: never let documentation imply more coverage than is real).

## Review Focus

- `acl-forcechangepassword-abuse` and `acl-genericall-takeover` require DIFFERENT ACL rights but produce the SAME `CapControlledAccount` postcondition kind — a reasonable future reader must be able to see that multiple distinct techniques converge on the same outcome, not assume a 1:1 technique-to-capability mapping. Tested in Task 1, Step 1 (both asserted to share `CapControlledAccount` while having different `Conditions` keys).
- `acl-addmember-privileged-group` and `acl-addself-privileged-group` are two DISTINCT primitives (different ACL rights, `AddMember` requires an existing member with the right to add others, `AddSelf` lets the attacker add themselves directly) that must not collapse into one entry — a reasonable reader searching by `Conditions` key for one must still find the other separately. Tested in Task 1, Step 1.
- The `Conditions` key convention (`"acl_right_held:<RightName>"`) must use the EXACT string values `adenv.ACLRight` already defines (e.g. `"ForceChangePassword"`, not `"force-change-password"` or `"ForceChangePW"`) — a future AD-M05 resolver reading this convention needs it to match `adenv`'s constants byte-for-byte, not approximately. Tested in Task 1, Step 1 (each primitive's condition key is asserted against the literal `adenv.ACLRight` string value it names, copied as a literal so the test would fail if a future edit to `adenv` silently changed the value — this test deliberately does NOT import `adenv`, preserving `adprimitive`'s independence, so the literal is checked against a comment-documented source of truth instead).

---

### Task 1: Add the 4 ACL-abuse primitives

**Files:**
- Modify: `orchestrator/internal/adprimitive/catalog.go` (new `ACLAbuseCatalog` var, alongside the existing `KerberoastingCatalog`)
- Modify: `orchestrator/internal/adprimitive/types.go` (2 new `CapabilityKind` constants)
- Modify: `orchestrator/internal/adprimitive/catalog_test.go` (new tests)

**Interfaces:**
- Consumes: `Primitive`, `Prerequisites`, `Capability`, `CapabilityKind` (from `types.go`).
- Produces: `ACLAbuseCatalog []Primitive`, `CapControlledAccount`, `CapGroupMember` — a later gap-filling sub-phase (RBCD, DCSync, ADCS-ESC1-4) follows this exact precedent (its own `<Name>Catalog` var), and a future AD-M05 chain planner reads both `KerberoastingCatalog` and `ACLAbuseCatalog` as primitive sources.

- [ ] **Step 1: Write the failing test**

```go
// Append to orchestrator/internal/adprimitive/catalog_test.go

func findInACLAbuseCatalog(id string) (Primitive, bool) {
	for _, p := range ACLAbuseCatalog {
		if p.ID == id {
			return p, true
		}
	}
	return Primitive{}, false
}

func TestACLAbuseCatalog_ForceChangePasswordAndGenericAllConvergeOnSameCapability(t *testing.T) {
	fcp, ok := findInACLAbuseCatalog("acl-forcechangepassword-abuse")
	if !ok {
		t.Fatal("expected acl-forcechangepassword-abuse in ACLAbuseCatalog")
	}
	// Copied literally from adenv.ACLForceChangePassword's value
	// ("ForceChangePassword") -- see this plan's Review Focus.
	if !fcp.Prerequisites.Conditions["acl_right_held:ForceChangePassword"] {
		t.Fatalf("expected acl-forcechangepassword-abuse to require acl_right_held:ForceChangePassword, got %+v", fcp.Prerequisites.Conditions)
	}
	if len(fcp.Postconditions) != 1 || fcp.Postconditions[0].Kind != CapControlledAccount {
		t.Fatalf("expected acl-forcechangepassword-abuse postcondition CapControlledAccount, got %+v", fcp.Postconditions)
	}

	gca, ok := findInACLAbuseCatalog("acl-genericall-takeover")
	if !ok {
		t.Fatal("expected acl-genericall-takeover in ACLAbuseCatalog")
	}
	// Copied literally from adenv.ACLGenericAll's value ("GenericAll").
	if !gca.Prerequisites.Conditions["acl_right_held:GenericAll"] {
		t.Fatalf("expected acl-genericall-takeover to require acl_right_held:GenericAll, got %+v", gca.Prerequisites.Conditions)
	}
	if len(gca.Postconditions) != 1 || gca.Postconditions[0].Kind != CapControlledAccount {
		t.Fatalf("expected acl-genericall-takeover postcondition CapControlledAccount, got %+v", gca.Postconditions)
	}

	// Different prerequisite rights, same outcome kind -- multiple paths
	// to the same capability, not a 1:1 technique-to-capability mapping.
	if fcp.ID == gca.ID {
		t.Fatal("acl-forcechangepassword-abuse and acl-genericall-takeover must be distinct primitives")
	}
}

func TestACLAbuseCatalog_AddMemberAndAddSelfAreDistinctPrimitives(t *testing.T) {
	am, ok := findInACLAbuseCatalog("acl-addmember-privileged-group")
	if !ok {
		t.Fatal("expected acl-addmember-privileged-group in ACLAbuseCatalog")
	}
	// Copied literally from adenv.ACLAddMember's value ("AddMember").
	if !am.Prerequisites.Conditions["acl_right_held:AddMember"] {
		t.Fatalf("expected acl-addmember-privileged-group to require acl_right_held:AddMember, got %+v", am.Prerequisites.Conditions)
	}

	as, ok := findInACLAbuseCatalog("acl-addself-privileged-group")
	if !ok {
		t.Fatal("expected acl-addself-privileged-group in ACLAbuseCatalog")
	}
	// Copied literally from adenv.ACLAddSelf's value ("AddSelf").
	if !as.Prerequisites.Conditions["acl_right_held:AddSelf"] {
		t.Fatalf("expected acl-addself-privileged-group to require acl_right_held:AddSelf, got %+v", as.Prerequisites.Conditions)
	}

	if am.ID == as.ID {
		t.Fatal("acl-addmember-privileged-group and acl-addself-privileged-group must be distinct primitives")
	}
	for _, p := range []Primitive{am, as} {
		if len(p.Postconditions) != 1 || p.Postconditions[0].Kind != CapGroupMember {
			t.Fatalf("expected %s postcondition CapGroupMember, got %+v", p.ID, p.Postconditions)
		}
	}
}

func TestACLAbuseCatalog_NoneHaveATechniqueID(t *testing.T) {
	// ACL-rights abuse via inherited permissions has no clean 1:1 ATT&CK
	// sub-technique -- leaving TechniqueID empty is more honest than an
	// imprecise tag (see this plan's Global Constraints).
	for _, p := range ACLAbuseCatalog {
		if p.TechniqueID != "" {
			t.Errorf("expected %s to have no TechniqueID, got %q", p.ID, p.TechniqueID)
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/adprimitive/... -run TestACLAbuseCatalog -v`
Expected: FAIL — `undefined: ACLAbuseCatalog` (the catalog doesn't exist yet).

- [ ] **Step 3: Write the minimal implementation**

```go
// In orchestrator/internal/adprimitive/types.go, extend the existing
// CapabilityKind const block (do not create a second block):

	CapKerberoastableTargetKnown CapabilityKind = "KERBEROASTABLE_TARGET_KNOWN"
	CapASREPRoastableTargetKnown CapabilityKind = "ASREP_ROASTABLE_TARGET_KNOWN"

	// The 2 below are the outcomes of ACL-rights abuse (added for the
	// ACLAbuseCatalog): CapControlledAccount is "the attacker now has
	// usable credentials for, or full control of, a specific account"
	// (ForceChangePassword/GenericAll); CapGroupMember is "the attacker
	// is now a member of a specific group" (AddMember/AddSelf).
	CapControlledAccount CapabilityKind = "CONTROLLED_ACCOUNT"
	CapGroupMember       CapabilityKind = "GROUP_MEMBER"
```

```go
// Append to orchestrator/internal/adprimitive/catalog.go

// ACLAbuseCatalog defines 4 ACL-abuse primitives from established AD
// attack technique knowledge. UNLIKE KerberoastingCatalog above, these
// have NO corresponding scenario YAML yet (scenarios/*.yaml has zero ACL-
// abuse coverage as of this writing) -- this is primitive-schema
// knowledge, not scenario coverage, and must not be read as "ACL-abuse
// scenarios exist." WriteOwner, WriteDacl, Owns, AllExtendedRights,
// AddKeyCredentialLink, and ReadLAPSPassword are deliberately deferred to
// a later pass.
//
// Each primitive's Prerequisites.Conditions uses the convention
// "acl_right_held:<RightName>", where <RightName> is the exact string
// value of the matching adenv.ACLRight constant (e.g. "ForceChangePassword"
// for adenv.ACLForceChangePassword). This means "the attacker holds this
// ACL right over SOME target" -- resolving which target satisfies that,
// for a specific environment, is graph traversal over attackpath's
// matching EdgeKind, which is AD-M05's job (the future chain planner),
// not this schema's. adprimitive deliberately has no dependency on adenv
// or attackpath; this is a documented STRING convention, not a typed
// cross-package reference.
var ACLAbuseCatalog = []Primitive{
	{
		ID: "acl-forcechangepassword-abuse", Name: "ForceChangePassword ACL Abuse",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainUser}},
			Conditions:   map[string]bool{"acl_right_held:ForceChangePassword": true},
		},
		Postconditions: []Capability{{Kind: CapControlledAccount}},
	},
	{
		ID: "acl-genericall-takeover", Name: "GenericAll ACL Takeover",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainUser}},
			Conditions:   map[string]bool{"acl_right_held:GenericAll": true},
		},
		Postconditions: []Capability{{Kind: CapControlledAccount}},
	},
	{
		ID: "acl-addmember-privileged-group", Name: "AddMember Privileged Group Join",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainUser}},
			Conditions:   map[string]bool{"acl_right_held:AddMember": true},
		},
		Postconditions: []Capability{{Kind: CapGroupMember}},
	},
	{
		ID: "acl-addself-privileged-group", Name: "AddSelf Privileged Group Join",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainUser}},
			Conditions:   map[string]bool{"acl_right_held:AddSelf": true},
		},
		Postconditions: []Capability{{Kind: CapGroupMember}},
	},
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/adprimitive/... -v`
Expected: PASS — all tests in the package (6 pre-existing plus 3 new).

- [ ] **Step 5: Run gofmt and go vet**

Run: `cd orchestrator && gofmt -l internal/adprimitive/ && go vet ./internal/adprimitive/...`
Expected: both print nothing.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/adprimitive/catalog.go orchestrator/internal/adprimitive/catalog_test.go orchestrator/internal/adprimitive/types.go
git commit -m "$(cat <<'EOF'
feat(adprimitive): add 4 ACL-abuse primitives (AD-M04 gap-filling)

ACLAbuseCatalog: acl-forcechangepassword-abuse, acl-genericall-
takeover (both -> CapControlledAccount), acl-addmember-privileged-
group, acl-addself-privileged-group (both -> CapGroupMember). Unlike
the Kerberoasting backfill, NO scenario YAML exists for any of these
yet -- this is primitive-schema knowledge from established AD attack
technique knowledge, not scenario coverage.

Prerequisites use a documented Conditions-key convention,
"acl_right_held:<RightName>" (matching adenv.ACLRight's string
values), rather than a typed attackpath/adenv dependency -- ACL-abuse
is graph-shaped (holds right R over SOME target T, which varies per
environment), and resolving which target satisfies that is AD-M05's
job, not this schema's. No TechniqueID on any of the 4: ACL-rights
abuse via inherited permissions has no clean 1:1 ATT&CK sub-technique.

WriteOwner, WriteDacl, Owns, AllExtendedRights, AddKeyCredentialLink,
and ReadLAPSPassword are deliberately deferred to a later pass.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Execution Handoff

**Execution method: Native (inline, this session), per the user's standing preference and the wave/phase process they set for this initiative — no subagent dispatch.** Single task, extends an already-tested schema with data only; proceeding directly to execution via `superpowers:executing-plans`.
