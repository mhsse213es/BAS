# AD-M04 DCSync Primitive Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (execution method already decided — native/inline, no subagent dispatch). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fill the DCSync gap in AD-M04's primitive library with 1 primitive, following the `ACLAbuseCatalog`/`RBCDCatalog` precedent.

**Architecture:** DCSync (replicating the domain's secrets via the directory replication service, MS-DRSR) requires the `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` extended rights on the domain object itself — in `attackpath`'s graph, both collapse into the single `AllExtendedRights` ACE right (`EdgeAllExtendedRights`), the same right `ACLAbuseCatalog` and `RBCDCatalog` already reference via the `"acl_right_held:<RightName>"` convention. Unlike those two gaps, DCSync has a clean 1:1 MITRE mapping (`T1003.006`, OS Credential Dumping: DCSync) and its outcome is exactly AD.txt's own worked `DOMAIN_CREDENTIAL_MATERIAL` example (lines 394-395) — `CapDomainCredentialMaterial`, defined in AD-M04's original schema, unused by any catalog until now. No scenario YAML exists for DCSync (confirmed by grep — the only matches in `scenarios/*.yaml` are an unrelated coincidental use of the word "replicated" in ransomware encryption prose), so this is primitive knowledge, not a backfill, same status as the prior 2 gap-filling sub-phases.

**Tech Stack:** Go (matches `orchestrator`'s existing stdlib-only convention; no new dependencies).

**Spec:** No separate written spec document — bounded, conversationally-approved task. Source material: `orchestrator/internal/adprimitive/types.go`/`catalog.go` (schema and the `"acl_right_held"` convention this plan reuses).

## Global Constraints

- Go stdlib only — no new third-party dependencies.
- `go 1.26.6`, module path `github.com/audspect/bas`.
- `adprimitive` still has no dependency on `adenv` or `attackpath`.
- The prerequisite ACL condition uses the SAME `"acl_right_held:<RightName>"` convention `ACLAbuseCatalog`/`RBCDCatalog` already established — `"acl_right_held:AllExtendedRights"`, matching `adenv.ACLAllExtendedRights`'s string value exactly.
- `dcsync`'s doc comment states the one caveat this Conditions-based convention cannot structurally express: the right must specifically be held on the DOMAIN object, not just any object — resolving that specificity is graph-query logic for AD-M05, same deferral already established for every other ACL-shaped primitive in this catalog.

## Review Focus

- `dcsync`'s postcondition must be `CapDomainCredentialMaterial` (the pre-existing, unused constant), not a newly-invented one — proving the schema's original 6-capability vocabulary (from AD-M04's very first commit) holds up across every gap-filling sub-phase without needing extension for the "big" outcomes, only the discovery/intermediate ones. Tested in Task 1, Step 1.
- `dcsync` is the first primitive in the whole library to have BOTH a `TechniqueID` and an `"acl_right_held"` condition together — a reasonable reader must be able to see that the two mechanisms (MITRE cross-reference, graph-shaped ACL prerequisite) are independent and can co-occur, not mutually exclusive (every prior ACL-shaped primitive had no `TechniqueID`, which could be mistaken for a rule rather than a coincidence of those specific techniques). Tested in Task 1, Step 1.

---

### Task 1: Add the DCSync primitive

**Files:**
- Modify: `orchestrator/internal/adprimitive/catalog.go` (new `DCSyncCatalog` var)
- Modify: `orchestrator/internal/adprimitive/catalog_test.go` (new test)

**Interfaces:**
- Consumes: `Primitive`, `Prerequisites`, `Capability`, `CapDomainUser`, `CapDomainCredentialMaterial` (all pre-existing in `types.go`; no new `CapabilityKind` needed this time).
- Produces: `DCSyncCatalog []Primitive` — the next gap-filling sub-phase (ADCS-ESC1-4) follows this same precedent.

- [ ] **Step 1: Write the failing test**

```go
// Append to orchestrator/internal/adprimitive/catalog_test.go

func TestDCSyncCatalog_RequiresAllExtendedRightsAndHasTechniqueID(t *testing.T) {
	if len(DCSyncCatalog) != 1 {
		t.Fatalf("expected exactly 1 primitive in DCSyncCatalog, got %d", len(DCSyncCatalog))
	}
	p := DCSyncCatalog[0]
	if p.ID != "dcsync" {
		t.Fatalf("expected ID dcsync, got %q", p.ID)
	}
	if p.TechniqueID != "T1003.006" {
		t.Fatalf("expected TechniqueID T1003.006, got %q", p.TechniqueID)
	}
	if !p.Prerequisites.Conditions["acl_right_held:AllExtendedRights"] {
		t.Fatalf("expected dcsync to require acl_right_held:AllExtendedRights, got %+v", p.Prerequisites.Conditions)
	}
	// Reuses the pre-existing constant from AD-M04's original schema
	// (AD.txt's own "After DCSync: DOMAIN_CREDENTIAL_MATERIAL" example),
	// not a newly-invented one.
	if len(p.Postconditions) != 1 || p.Postconditions[0].Kind != CapDomainCredentialMaterial {
		t.Fatalf("expected postcondition CapDomainCredentialMaterial, got %+v", p.Postconditions)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/adprimitive/... -run TestDCSyncCatalog -v`
Expected: FAIL — `undefined: DCSyncCatalog` (the catalog doesn't exist yet).

- [ ] **Step 3: Write the minimal implementation**

```go
// Append to orchestrator/internal/adprimitive/catalog.go

// DCSyncCatalog defines the single DCSync primitive. DS-Replication-Get-
// Changes and DS-Replication-Get-Changes-All (the 2 extended rights
// DCSync requires) collapse into attackpath's single AllExtendedRights
// ACE right -- the same "acl_right_held:<RightName>" convention
// ACLAbuseCatalog/RBCDCatalog already use. Unlike those two, DCSync has
// a clean 1:1 MITRE mapping (T1003.006) and NO scenario YAML exists for
// it yet (confirmed by grep; the only scenarios/*.yaml matches for
// "replicat" are an unrelated coincidental use of the word in
// ransomware-encryption prose) -- primitive knowledge, not a backfill,
// same status as every other catalog in this file.
//
// This Conditions-based convention cannot structurally express that the
// right must be held specifically on the DOMAIN object, not just any
// object -- resolving that specificity against a real environment's
// graph is AD-M05's job, the same deferral already established for every
// ACL-shaped primitive here.
var DCSyncCatalog = []Primitive{
	{
		ID: "dcsync", Name: "DCSync Directory Replication", TechniqueID: "T1003.006",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainUser}},
			Conditions:   map[string]bool{"acl_right_held:AllExtendedRights": true},
		},
		Postconditions: []Capability{{Kind: CapDomainCredentialMaterial}},
	},
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/adprimitive/... -v`
Expected: PASS — all tests in the package (12 pre-existing plus 1 new).

- [ ] **Step 5: Run gofmt and go vet**

Run: `cd orchestrator && gofmt -l internal/adprimitive/ && go vet ./internal/adprimitive/...`
Expected: both print nothing.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/adprimitive/catalog.go orchestrator/internal/adprimitive/catalog_test.go
git commit -m "$(cat <<'EOF'
feat(adprimitive): add DCSync primitive (AD-M04 gap-filling)

DCSyncCatalog: dcsync (T1003.006, requires
acl_right_held:AllExtendedRights -> CapDomainCredentialMaterial,
reusing AD-M04's original schema constant -- AD.txt's own worked
DCSync example). No scenario YAML exists for DCSync yet (confirmed
by grep); primitive knowledge, not a backfill, same status as
ACLAbuseCatalog/RBCDCatalog.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Execution Handoff

**Execution method: Native (inline, this session), per the user's standing preference and the wave/phase process they set for this initiative — no subagent dispatch.** Single task, single primitive, extends an already-tested schema with data only; proceeding directly to execution via `superpowers:executing-plans`.
