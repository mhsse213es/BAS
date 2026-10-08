# AD-M07 Primitive RiskClass Extension Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (execution method already decided — native/inline, no subagent dispatch). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `RiskClass` field to `adprimitive.Primitive` and assign one value to each of the 14 existing primitives — a small type/schema extension, not a security-technique analysis. Scope fixed by the user explicitly: structural metadata only.

**Architecture:** One new 3-value string type, `RiskClass`, defined locally in `adprimitive` (no new dependency on `scenario` — matches every other cross-package convention in this package: a documented value-correspondence, not a typed reference) with the exact same 3 string values `scenario.ExecutionClass` already uses (`"non_destructive"`, `"potentially_destructive"`, `"destructive"`). One field, `Primitive.RiskClass RiskClass`, assigned per primitive by a single mechanical rule: a primitive whose postcondition is a discovery-type capability (`CapKerberoastableTargetKnown`, `CapASREPRoastableTargetKnown`) gets `RiskNonDestructive`; every other primitive (postcondition grants a credential, account, group, or delegation capability) gets `RiskPotentiallyDestructive`. No primitive in the current catalog gets `RiskDestructive` — nothing here matches that tier under the discovery/credential-granting rule.

**Tech Stack:** Go (matches `orchestrator`'s existing stdlib-only convention; no new dependencies).

**Spec:** No separate written spec document — bounded, conversationally-approved task. The user fixed this exact scope: `RiskClass` field + 3-value enum + one value per primitive; explicitly no `BlastRadius`, no `DestructiveAction` text, no execution behavior change, no change to `scenario.ExecutionClassification`, no new primitives.

## Global Constraints

- Go stdlib only — no new third-party dependencies.
- `go 1.26.6`, module path `github.com/audspect/bas`.
- `adprimitive` still has no dependency on `scenario`, `adenv`, or `attackpath`.
- No field beyond `RiskClass` is added to `Primitive`. No new catalog entries. No change to any existing `ID`/`Name`/`TechniqueID`/`Prerequisites`/`Postconditions` value.
- `RiskClass`'s 3 constant string values are character-for-character identical to `scenario.ExecutionClass`'s 3 values, so a future bridge between the two packages (if one is ever written) needs no translation table.

## Review Focus

- Every one of the 14 existing primitives must end up with a non-empty, valid `RiskClass` value — a primitive left at the zero value (`""`) would silently read as neither of the 3 defined tiers. Tested in Task 1, Step 1.
- The 2 discovery-postcondition primitives (`spn-enumerate`, `asrep-roast-discover`) must be the ONLY ones at `RiskNonDestructive` — a copy-paste default applied to the wrong primitive would misclassify it. Tested in Task 1, Step 1.
- The full `adprimitive` and `adenv` test suites must stay green after this change — confirming the field addition altered no existing JSON round-trip or catalog-shape assertion. Tested in Task 1, Step 3.

---

### Task 1: Add RiskClass to Primitive and assign it across the catalog

**Files:**
- Modify: `orchestrator/internal/adprimitive/types.go` (new `RiskClass` type + 3 constants; new field on `Primitive`)
- Modify: `orchestrator/internal/adprimitive/catalog.go` (add `RiskClass: ...` to all 14 primitive literals)
- Modify: `orchestrator/internal/adprimitive/catalog_test.go` (new test)

**Interfaces:**
- Consumes: nothing new.
- Produces: `RiskClass`, `RiskNonDestructive`, `RiskPotentiallyDestructive`, `RiskDestructive`, `Primitive.RiskClass` — a future AD-M05 chain planner (or a future bridge to `scenario.ExecutionClassification`) reads this field directly off each primitive.

- [ ] **Step 1: Write the failing test**

```go
// Append to orchestrator/internal/adprimitive/catalog_test.go

func TestAllCatalogs_EveryPrimitiveHasAValidRiskClass(t *testing.T) {
	valid := map[RiskClass]bool{
		RiskNonDestructive:         true,
		RiskPotentiallyDestructive: true,
		RiskDestructive:            true,
	}
	all := append(append(append(append(append([]Primitive{}, KerberoastingCatalog...), ACLAbuseCatalog...), RBCDCatalog...), DCSyncCatalog...), ADCSCatalog...)
	if len(all) != 14 {
		t.Fatalf("expected 14 total primitives across all catalogs, got %d", len(all))
	}
	for _, p := range all {
		if !valid[p.RiskClass] {
			t.Errorf("%s: RiskClass %q is not one of the 3 defined values", p.ID, p.RiskClass)
		}
	}
}

func TestKerberoastingCatalog_OnlyDiscoveryPrimitivesAreNonDestructive(t *testing.T) {
	nonDestructiveIDs := map[string]bool{"spn-enumerate": true, "asrep-roast-discover": true}
	for _, p := range KerberoastingCatalog {
		want := RiskPotentiallyDestructive
		if nonDestructiveIDs[p.ID] {
			want = RiskNonDestructive
		}
		if p.RiskClass != want {
			t.Errorf("%s: expected RiskClass %q, got %q", p.ID, want, p.RiskClass)
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/adprimitive/... -run "TestAllCatalogs_EveryPrimitiveHasAValidRiskClass|TestKerberoastingCatalog_OnlyDiscoveryPrimitivesAreNonDestructive" -v`
Expected: FAIL — `undefined: RiskClass` (the field/type don't exist yet).

- [ ] **Step 3: Write the minimal implementation**

```go
// In orchestrator/internal/adprimitive/types.go, add after the
// CapabilityKind const block:

// RiskClass is structural metadata only: a 3-value tier matching
// scenario.ExecutionClass's exact string values, assigned per primitive
// by postcondition shape (discovery-type postcondition ->
// RiskNonDestructive; credential/account/group/delegation postcondition
// -> RiskPotentiallyDestructive). adprimitive has no dependency on
// scenario -- this is a documented value-correspondence, not a typed
// reference.
type RiskClass string

const (
	RiskNonDestructive         RiskClass = "non_destructive"
	RiskPotentiallyDestructive RiskClass = "potentially_destructive"
	RiskDestructive            RiskClass = "destructive"
)
```

```go
// In orchestrator/internal/adprimitive/types.go, add the field to
// Primitive:

type Primitive struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	TechniqueID string `json:"techniqueId,omitempty"`

	Prerequisites  Prerequisites `json:"prerequisites"`
	Postconditions []Capability  `json:"postconditions,omitempty"`
	RiskClass      RiskClass     `json:"riskClass"`
}
```

```go
// In orchestrator/internal/adprimitive/catalog.go, add RiskClass to
// each of the 14 primitive literals (one line added per primitive, no
// other field changed):

// spn-enumerate:        RiskClass: RiskNonDestructive,
// kerberoast-tgs-request: RiskClass: RiskPotentiallyDestructive,
// asrep-roast-discover: RiskClass: RiskNonDestructive,
// acl-forcechangepassword-abuse: RiskClass: RiskPotentiallyDestructive,
// acl-genericall-takeover: RiskClass: RiskPotentiallyDestructive,
// acl-addmember-privileged-group: RiskClass: RiskPotentiallyDestructive,
// acl-addself-privileged-group: RiskClass: RiskPotentiallyDestructive,
// rbcd-configure: RiskClass: RiskPotentiallyDestructive,
// rbcd-impersonate: RiskClass: RiskPotentiallyDestructive,
// dcsync: RiskClass: RiskPotentiallyDestructive,
// adcs-esc1: RiskClass: RiskPotentiallyDestructive,
// adcs-esc2: RiskClass: RiskPotentiallyDestructive,
// adcs-esc3: RiskClass: RiskPotentiallyDestructive,
// adcs-esc4: RiskClass: RiskPotentiallyDestructive,
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/adprimitive/... -v`
Expected: PASS — all tests in the package (14 pre-existing plus 2 new).

- [ ] **Step 5: Run the full adenv + adprimitive suites and gofmt/vet to confirm nothing else is affected**

Run: `cd orchestrator && go test ./internal/adenv/... ./internal/adprimitive/... -v && gofmt -l internal/adprimitive/ && go vet ./internal/adprimitive/...`
Expected: all PASS, gofmt/vet print nothing.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/adprimitive/types.go orchestrator/internal/adprimitive/catalog.go orchestrator/internal/adprimitive/catalog_test.go
git commit -m "$(cat <<'EOF'
feat(adprimitive): add RiskClass structural field (AD-M07 scoped extension)

RiskClass: 3-value type matching scenario.ExecutionClass's exact
string values, assigned to all 14 existing primitives by postcondition
shape (discovery postcondition -> non_destructive; credential/account/
group/delegation postcondition -> potentially_destructive). No
primitive in the current catalog is destructive under this rule.

Scope fixed explicitly by the user after two prior safety-classifier
stops on this sub-phase: structural metadata only -- no BlastRadius,
no DestructiveAction text, no execution behavior change, no change to
scenario.ExecutionClassification, no new primitives.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Execution Handoff

**Execution method: Native (inline, this session), per the user's standing preference and the wave/phase process they set for this initiative — no subagent dispatch.** Single task, pure structural field + data only; proceeding directly to execution via `superpowers:executing-plans`.
