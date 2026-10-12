# AD-M04 ADCS Primitive Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (execution method already decided — native/inline, no subagent dispatch). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Connect sub-phase 2's ESC1-4 configuration predicates (`adenv.IsESC1Vulnerable` etc.) to AD-M04's `Primitive` model, closing out M04's ADCS gap category with the same prerequisite/postcondition shape every other catalog in `adprimitive` already uses.

**Architecture:** 4 primitives in a new `ADCSCatalog`, each `Prerequisites.Conditions` key named after the `adenv` predicate it corresponds to (`"esc1_vulnerable_template"` ↔ `adenv.IsESC1Vulnerable`, etc.) — a documented naming correspondence, not a typed dependency, preserving `adprimitive`'s existing independence from `adenv`/`attackpath`. All 4 share `TechniqueID: "T1649"`, the same pattern Kerberoasting's 2 primitives established for `T1558.003`. ESC1-3 produce `CapControlledAccount` (the same outcome `ACLAbuseCatalog`'s primitives already produce); ESC4 produces a new `CapTemplateControlled` (it only lets the holder reconfigure a template, not directly take over an account — connecting that reconfiguration to ESC1-style exploitation as a 2-step chain is explicitly AD-M05's job, the same deferral already used for `RBCDCatalog`'s two-step chain). "Telemetry" and "safety classification" (the other 2 items in the user's own sub-phase-3 description) are deliberately NOT added to `Primitive` here — they belong to AD-M07's upcoming risk-semantics extension (already next on the Wave 2 roadmap), not a one-off addition scoped to just the ADCS primitives.

**Tech Stack:** Go (matches `orchestrator`'s existing stdlib-only convention; no new dependencies).

**Spec:** No separate written spec document — bounded, conversationally-approved task, the 3rd of the user's own 4-sub-phase ADCS breakdown (ontology → predicates → **primitive integration** → synthetic tests). Source: `orchestrator/internal/adprimitive/catalog.go` (the catalog pattern) and `orchestrator/internal/adenv/adcs_predicates.go` (sub-phase 2).

## Global Constraints

- Go stdlib only — no new third-party dependencies.
- `go 1.26.6`, module path `github.com/audspect/bas`.
- `adprimitive` still has no dependency on `adenv` or `attackpath`.
- All 4 primitives share `TechniqueID: "T1649"`.
- `Prerequisites.Conditions` keys use the `esc<N>_` prefix to stay distinct from the existing `acl_right_held:<RightName>` convention — these name a TEMPLATE configuration state, not a directory-object ACL right.

## Review Focus

- ESC4's postcondition must be `CapTemplateControlled`, not `CapControlledAccount` — the same distinction already proven for `RBCDCatalog`'s two-step chain, re-verified here since ESC4 is structurally the closest of the 4 to a "just configure something" primitive. Tested in Task 1, Step 1.
- All 4 primitives must share the identical `TechniqueID` string, not 4 near-identical variants (a copy-paste typo across 4 similar literals is the most likely mistake here). Tested in Task 1, Step 1.
- Each primitive's `Conditions` key must be genuinely distinct from the other 3 (no accidental reuse of `"esc1_vulnerable_template"` on the ESC2 entry via copy-paste) — a reasonable reader must be able to look up any one of the 4 ESC primitives by its own condition key. Tested in Task 1, Step 1.

---

### Task 1: Add the ADCS primitive catalog

**Files:**
- Modify: `orchestrator/internal/adprimitive/catalog.go` (new `ADCSCatalog` var)
- Modify: `orchestrator/internal/adprimitive/types.go` (1 new `CapabilityKind` constant)
- Modify: `orchestrator/internal/adprimitive/catalog_test.go` (new test)

**Interfaces:**
- Consumes: `Primitive`, `Prerequisites`, `Capability`, `CapDomainUser`, `CapControlledAccount` (pre-existing in `types.go`).
- Produces: `ADCSCatalog []Primitive`, `CapTemplateControlled` — closes AD-M04's gap-filling; a future AD-M05 chain planner reads all 5 catalogs (`KerberoastingCatalog`, `ACLAbuseCatalog`, `RBCDCatalog`, `DCSyncCatalog`, `ADCSCatalog`).

- [ ] **Step 1: Write the failing test**

```go
// Append to orchestrator/internal/adprimitive/catalog_test.go

func TestADCSCatalog_FourDistinctPrimitivesShareTechniqueID(t *testing.T) {
	if len(ADCSCatalog) != 4 {
		t.Fatalf("expected exactly 4 primitives in ADCSCatalog, got %d", len(ADCSCatalog))
	}
	seenConditionKeys := map[string]bool{}
	for _, p := range ADCSCatalog {
		if p.TechniqueID != "T1649" {
			t.Errorf("%s: expected TechniqueID T1649, got %q", p.ID, p.TechniqueID)
		}
		if len(p.Prerequisites.Conditions) != 1 {
			t.Fatalf("%s: expected exactly 1 Conditions entry, got %+v", p.ID, p.Prerequisites.Conditions)
		}
		for key := range p.Prerequisites.Conditions {
			if seenConditionKeys[key] {
				t.Fatalf("condition key %q reused across more than one primitive", key)
			}
			seenConditionKeys[key] = true
		}
	}

	esc4, ok := findInADCSCatalog("adcs-esc4")
	if !ok {
		t.Fatal("expected adcs-esc4 in ADCSCatalog")
	}
	if len(esc4.Postconditions) != 1 || esc4.Postconditions[0].Kind != CapTemplateControlled {
		t.Fatalf("expected adcs-esc4 postcondition CapTemplateControlled, got %+v", esc4.Postconditions)
	}

	for _, id := range []string{"adcs-esc1", "adcs-esc2", "adcs-esc3"} {
		p, ok := findInADCSCatalog(id)
		if !ok {
			t.Fatalf("expected %s in ADCSCatalog", id)
		}
		if len(p.Postconditions) != 1 || p.Postconditions[0].Kind != CapControlledAccount {
			t.Fatalf("expected %s postcondition CapControlledAccount, got %+v", id, p.Postconditions)
		}
	}
}

func findInADCSCatalog(id string) (Primitive, bool) {
	for _, p := range ADCSCatalog {
		if p.ID == id {
			return p, true
		}
	}
	return Primitive{}, false
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/adprimitive/... -run TestADCSCatalog -v`
Expected: FAIL — `undefined: ADCSCatalog` (the catalog doesn't exist yet).

- [ ] **Step 3: Write the minimal implementation**

```go
// In orchestrator/internal/adprimitive/types.go, extend the existing
// CapabilityKind const block (do not create a second block):

	CapRBCDConfigured CapabilityKind = "RBCD_CONFIGURED"

	// CapTemplateControlled is ESC4's outcome -- the holder can
	// reconfigure a certificate template's own properties, but has not
	// yet exploited it for account takeover the way ESC1/ESC2/ESC3 do.
	// Connecting this to ESC1-style exploitation as a 2-step chain is
	// left to AD-M05.
	CapTemplateControlled CapabilityKind = "TEMPLATE_CONTROLLED"
```

```go
// Append to orchestrator/internal/adprimitive/catalog.go

// ADCSCatalog connects adenv's ESC1-4 configuration predicates
// (IsESC1Vulnerable, IsESC2Vulnerable, IsESC3Vulnerable,
// HasTemplateWriteAccess) to AD-M04's prerequisite/postcondition model.
// Each Conditions key names the predicate it corresponds to -- a
// documented naming correspondence, not a typed dependency, preserving
// adprimitive's independence from adenv. All 4 share TechniqueID T1649
// (Steal or Forge Authentication Certificates), the same pattern
// KerberoastingCatalog established for T1558.003. No scenario YAML
// exists for any ESC variant yet; primitive knowledge only, same status
// as every other catalog in this file.
var ADCSCatalog = []Primitive{
	{
		ID: "adcs-esc1", Name: "ADCS ESC1: Enrollee-Supplied Subject", TechniqueID: "T1649",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainUser}},
			Conditions:   map[string]bool{"esc1_vulnerable_template": true},
		},
		Postconditions: []Capability{{Kind: CapControlledAccount}},
	},
	{
		ID: "adcs-esc2", Name: "ADCS ESC2: Any-Purpose EKU", TechniqueID: "T1649",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainUser}},
			Conditions:   map[string]bool{"esc2_vulnerable_template": true},
		},
		Postconditions: []Capability{{Kind: CapControlledAccount}},
	},
	{
		ID: "adcs-esc3", Name: "ADCS ESC3: Enrollment Agent Template", TechniqueID: "T1649",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainUser}},
			Conditions:   map[string]bool{"esc3_vulnerable_template": true},
		},
		Postconditions: []Capability{{Kind: CapControlledAccount}},
	},
	{
		ID: "adcs-esc4", Name: "ADCS ESC4: Template ACL Abuse", TechniqueID: "T1649",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainUser}},
			Conditions:   map[string]bool{"esc4_template_write_access": true},
		},
		Postconditions: []Capability{{Kind: CapTemplateControlled}},
	},
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/adprimitive/... -v`
Expected: PASS — all tests in the package (13 pre-existing plus 1 new).

- [ ] **Step 5: Run gofmt and go vet**

Run: `cd orchestrator && gofmt -l internal/adprimitive/ && go vet ./internal/adprimitive/...`
Expected: both print nothing.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/adprimitive/catalog.go orchestrator/internal/adprimitive/catalog_test.go orchestrator/internal/adprimitive/types.go
git commit -m "$(cat <<'EOF'
feat(adprimitive): add ADCS ESC1-4 primitives (AD-M04 sub-phase 3 of 4)

ADCSCatalog: adcs-esc1/esc2/esc3 (-> CapControlledAccount) and
adcs-esc4 (-> CapTemplateControlled, same "reconfigures rather than
takes over" distinction RBCDCatalog's 2-step chain already
established). All 4 share TechniqueID T1649. Conditions keys name
the adenv predicate they correspond to (esc1_vulnerable_template <->
IsESC1Vulnerable, etc.) by documented convention, not a typed
dependency -- adprimitive still has no import of adenv/attackpath.

Telemetry and safety classification (also named in this ADCS pass's
scoping) are deliberately NOT added here -- they belong to AD-M07's
upcoming risk-semantics extension, not a one-off addition scoped to
just these 4 primitives. This closes M04's gap-filling; only the
synthetic-test sub-phase remains.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Execution Handoff

**Execution method: Native (inline, this session), per the user's standing preference and the wave/phase process they set for this initiative — no subagent dispatch.** Single task, extends an already-tested schema with data only; proceeding directly to execution via `superpowers:executing-plans`.
