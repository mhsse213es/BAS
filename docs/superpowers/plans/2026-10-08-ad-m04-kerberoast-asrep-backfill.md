# AD-M04 Kerberoasting/AS-REP Primitive Backfill Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (execution method already decided — native/inline, no subagent dispatch). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Backfill AD-M04's `Primitive` schema onto the real, already-shipped Kerberoasting/AS-REP scenario (`scenarios/kerberoasting-ad-drill.yaml`, stages 1-3) — the second sub-phase of M04 per the wave sequencing, after the schema-only sub-phase.

**Architecture:** A static Go catalog (`orchestrator/internal/adprimitive/catalog.go`, a package-level `[]Primitive` var) describing 3 primitives that map 1:1 onto `kerberoasting-ad-drill.yaml`'s existing stages 1-3: `spn-enumerate` (Stage 1), `kerberoast-tgs-request` (Stage 2), `asrep-roast-discover` (Stage 3). Both Stage 1 and Stage 2 carry the SAME MITRE ID (`T1558.003`) in the real scenario file — direct, real-world confirmation of AD.txt's point (lines 129-178) that one ATT&CK technique covers multiple primitives. Stage 3 backfills as a DISCOVERY-only primitive (no credential obtained) because the real scenario step only finds AS-REP-roastable accounts and deliberately never requests or cracks a ticket (its own `blast_radius` text says so) — the catalog must not claim a capability the scenario doesn't actually grant. Two new `CapabilityKind` constants are added (not a schema redesign — `CapabilityKind` was always an open string type) to represent the DISCOVERY-type capabilities Stage 1 and Stage 3 produce, distinct from the credential-type capability Stage 2 produces.

**Tech Stack:** Go (matches `orchestrator`'s existing stdlib-only convention; no new dependencies).

**Spec:** No separate written spec document — bounded, conversationally-approved task. Source material: `orchestrator/internal/adprimitive/types.go` (AD-M04 schema, just shipped) and `scenarios/kerberoasting-ad-drill.yaml` stages 1-3 (the real scenario this backfills).

## Global Constraints

- Go stdlib only — no new third-party dependencies.
- `go 1.26.6`, module path `github.com/audspect/bas`.
- Every primitive's `TechniqueID` must match the `technique_id` value of the real scenario step it backfills, copied verbatim from `scenarios/kerberoasting-ad-drill.yaml` (`T1558.003` for Stage 1 and Stage 2, `T1558.004` for Stage 3) — not invented.
- No primitive claims a postcondition the real scenario step doesn't actually produce. Stage 3's own `blast_radius` text is explicit that it discovers but never requests/cracks an AS-REP, so `asrep-roast-discover`'s postcondition is a discovery capability, never a credential one.

## Review Focus

- `spn-enumerate` (Stage 1) and `kerberoast-tgs-request` (Stage 2) share the identical `TechniqueID` ("T1558.003") but must be two DISTINCT `Primitive` entries, not merged into one — a reasonable future reader of the catalog, searching by `TechniqueID`, would otherwise find only one of the two real scenario steps. Tested in Task 1, Step 1.
- `kerberoast-tgs-request`'s prerequisite capability must be satisfied by `spn-enumerate`'s postcondition (by equality, the same mechanism AD-M04's schema test already proved) — if the catalog's two Kerberoast-related primitives don't actually chain, the backfill has silently failed its one real purpose. Tested in Task 1, Step 1.
- `asrep-roast-discover`'s postcondition must NOT be (or contain) `CapServiceAccountCredential` or any other credential-bearing capability — asserting the negative explicitly, since copy-pasting `kerberoast-tgs-request`'s postcondition would be the easiest mistake to make and the hardest to notice by inspection alone. Tested in Task 1, Step 1.

---

### Task 1: Backfill the Kerberoasting/AS-REP catalog

**Files:**
- Create: `orchestrator/internal/adprimitive/catalog.go`
- Test: `orchestrator/internal/adprimitive/catalog_test.go`

**Interfaces:**
- Consumes: `Primitive`, `Prerequisites`, `Capability`, `CapabilityKind` (from `types.go`, AD-M04's schema sub-phase).
- Produces: `KerberoastingCatalog []Primitive` (package-level var) and 2 new constants, `CapKerberoastableTargetKnown`, `CapASREPRoastableTargetKnown` — a later gap-filling sub-phase of M04 (ACL-abuse/RBCD/DCSync/ADCS-ESC1-4) appends its own primitives to a catalog following this exact precedent, and AD-M05's future chain planner reads `KerberoastingCatalog` as one of its primitive sources.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/adprimitive/catalog_test.go
package adprimitive

import "testing"

func findPrimitive(id string) (Primitive, bool) {
	for _, p := range KerberoastingCatalog {
		if p.ID == id {
			return p, true
		}
	}
	return Primitive{}, false
}

func TestKerberoastingCatalog_Stage1And2ShareTechniqueIDButAreDistinctPrimitives(t *testing.T) {
	enum, ok := findPrimitive("spn-enumerate")
	if !ok || enum.TechniqueID != "T1558.003" {
		t.Fatalf("expected spn-enumerate with TechniqueID T1558.003, got %+v (ok=%v)", enum, ok)
	}
	kerb, ok := findPrimitive("kerberoast-tgs-request")
	if !ok || kerb.TechniqueID != "T1558.003" {
		t.Fatalf("expected kerberoast-tgs-request with TechniqueID T1558.003, got %+v (ok=%v)", kerb, ok)
	}
	if enum.ID == kerb.ID {
		t.Fatal("spn-enumerate and kerberoast-tgs-request must be distinct catalog entries despite sharing a TechniqueID")
	}
}

func TestKerberoastingCatalog_EnumeratePostconditionSatisfiesKerberoastPrerequisite(t *testing.T) {
	enum, _ := findPrimitive("spn-enumerate")
	kerb, _ := findPrimitive("kerberoast-tgs-request")

	satisfied := false
	for _, have := range enum.Postconditions {
		for _, need := range kerb.Prerequisites.Capabilities {
			if have == need {
				satisfied = true
			}
		}
	}
	if !satisfied {
		t.Fatalf("expected spn-enumerate's postcondition %+v to satisfy kerberoast-tgs-request's prerequisite %+v", enum.Postconditions, kerb.Prerequisites.Capabilities)
	}
}

func TestKerberoastingCatalog_ASREPDiscoverDoesNotClaimCredentialCapability(t *testing.T) {
	asrep, ok := findPrimitive("asrep-roast-discover")
	if !ok || asrep.TechniqueID != "T1558.004" {
		t.Fatalf("expected asrep-roast-discover with TechniqueID T1558.004, got %+v (ok=%v)", asrep, ok)
	}
	for _, cap := range asrep.Postconditions {
		if cap.Kind == CapServiceAccountCredential || cap.Kind == CapNTLMHash || cap.Kind == CapDomainCredentialMaterial || cap.Kind == CapTicket {
			t.Fatalf("asrep-roast-discover must not claim a credential-bearing postcondition (the real scenario step only discovers roastable accounts, never requests or cracks a ticket), got %+v", cap)
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/adprimitive/... -run TestKerberoastingCatalog -v`
Expected: FAIL — `undefined: KerberoastingCatalog` (the catalog doesn't exist yet).

- [ ] **Step 3: Write the minimal implementation**

```go
// orchestrator/internal/adprimitive/catalog.go

// KerberoastingCatalog backfills AD-M04's schema onto the real,
// already-shipped scenarios/kerberoasting-ad-drill.yaml -- one Primitive
// per scenario stage that actually produces or requires attacker
// capability (stages 4-8 of that scenario are general AD reconnaissance
// -- trust/GPO/privileged-group/LAPS enumeration -- not part of the
// Kerberoasting/AS-REP chain this backfill targets).
var KerberoastingCatalog = []Primitive{
	{
		// Backfills Stage 1 ("AD Stage 1 -- Service Principal Name (SPN)
		// Enumeration (T1558.003)").
		ID: "spn-enumerate", Name: "SPN Enumeration", TechniqueID: "T1558.003",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Privileges:   []string{"domain_user"},
			Capabilities: []Capability{{Kind: CapDomainUser}},
		},
		Postconditions: []Capability{{Kind: CapKerberoastableTargetKnown}},
	},
	{
		// Backfills Stage 2 ("AD Stage 2 -- Kerberoasting TGS-REP Request
		// (no crack) (T1558.003)"). Shares Stage 1's TechniqueID -- ATT&CK
		// does not distinguish "found a target" from "requested its
		// ticket" the way these two primitives do.
		ID: "kerberoast-tgs-request", Name: "Kerberoasting TGS-REP Request", TechniqueID: "T1558.003",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapKerberoastableTargetKnown}},
		},
		Postconditions: []Capability{{Kind: CapServiceAccountCredential}},
	},
	{
		// Backfills Stage 3 ("AD Stage 3 -- AS-REP Roastable Account
		// Discovery (T1558.004)"). The real scenario step is discovery
		// ONLY -- its own blast_radius text is explicit that it never
		// requests or cracks an AS-REP -- so this primitive's
		// postcondition is a discovery capability, never a credential
		// one.
		ID: "asrep-roast-discover", Name: "AS-REP Roastable Account Discovery", TechniqueID: "T1558.004",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Privileges:   []string{"domain_user"},
			Capabilities: []Capability{{Kind: CapDomainUser}},
		},
		Postconditions: []Capability{{Kind: CapASREPRoastableTargetKnown}},
	},
}
```

```go
// In orchestrator/internal/adprimitive/types.go, extend the existing
// CapabilityKind const block (do not create a second block):

const (
	CapDomainUser               CapabilityKind = "DOMAIN_USER"
	CapServiceAccountCredential CapabilityKind = "SERVICE_ACCOUNT_CREDENTIAL"
	CapLocalAdmin               CapabilityKind = "LOCAL_ADMIN"
	CapNTLMHash                 CapabilityKind = "NTLM_HASH"
	CapTicket                   CapabilityKind = "TICKET"
	CapDomainCredentialMaterial CapabilityKind = "DOMAIN_CREDENTIAL_MATERIAL"

	// The 2 below are DISCOVERY-type capabilities (knowledge of a target,
	// not possession of a credential), added for the Kerberoasting/AS-REP
	// catalog backfill -- CapabilityKind was always an open string type,
	// so this extends it rather than redesigning it.
	CapKerberoastableTargetKnown CapabilityKind = "KERBEROASTABLE_TARGET_KNOWN"
	CapASREPRoastableTargetKnown CapabilityKind = "ASREP_ROASTABLE_TARGET_KNOWN"
)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/adprimitive/... -v`
Expected: PASS — all tests in the package, the 3 pre-existing schema tests plus the 3 new catalog tests.

- [ ] **Step 5: Run gofmt and go vet**

Run: `cd orchestrator && gofmt -l internal/adprimitive/ && go vet ./internal/adprimitive/...`
Expected: both print nothing.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/adprimitive/catalog.go orchestrator/internal/adprimitive/catalog_test.go orchestrator/internal/adprimitive/types.go
git commit -m "$(cat <<'EOF'
feat(adprimitive): backfill Kerberoasting/AS-REP primitives (AD-M04)

KerberoastingCatalog maps 3 primitives onto scenarios/kerberoasting-
ad-drill.yaml's real stages 1-3: spn-enumerate and
kerberoast-tgs-request (both T1558.003 -- confirms AD.txt's point
that one ATT&CK technique covers multiple primitives) and
asrep-roast-discover (T1558.004, discovery only -- the real scenario
step never requests or cracks a ticket, so its postcondition stays a
discovery capability, never a credential one).

Adds 2 CapabilityKind constants for the discovery-type capabilities
these primitives produce; CapabilityKind was always an open string
type, so this extends it rather than redesigning AD-M04's schema.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Execution Handoff

**Execution method: Native (inline, this session), per the user's standing preference and the wave/phase process they set for this initiative — no subagent dispatch.** Single task, extends an already-tested schema with data only; proceeding directly to execution via `superpowers:executing-plans`.
