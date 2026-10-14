# AD-M04 Primitive Schema Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (execution method already decided — native/inline, no subagent dispatch). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Define the AD attack-primitive schema (AD-M04's first sub-phase): a `Primitive` type carrying the prerequisite/postcondition pair AD.txt calls "absolutely necessary" (lines 343-396), with zero backfill of real scenarios and zero gap-filling — those are separate future sub-phases of M04, per the wave process.

**Architecture:** New package `orchestrator/internal/adprimitive`, following the exact precedent `adenv` set for AD-M01: one file of pure data types, one JSON round-trip test, no behavior. `Primitive` is deliberately a SEPARATE concept from a MITRE ATT&CK technique ID (AD.txt lines 129-178: one technique like T1649/ADCS maps to many primitives -- CA discovery, template discovery, enrollment permissions, each modeled individually), so `Primitive.TechniqueID` is optional, not every primitive has one. AD.txt's own illustrative examples use two slightly different vocabularies for the capability a primitive produces/requires (a loose flag like `credential_material_obtained` in one example, a structured list like `SERVICE_ACCOUNT_CREDENTIAL` in another) -- this plan reconciles them into one consistent `Capability{Kind, Target}` type used in both `Prerequisites` and `Postconditions`, so a future chain planner (AD-M05) can match one primitive's output against another's input by equality, not by string-matching two different vocabularies.

**Tech Stack:** Go (matches `orchestrator`'s existing stdlib-only convention; no new dependencies).

**Spec:** No separate written spec document — bounded, conversationally-approved task per the user's "wave → short design → bounded implementation plan → execute → verify → stop" process. The source material is `AD.txt` at the repo root, specifically lines 129-178 (primitive-vs-technique separation) and 343-396 (prerequisites/postconditions/capability examples).

## Global Constraints

- Go stdlib only — no new third-party dependencies.
- `go 1.26.6`, module path `github.com/audspect/bas`.
- JSON field names are camelCase, matching `adenv`'s and `attackpath`'s existing convention.
- `Target` on `Capability` stays a plain string (e.g. `"SERVER01"` for a `LOCAL_ADMIN@SERVER01`-style capability) and empty for host-agnostic capabilities (`DOMAIN_USER`, `NTLM_HASH`). Binding a real host into that field when planning an actual attack chain is AD-M05's job (the chain planner), not modeled here — this schema only describes what KIND of target-scoping a capability has, not a live value.
- `Prerequisites.Conditions` stays an open `map[string]bool` (AD.txt's own example key, `spn_account_exists`, is primitive-specific and not drawn from any closed set) — do not try to enumerate every possible condition up front.

## Review Focus

- A primitive with NO `TechniqueID` (e.g. an ADCS sub-step like "template discovery" that AD.txt explicitly says has no dedicated MITRE ID) must round-trip cleanly with that field absent, not required. Tested in Task 1, Step 1 (the zero-value test already covers this generically, but the fully-populated fixture also includes one primitive with `TechniqueID` empty, so both "has one" and "doesn't" are exercised).
- A host-scoped capability (`LOCAL_ADMIN` with a `Target`) and a host-agnostic one (`DOMAIN_USER`, no `Target`) must both round-trip correctly in the SAME `Postconditions` slice — the most likely bug in a struct with an optional sub-field is losing it under `omitempty` on one but not the other. Tested in Task 1, Step 1.
- `Prerequisites.Capabilities` (what the attacker must already hold) and `Postconditions` (what the attacker gains) use the exact same `Capability` type — a future chain planner needs `reflect.DeepEqual`-style matching between one primitive's postcondition and the next's prerequisite to work without a translation step. Tested in Task 1, Step 1 (the fixture's Kerberoast primitive's prerequisite capability and a second primitive's postcondition use the identical `Capability{Kind: CapDomainUser}` value).

---

### Task 1: Define the `adprimitive.Primitive` schema with a JSON round-trip test

**Files:**
- Create: `orchestrator/internal/adprimitive/types.go`
- Test: `orchestrator/internal/adprimitive/types_test.go`

**Interfaces:**
- Consumes: nothing (first file in a new package; deliberately has NO dependency on `adenv` or `attackpath` — a primitive describes an attack TECHNIQUE, not an environment snapshot or a graph, so it doesn't need either).
- Produces: `adprimitive.Primitive`, `Prerequisites`, `Capability`, `CapabilityKind` (with 6 constants matching AD.txt's capability-state example at lines 379-395) — a future AD-M05 chain planner and a future scenario-backfill sub-phase of M04 both import `github.com/audspect/bas/internal/adprimitive` and construct/read these exact names.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/adprimitive/types_test.go
package adprimitive

import (
	"encoding/json"
	"reflect"
	"testing"
)

// twoChainedPrimitives is Kerberoasting (AD.txt's own worked example,
// lines 349-360) followed by a second primitive that CONSUMES the
// DOMAIN_USER capability every domain principal already starts with --
// exercising a host-agnostic capability, a host-scoped one, an empty
// TechniqueID, and prerequisite/postcondition capability matching, all in
// one fixture.
func twoChainedPrimitives() []Primitive {
	return []Primitive{
		{
			ID: "kerberoast", Name: "Kerberoasting", TechniqueID: "T1558.003",
			Prerequisites: Prerequisites{
				DomainJoined: true,
				Privileges:   []string{"domain_user"},
				Capabilities: []Capability{{Kind: CapDomainUser}},
				Conditions:   map[string]bool{"spn_account_exists": true},
			},
			Postconditions: []Capability{{Kind: CapServiceAccountCredential}},
		},
		{
			// AD.txt lines 144-156: ADCS sub-steps like template discovery
			// have no dedicated MITRE technique ID -- TechniqueID empty here
			// on purpose.
			ID: "adcs-template-discovery", Name: "ADCS Certificate Template Discovery",
			Prerequisites: Prerequisites{
				DomainJoined: true,
				Capabilities: []Capability{{Kind: CapServiceAccountCredential}},
			},
			Postconditions: []Capability{
				{Kind: CapLocalAdmin, Target: "SERVER01"},
			},
		},
	}
}

func TestPrimitive_JSONRoundTrip_FullyPopulated(t *testing.T) {
	prims := twoChainedPrimitives()

	data, err := json.Marshal(prims)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got []Primitive
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(prims, got) {
		t.Fatalf("round-trip mismatch:\n got  %+v\n want %+v", got, prims)
	}
}

func TestPrimitive_JSONRoundTrip_ZeroValue(t *testing.T) {
	var p Primitive

	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got Primitive
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(p, got) {
		t.Fatalf("zero-value round-trip mismatch:\n got  %+v\n want %+v", got, p)
	}
}

func TestPrimitive_PostconditionMatchesNextPrerequisite(t *testing.T) {
	prims := twoChainedPrimitives()
	// The planner's core operation (AD-M05, not implemented here): can
	// primitive B run after primitive A, because A's postcondition
	// satisfies one of B's required capabilities? Prove the TYPE supports
	// this match by plain equality, with no translation step.
	kerberoast, adcs := prims[0], prims[1]
	satisfied := false
	for _, have := range kerberoast.Postconditions {
		for _, need := range adcs.Prerequisites.Capabilities {
			if have == need {
				satisfied = true
			}
		}
	}
	if !satisfied {
		t.Fatalf("expected kerberoast's postcondition %+v to satisfy adcs-template-discovery's prerequisite %+v by equality", kerberoast.Postconditions, adcs.Prerequisites.Capabilities)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/adprimitive/... -v`
Expected: FAIL — `undefined: Primitive` (the package doesn't exist yet).

- [ ] **Step 3: Write the minimal implementation**

```go
// orchestrator/internal/adprimitive/types.go

// Package adprimitive is the AD attack-primitive schema (AD-M04): a typed
// description of an individual AD attack technique's prerequisites and
// postconditions, per AD.txt lines 343-396.
//
// A Primitive is deliberately NOT the same concept as a MITRE ATT&CK
// technique ID. AD.txt (lines 129-178) is explicit that one technique can
// cover many primitives -- ADCS/T1649 alone decomposes into CA discovery,
// template discovery, enrollment-permission analysis, EKU analysis, and
// more, each with its own prerequisites and postconditions. TechniqueID
// is therefore optional: many primitives have no single MITRE ID to
// point to.
//
// This package holds pure data types only -- no chain-planning logic
// (AD-M05 will consume Capability equality between one primitive's
// Postconditions and another's Prerequisites.Capabilities to decide what
// can follow what) and no scenario backfill (a separate future AD-M04
// sub-phase maps these onto the existing scenarios/*.yaml step format).
package adprimitive

// CapabilityKind is one of the attacker capability states AD.txt's own
// worked example names (lines 379-395).
type CapabilityKind string

const (
	CapDomainUser               CapabilityKind = "DOMAIN_USER"
	CapServiceAccountCredential CapabilityKind = "SERVICE_ACCOUNT_CREDENTIAL"
	CapLocalAdmin               CapabilityKind = "LOCAL_ADMIN"
	CapNTLMHash                 CapabilityKind = "NTLM_HASH"
	CapTicket                   CapabilityKind = "TICKET"
	CapDomainCredentialMaterial CapabilityKind = "DOMAIN_CREDENTIAL_MATERIAL"
)

// Capability is an attacker capability state, optionally scoped to a
// target (e.g. LOCAL_ADMIN@SERVER01 is Capability{Kind: CapLocalAdmin,
// Target: "SERVER01"}; DOMAIN_USER is host-agnostic, Target stays "").
// Binding a real host into Target when planning an actual chain is
// AD-M05's job, not this schema's.
type Capability struct {
	Kind   CapabilityKind `json:"kind"`
	Target string         `json:"target,omitempty"`
}

// Prerequisites is what must already be true for a Primitive to be
// applicable, per AD.txt's worked example (lines 349-354).
type Prerequisites struct {
	DomainJoined bool     `json:"domainJoined"`
	Privileges   []string `json:"privileges,omitempty"` // e.g. "domain_user" -- AD.txt gives no closed set

	// Capabilities are attacker capability states that must already be
	// held -- the chain-reasoning half (AD.txt lines 362-369: "requires:
	// - credential_material_obtained"). Matched against another
	// Primitive's Postconditions by equality.
	Capabilities []Capability `json:"capabilities,omitempty"`

	// Conditions are open-ended environment-state checks specific to
	// this primitive (AD.txt's own example key is "spn_account_exists"),
	// never drawn from a fixed enum.
	Conditions map[string]bool `json:"conditions,omitempty"`
}

// Primitive is one AD attack primitive: an action with a name, an
// optional MITRE cross-reference, what it requires, and what capability
// it grants once it succeeds.
type Primitive struct {
	ID          string `json:"id"`                    // e.g. "kerberoast", "adcs-template-discovery"
	Name        string `json:"name"`
	TechniqueID string `json:"techniqueId,omitempty"` // MITRE ATT&CK sub-technique, when one exists

	Prerequisites  Prerequisites `json:"prerequisites"`
	Postconditions []Capability  `json:"postconditions,omitempty"` // capabilities GAINED once this primitive succeeds
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/adprimitive/... -v`
Expected: PASS — all 3 tests (`TestPrimitive_JSONRoundTrip_FullyPopulated`, `TestPrimitive_JSONRoundTrip_ZeroValue`, `TestPrimitive_PostconditionMatchesNextPrerequisite`).

- [ ] **Step 5: Run gofmt and go vet**

Run: `cd orchestrator && gofmt -l internal/adprimitive/ && go vet ./internal/adprimitive/...`
Expected: both print nothing.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/adprimitive/types.go orchestrator/internal/adprimitive/types_test.go
git commit -m "$(cat <<'EOF'
feat(adprimitive): add AD attack-primitive schema (AD-M04, schema only)

Primitive{ID, Name, TechniqueID (optional), Prerequisites,
Postconditions} per AD.txt lines 343-396's prerequisite/postcondition
model, with a Capability{Kind, Target} type used on both sides so a
future chain planner (AD-M05) can match one primitive's output
against another's input by equality. TechniqueID is optional because
AD.txt (lines 129-178) is explicit that one MITRE technique can cover
many primitives with no 1:1 mapping.

Pure schema only -- no scenario backfill, no gap-filling, no planner
logic. Those are separate future AD-M04 sub-phases and AD-M05.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Execution Handoff

**Execution method: Native (inline, this session), per the user's standing preference and the wave/phase process they set for this initiative — no subagent dispatch.** Single task, pure data types, no behavior, same low-risk shape as AD-M01's schema task; proceeding directly to execution via `superpowers:executing-plans`.
