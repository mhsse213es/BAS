# AD-M04 RBCD Primitives Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (execution method already decided — native/inline, no subagent dispatch). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fill the RBCD (Resource-Based Constrained Delegation abuse) gap in AD-M04's primitive library with 2 chained primitives, following the exact `ACLAbuseCatalog` precedent.

**Architecture:** Same shape as the ACL-abuse sub-phase: zero scenario YAML exists for RBCD (confirmed by grep across `scenarios/*.yaml`), so this is primitive KNOWLEDGE, not a backfill. The real-world technique: an attacker who already controls some principal (commonly a computer account, often created via `MachineAccountQuota`, which lets any domain user create new computer accounts by default — `CapControlledAccount`, already modeled) and holds a write-capable ACL right (`GenericWrite`/`GenericAll`) over a target computer object can write that computer's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute, naming their controlled principal — this is `rbcd-configure`. Once configured, they can request a service ticket via S4U2Self+S4U2Proxy impersonating ANY user (including a Domain Admin) to the target resource — `rbcd-impersonate`, whose outcome is exactly AD.txt's own `LOCAL_ADMIN@SERVER01` example capability (`CapLocalAdmin`, defined in AD-M04's original schema but never yet used by any catalog). One new `CapabilityKind`, `CapRBCDConfigured`, represents the intermediate state between the two primitives.

**Tech Stack:** Go (matches `orchestrator`'s existing stdlib-only convention; no new dependencies).

**Spec:** No separate written spec document — bounded, conversationally-approved task. Source material: `orchestrator/internal/adprimitive/types.go` (schema) and `catalog.go` (the `ACLAbuseCatalog` convention this plan reuses), and `orchestrator/internal/adenv/types.go`'s `RBCDEntry`/`attackpath/graph.go`'s `EdgeAllowedToAct` (the already-shipped AD-M01/M03 representations of this same technique at the environment/graph level — this plan's primitives describe the TECHNIQUE, those describe the STATE; AD-M05 will eventually connect the two).

## Global Constraints

- Go stdlib only — no new third-party dependencies.
- `go 1.26.6`, module path `github.com/audspect/bas`.
- `adprimitive` still has no dependency on `adenv` or `attackpath`.
- `rbcd-configure`'s prerequisite ACL condition uses the SAME `"acl_right_held:<RightName>"` convention `ACLAbuseCatalog` established — do not invent a second convention for the same kind of fact.
- Neither primitive gets a `TechniqueID` — RBCD privilege escalation has no single clean 1:1 ATT&CK sub-technique (it is sometimes loosely associated with Kerberos ticket abuse, T1558, but that describes the LAST step of RBCD, not the ACL-write configuration step, and forcing one imprecise tag onto both would misrepresent the chain) — consistent with how `ACLAbuseCatalog` already handled this.

## Review Focus

- `rbcd-configure`'s postcondition must satisfy `rbcd-impersonate`'s prerequisite by equality (the same chain-compatibility proof every prior catalog addition has required) — if these two primitives don't actually chain, the whole point of modeling RBCD as 2 steps instead of 1 is lost. Tested in Task 1, Step 1.
- `rbcd-impersonate`'s postcondition must be `CapLocalAdmin` (the pre-existing constant from AD-M04's original schema, unused until now) — NOT a newly-invented capability kind, since AD.txt's own worked example already names exactly this outcome (`LOCAL_ADMIN@SERVER01`) and reusing it proves the schema's vocabulary holds up across a second, independently-designed primitive family. Tested in Task 1, Step 1.
- `rbcd-configure` must require BOTH the ACL condition AND an already-controlled principal (`CapControlledAccount`) as prerequisites — a reasonable reader might assume the ACL right alone suffices, but without a principal to NAME in the attribute, there is nothing to configure. Tested in Task 1, Step 1 (asserts both are present, not just one).

---

### Task 1: Add the 2 RBCD primitives

**Files:**
- Modify: `orchestrator/internal/adprimitive/catalog.go` (new `RBCDCatalog` var)
- Modify: `orchestrator/internal/adprimitive/types.go` (1 new `CapabilityKind` constant)
- Modify: `orchestrator/internal/adprimitive/catalog_test.go` (new tests)

**Interfaces:**
- Consumes: `Primitive`, `Prerequisites`, `Capability`, `CapabilityKind`, `CapControlledAccount`, `CapLocalAdmin` (all from `types.go`; `CapLocalAdmin` was defined in AD-M04's original schema commit and used only in that commit's test fixture until now).
- Produces: `RBCDCatalog []Primitive`, `CapRBCDConfigured` — the next gap-filling sub-phase (DCSync, ADCS-ESC1-4) follows this same `<Name>Catalog` precedent.

- [ ] **Step 1: Write the failing test**

```go
// Append to orchestrator/internal/adprimitive/catalog_test.go

func findInRBCDCatalog(id string) (Primitive, bool) {
	for _, p := range RBCDCatalog {
		if p.ID == id {
			return p, true
		}
	}
	return Primitive{}, false
}

func TestRBCDCatalog_ConfigureRequiresBothACLRightAndControlledPrincipal(t *testing.T) {
	cfg, ok := findInRBCDCatalog("rbcd-configure")
	if !ok {
		t.Fatal("expected rbcd-configure in RBCDCatalog")
	}
	if !cfg.Prerequisites.Conditions["acl_right_held:GenericWrite"] {
		t.Fatalf("expected rbcd-configure to require acl_right_held:GenericWrite, got %+v", cfg.Prerequisites.Conditions)
	}
	hasControlledAccount := false
	for _, c := range cfg.Prerequisites.Capabilities {
		if c.Kind == CapControlledAccount {
			hasControlledAccount = true
		}
	}
	if !hasControlledAccount {
		t.Fatalf("expected rbcd-configure to require CapControlledAccount (a principal to name in the attribute), got %+v", cfg.Prerequisites.Capabilities)
	}
}

func TestRBCDCatalog_ConfigurePostconditionSatisfiesImpersonatePrerequisite(t *testing.T) {
	cfg, _ := findInRBCDCatalog("rbcd-configure")
	imp, ok := findInRBCDCatalog("rbcd-impersonate")
	if !ok {
		t.Fatal("expected rbcd-impersonate in RBCDCatalog")
	}

	satisfied := false
	for _, have := range cfg.Postconditions {
		for _, need := range imp.Prerequisites.Capabilities {
			if have == need {
				satisfied = true
			}
		}
	}
	if !satisfied {
		t.Fatalf("expected rbcd-configure's postcondition %+v to satisfy rbcd-impersonate's prerequisite %+v", cfg.Postconditions, imp.Prerequisites.Capabilities)
	}

	// The outcome is exactly AD.txt's own worked LOCAL_ADMIN@SERVER01
	// example (lines 385-386) -- reusing the pre-existing CapLocalAdmin
	// constant, not inventing a new one.
	if len(imp.Postconditions) != 1 || imp.Postconditions[0].Kind != CapLocalAdmin {
		t.Fatalf("expected rbcd-impersonate postcondition CapLocalAdmin, got %+v", imp.Postconditions)
	}
}

func TestRBCDCatalog_NoneHaveATechniqueID(t *testing.T) {
	for _, p := range RBCDCatalog {
		if p.TechniqueID != "" {
			t.Errorf("expected %s to have no TechniqueID, got %q", p.ID, p.TechniqueID)
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/adprimitive/... -run TestRBCDCatalog -v`
Expected: FAIL — `undefined: RBCDCatalog` (the catalog doesn't exist yet).

- [ ] **Step 3: Write the minimal implementation**

```go
// In orchestrator/internal/adprimitive/types.go, extend the existing
// CapabilityKind const block (do not create a second block):

	CapControlledAccount CapabilityKind = "CONTROLLED_ACCOUNT"
	CapGroupMember       CapabilityKind = "GROUP_MEMBER"

	// CapRBCDConfigured is the intermediate state between configuring
	// Resource-Based Constrained Delegation on a target and actually
	// impersonating a user through it (added for RBCDCatalog).
	CapRBCDConfigured CapabilityKind = "RBCD_CONFIGURED"
```

```go
// Append to orchestrator/internal/adprimitive/catalog.go

// RBCDCatalog defines 2 chained primitives for Resource-Based Constrained
// Delegation abuse, following the same "no scenario YAML yet, primitive
// knowledge only" status as ACLAbuseCatalog (confirmed by grep across
// scenarios/*.yaml).
//
// rbcd-configure requires BOTH a write-capable ACL right over the target
// (the same "acl_right_held:<RightName>" convention ACLAbuseCatalog
// established) AND an already-controlled principal to name in the
// target's msDS-AllowedToActOnBehalfOfOtherIdentity attribute -- commonly
// a computer account the attacker created via MachineAccountQuota (which
// lets any domain user create new computer accounts by default). Once
// configured, rbcd-impersonate requests a service ticket via
// S4U2Self+S4U2Proxy impersonating ANY user (including a Domain Admin) to
// the target -- exactly AD.txt's own worked LOCAL_ADMIN@SERVER01 example
// (lines 385-386), reusing the pre-existing CapLocalAdmin constant rather
// than inventing a new one.
var RBCDCatalog = []Primitive{
	{
		ID: "rbcd-configure", Name: "Configure Resource-Based Constrained Delegation",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapControlledAccount}},
			Conditions:   map[string]bool{"acl_right_held:GenericWrite": true},
		},
		Postconditions: []Capability{{Kind: CapRBCDConfigured}},
	},
	{
		ID: "rbcd-impersonate", Name: "RBCD S4U2Proxy Impersonation",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapRBCDConfigured}},
		},
		Postconditions: []Capability{{Kind: CapLocalAdmin}},
	},
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/adprimitive/... -v`
Expected: PASS — all tests in the package (9 pre-existing plus 3 new).

- [ ] **Step 5: Run gofmt and go vet**

Run: `cd orchestrator && gofmt -l internal/adprimitive/ && go vet ./internal/adprimitive/...`
Expected: both print nothing.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/adprimitive/catalog.go orchestrator/internal/adprimitive/catalog_test.go orchestrator/internal/adprimitive/types.go
git commit -m "$(cat <<'EOF'
feat(adprimitive): add RBCD primitives (AD-M04 gap-filling)

RBCDCatalog: rbcd-configure (requires acl_right_held:GenericWrite +
an already-controlled principal -> CapRBCDConfigured) chains into
rbcd-impersonate (-> CapLocalAdmin, reusing the pre-existing constant
from AD-M04's original schema -- exactly AD.txt's own worked
LOCAL_ADMIN@SERVER01 example). Same "no scenario YAML yet" status as
ACLAbuseCatalog; no TechniqueID on either (no clean 1:1 ATT&CK
mapping for RBCD privilege escalation).

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Execution Handoff

**Execution method: Native (inline, this session), per the user's standing preference and the wave/phase process they set for this initiative — no subagent dispatch.** Single task, extends an already-tested schema with data only; proceeding directly to execution via `superpowers:executing-plans`.
