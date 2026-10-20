# Ransomware Domain Taxonomy (`internal/rwtaxonomy`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish a closed 12-domain ransomware capability taxonomy and a validated, fail-closed technique-to-domain mapping for every MITRE technique used by Audspect's 8 ransomware scenarios/drills.

**Architecture:** One new, isolated, pure-Go package (`internal/rwtaxonomy`) with a closed `Domain` enum, a `map[string]Domain` technique lookup, and a content-verification test that parses the real scenario YAML corpus at test time and fails if the mapping and the corpus ever diverge in either direction.

**Tech Stack:** Go. Reuses `internal/scenario.ParseYAML` and `internal/scenario.Step.TechniqueID` (already-established content-verification pattern from `internal/rwdetect/profiles_test.go`). No DB, no HTTP, no testcontainers.

**Spec:** `docs/superpowers/specs/2026-10-12-ransomware-domain-taxonomy-design.md`

## Global Constraints

- `Domain` is a dedicated Go type (`type Domain string`), never aliased to `models.Tactic` (MITRE's 14 generic tactics) or `rwevidence.Capability` (the orthogonal control-efficacy axis).
- `TechniqueDomain` is one-to-one by construction: it is a `map[string]Domain`, so a technique can never carry two domains. There is no multi-domain representation anywhere in this plan.
- Nothing in the codebase calls this package after this pass ships. No HTTP endpoint, no DB table/column, no scoring change, no reporting change is part of this plan.
- `scenario.Scenario.MITREPhases` (the informal 8-phase field) is not touched by this pass.
- This taxonomy is ransomware-specific: `TechniqueDomain` covers only the technique IDs that actually appear in the 8 ransomware scenario/drill YAMLs listed below, not the full MITRE ATT&CK catalog.

## Review Focus

- A scenario introduces a new `technique_id` that `TechniqueDomain` has no entry for — the real-corpus test must fail, not silently skip it. Task 2's `TestTechniqueDomain_MatchesRealCorpus` pins this with a real two-way comparison against freshly-parsed YAML, not a hardcoded count.
- A mapping entry's value is a typo'd or retired `Domain` constant — `Domain.Valid()` must reject it, and a test must prove every `TechniqueDomain` value passes `Valid()`. Task 2's `TestTechniqueDomain_AllValuesAreValidDomains` pins this.
- A mapping entry's key is a malformed technique ID (missing the `T` prefix, a 2-digit or 3-digit main number, a sub-technique suffix of the wrong length) — `techniqueIDPattern` must reject it, proven against both valid and invalid examples. Task 2's `TestTechniqueDomain_AllKeysAreWellFormedTechniqueIDs` pins this.
- `AllDomains` silently drifts out of ransomware.txt's own order (e.g. after a future edit) — a literal, ordered comparison against the 12 names, not just a set-equality check, is needed so a reorder is caught even though it wouldn't break any map lookup. Task 1's `TestAllDomains_HasExactlyTwelveEntriesInRoadmapOrder` pins this.
- A technique legitimately retired from the real scenario corpus (a scenario edited or removed) would leave a stale, now-unused entry in `TechniqueDomain` forever if the real-corpus test only checked one direction (corpus → map). Task 2's `TestTechniqueDomain_MatchesRealCorpus` checks **both** directions for exactly this reason.

---

### Task 1: `Domain` enum — the closed 12-value type

**Files:**
- Create: `orchestrator/internal/rwtaxonomy/domain.go`
- Create: `orchestrator/internal/rwtaxonomy/domain_test.go`

**Interfaces:**
- Consumes: nothing (first task in the package).
- Produces: `type Domain string`; 12 consts (`DomainInitialAccess` … `DomainPostIncidentAssurance`); `var AllDomains []Domain`; `func (d Domain) Valid() bool`. Task 2 consumes all of these.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/rwtaxonomy/domain_test.go`:

```go
package rwtaxonomy

import "testing"

func TestAllDomains_HasExactlyTwelveEntriesInRoadmapOrder(t *testing.T) {
	want := []Domain{
		DomainInitialAccess,
		DomainPreparationAndPersistence,
		DomainCredentialAccess,
		DomainLateralMovement,
		DomainDefenseEvasion,
		DomainDataDiscoveryAndStaging,
		DomainExfiltration,
		DomainEncryptionAndDestruction,
		DomainRecoveryInhibition,
		DomainContainmentAndResponse,
		DomainRecoveryAndResilience,
		DomainPostIncidentAssurance,
	}
	if len(AllDomains) != len(want) {
		t.Fatalf("len(AllDomains) = %d, want %d", len(AllDomains), len(want))
	}
	for i, d := range want {
		if AllDomains[i] != d {
			t.Errorf("AllDomains[%d] = %q, want %q -- order must match ransomware.txt's own table exactly, not just contain the same values", i, AllDomains[i], d)
		}
	}
}

func TestDomain_ValidAcceptsEveryMemberOfAllDomains(t *testing.T) {
	for _, d := range AllDomains {
		if !d.Valid() {
			t.Errorf("Domain(%q).Valid() = false, want true -- every member of AllDomains must be valid", d)
		}
	}
}

func TestDomain_ValidRejectsUnknownValue(t *testing.T) {
	if Domain("not_a_real_domain").Valid() {
		t.Fatal("Valid() = true for an unknown domain string, want false")
	}
	if Domain("").Valid() {
		t.Fatal("Valid() = true for an empty string, want false")
	}
}

func TestDomainConstants_HaveExpectedStringValues(t *testing.T) {
	cases := map[Domain]string{
		DomainInitialAccess:             "initial_access",
		DomainPreparationAndPersistence: "preparation_and_persistence",
		DomainCredentialAccess:          "credential_access",
		DomainLateralMovement:           "lateral_movement",
		DomainDefenseEvasion:            "defense_evasion",
		DomainDataDiscoveryAndStaging:   "data_discovery_and_staging",
		DomainExfiltration:              "exfiltration",
		DomainEncryptionAndDestruction:  "encryption_and_destruction",
		DomainRecoveryInhibition:        "recovery_inhibition",
		DomainContainmentAndResponse:    "containment_and_response",
		DomainRecoveryAndResilience:     "recovery_and_resilience",
		DomainPostIncidentAssurance:     "post_incident_assurance",
	}
	for constVal, want := range cases {
		if string(constVal) != want {
			t.Errorf("const %q, want string value %q", constVal, want)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/rwtaxonomy/ -v`
Expected: FAIL with a build error (`undefined: Domain`, `undefined: AllDomains`, etc.) — the package doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `orchestrator/internal/rwtaxonomy/domain.go`:

```go
// Package rwtaxonomy classifies MITRE ATT&CK techniques used by Audspect's
// ransomware scenarios into the 12 ransomware-specific capability domains
// from ransomware.txt (lines 171-183). It answers one question only: which
// part of the ransomware kill chain does a technique represent. It never
// answers how controls responded to that technique -- that is
// internal/rwevidence's job, an orthogonal axis. See
// docs/superpowers/specs/2026-10-12-ransomware-domain-taxonomy-design.md.
package rwtaxonomy

// Domain is one of the 12 ransomware-specific capability domains. It is a
// dedicated type, never aliased to models.Tactic (MITRE's 14 generic
// Enterprise tactics) or rwevidence.Capability (the control-efficacy axis)
// -- those answer different questions at a different granularity.
type Domain string

const (
	DomainInitialAccess             Domain = "initial_access"
	DomainPreparationAndPersistence Domain = "preparation_and_persistence"
	DomainCredentialAccess          Domain = "credential_access"
	DomainLateralMovement           Domain = "lateral_movement"
	DomainDefenseEvasion            Domain = "defense_evasion"
	DomainDataDiscoveryAndStaging   Domain = "data_discovery_and_staging"
	DomainExfiltration              Domain = "exfiltration"
	DomainEncryptionAndDestruction  Domain = "encryption_and_destruction"
	DomainRecoveryInhibition        Domain = "recovery_inhibition"
	DomainContainmentAndResponse    Domain = "containment_and_response"
	DomainRecoveryAndResilience     Domain = "recovery_and_resilience"
	DomainPostIncidentAssurance     Domain = "post_incident_assurance"
)

// AllDomains is the closed, ordered set of valid domains -- the single
// source of truth other code (including this package's own tests) checks
// membership against. Order matches ransomware.txt's own table.
var AllDomains = []Domain{
	DomainInitialAccess, DomainPreparationAndPersistence, DomainCredentialAccess,
	DomainLateralMovement, DomainDefenseEvasion, DomainDataDiscoveryAndStaging,
	DomainExfiltration, DomainEncryptionAndDestruction, DomainRecoveryInhibition,
	DomainContainmentAndResponse, DomainRecoveryAndResilience, DomainPostIncidentAssurance,
}

// Valid reports whether d is one of AllDomains.
func (d Domain) Valid() bool {
	for _, v := range AllDomains {
		if d == v {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/rwtaxonomy/ -v`
Expected: PASS, 4/4 (`TestAllDomains_HasExactlyTwelveEntriesInRoadmapOrder`, `TestDomain_ValidAcceptsEveryMemberOfAllDomains`, `TestDomain_ValidRejectsUnknownValue`, `TestDomainConstants_HaveExpectedStringValues`).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/rwtaxonomy/domain.go orchestrator/internal/rwtaxonomy/domain_test.go
git commit -m "feat(rwtaxonomy): closed 12-domain enum

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 2: Technique-to-domain mapping + fail-closed real-corpus validation

**Files:**
- Create: `orchestrator/internal/rwtaxonomy/mapping.go`
- Create: `orchestrator/internal/rwtaxonomy/mapping_test.go`
- Create: `orchestrator/internal/rwtaxonomy/mapping_corpus_test.go`

**Interfaces:**
- Consumes: `Domain`, `AllDomains`, `(Domain).Valid()` from Task 1 (exact names, no changes). Also consumes `scenario.ParseYAML(b []byte) (*scenario.Scenario, error)` and `scenario.Step.TechniqueID string` from `internal/scenario` (confirmed at `orchestrator/internal/scenario/engine.go:274` and `orchestrator/internal/scenario/types.go:124` respectively) — read-only, this plan does not modify `internal/scenario`.
- Produces: `TechniqueDomain map[string]Domain`; `func DomainFor(techniqueID string) (Domain, bool)`. Nothing later in this plan consumes these (Task 3 is verification-only), but this is the package's permanent public surface for any future caller.

- [ ] **Step 1: Write the failing tests — construction-level checks**

Create `orchestrator/internal/rwtaxonomy/mapping_test.go`:

```go
package rwtaxonomy

import "testing"

func TestTechniqueDomain_AllValuesAreValidDomains(t *testing.T) {
	for id, d := range TechniqueDomain {
		if !d.Valid() {
			t.Errorf("TechniqueDomain[%q] = %q, not a valid Domain", id, d)
		}
	}
}

func TestTechniqueDomain_AllKeysAreWellFormedTechniqueIDs(t *testing.T) {
	for id := range TechniqueDomain {
		if !techniqueIDPattern.MatchString(id) {
			t.Errorf("TechniqueDomain key %q does not match a valid MITRE technique ID pattern", id)
		}
	}
}

func TestTechniqueIDPattern_RejectsMalformedIDs(t *testing.T) {
	invalid := []string{"1486", "T148", "T14866", "T1486.00", "T1486.0000", "t1486", "T1486.", ""}
	for _, id := range invalid {
		if techniqueIDPattern.MatchString(id) {
			t.Errorf("techniqueIDPattern matched invalid ID %q, want no match", id)
		}
	}
}

func TestTechniqueIDPattern_AcceptsWellFormedIDs(t *testing.T) {
	valid := []string{"T1486", "T1021.001", "T1543.003"}
	for _, id := range valid {
		if !techniqueIDPattern.MatchString(id) {
			t.Errorf("techniqueIDPattern did not match valid ID %q, want match", id)
		}
	}
}

func TestDomainFor_KnownTechniqueReturnsTrueAndItsDomain(t *testing.T) {
	d, ok := DomainFor("T1486")
	if !ok {
		t.Fatal("ok = false for T1486, want true")
	}
	if d != DomainEncryptionAndDestruction {
		t.Errorf("DomainFor(\"T1486\") = %q, want %q", d, DomainEncryptionAndDestruction)
	}
}

func TestDomainFor_UnknownTechniqueReturnsFalse(t *testing.T) {
	_, ok := DomainFor("T9999")
	if ok {
		t.Fatal("ok = true for an unmapped technique ID, want false")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/rwtaxonomy/ -v -run TestTechniqueDomain_AllValuesAreValidDomains`
Expected: FAIL with a build error (`undefined: TechniqueDomain`).

- [ ] **Step 3: Write the mapping implementation**

Create `orchestrator/internal/rwtaxonomy/mapping.go`:

```go
package rwtaxonomy

import "regexp"

// techniqueIDPattern matches a syntactically valid MITRE ATT&CK technique
// ID: Txxxx or Txxxx.yyy.
var techniqueIDPattern = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)

// TechniqueDomain maps every MITRE technique ID referenced by the 8
// ransomware scenarios/drills in scenarios/ to its one primary domain in
// THIS ransomware-specific context. A technique mapped here under one
// domain is not a claim that it belongs exclusively to that domain across
// every ATT&CK context -- only that, as used in Audspect's ransomware
// corpus today, this is its primary classification.
var TechniqueDomain = map[string]Domain{
	"T1003.002": DomainCredentialAccess,          // OS Credential Dumping: SAM
	"T1021.001": DomainLateralMovement,           // Remote Services: RDP
	"T1021.002": DomainLateralMovement,           // Remote Services: SMB/Windows Admin Shares
	"T1070.001": DomainPostIncidentAssurance,     // Indicator Removal: Clear Windows Event Logs.
	// Ambiguous case, documented per the spec: this could reasonably sit
	// under Defense Evasion (MITRE's own tactic for it) instead. Chosen as
	// Post-Incident Assurance because that domain's own description
	// ("evidence preservation, root-cause findings, regression testing")
	// is precisely about whether evidence survives an attacker's attempt
	// to erase it, while Defense Evasion's description here is specifically
	// about security-tool tampering and agent health, not log/forensic-
	// trail destruction.
	"T1083":     DomainDataDiscoveryAndStaging,   // File and Directory Discovery (BFSI sensitive-file recon ahead of staging)
	"T1087.002": DomainPreparationAndPersistence, // Account Discovery: Domain Account
	"T1135":     DomainLateralMovement,           // Network Share Discovery (ahead of SMB-based lateral movement)
	"T1486":     DomainEncryptionAndDestruction,  // Data Encrypted for Impact
	"T1489":     DomainRecoveryInhibition,        // Service Stop (backup service stop attempt, em-07 Stage 5A)
	"T1490":     DomainRecoveryInhibition,        // Inhibit System Recovery
	"T1518.001": DomainPreparationAndPersistence, // Security Software Discovery
	"T1543.003": DomainPreparationAndPersistence, // Create or Modify System Process: Windows Service
	"T1560.001": DomainDataDiscoveryAndStaging,   // Archive Collected Data via Utility
	"T1562.001": DomainDefenseEvasion,            // Impair Defenses: Disable or Modify Tools
	"T1567.002": DomainExfiltration,              // Exfiltration to Cloud Storage
}

// DomainFor returns techniqueID's mapped domain and true, or ("", false)
// if techniqueID has no entry.
func DomainFor(techniqueID string) (Domain, bool) {
	d, ok := TechniqueDomain[techniqueID]
	return d, ok
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/rwtaxonomy/ -v`
Expected: PASS, all tests from Task 1 and Task 2 Step 1 green (10 tests total).

- [ ] **Step 5: Write the failing test — fail-closed real-corpus validation**

Create `orchestrator/internal/rwtaxonomy/mapping_corpus_test.go`. This follows `internal/rwdetect/profiles_test.go`'s already-established pattern exactly (same helper shape, same 8-file list, same `scenario.ParseYAML` + field extraction), substituting `step.TechniqueID` for that file's `step.DetectionProfiles`:

```go
package rwtaxonomy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

// ransomwareScenarioFiles matches internal/rwdetect/profiles_test.go's own
// list and internal/api.ransomwareScenarioIDs' 8 entries exactly -- kept as
// its own small copy here since that list is unexported in rwdetect.
var ransomwareScenarioFiles = []string{
	"akira-kill-chain.yaml", "blackcat-kill-chain.yaml", "clop-kill-chain.yaml",
	"lockbit-kill-chain.yaml", "play-kill-chain.yaml", "ransomhub-kill-chain.yaml",
	"ransomware-drill.yaml", "endpoint-mastery/em-07-ransomware-readiness.yaml",
}

// repoScenariosDir resolves ../../../scenarios relative to this package --
// same relative depth as internal/rwdetect's own helper (internal/rwtaxonomy
// and internal/rwdetect sit at the same depth under orchestrator/internal/).
func repoScenariosDir(t *testing.T) string {
	dir, err := filepath.Abs("../../../scenarios")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("scenarios dir not found at %s: %v", dir, err)
	}
	return dir
}

// TestTechniqueDomain_MatchesRealCorpus is the single most important test
// in this package: it parses all 8 real scenario YAMLs fresh, collects
// every distinct technique_id actually used, and checks a two-way match
// against TechniqueDomain's keys. A scenario introducing an unmapped
// technique fails the first loop; a mapping entry whose technique was
// removed/renamed from every scenario fails the second loop -- a stale
// mapping is caught just as reliably as a missing one.
func TestTechniqueDomain_MatchesRealCorpus(t *testing.T) {
	seen := map[string]bool{}
	for _, file := range ransomwareScenarioFiles {
		b, err := os.ReadFile(filepath.Join(repoScenariosDir(t), file))
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		sc, err := scenario.ParseYAML(b)
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		for _, step := range sc.Steps {
			if step.TechniqueID != "" {
				seen[step.TechniqueID] = true
			}
		}
	}

	for id := range seen {
		if _, ok := TechniqueDomain[id]; !ok {
			t.Errorf("real corpus references technique %q, not in TechniqueDomain -- mapping is stale (unmapped technique introduced)", id)
		}
	}
	for id := range TechniqueDomain {
		if !seen[id] {
			t.Errorf("TechniqueDomain maps %q, but no real scenario step references it -- mapping is stale (technique retired from corpus)", id)
		}
	}
}
```

- [ ] **Step 6: Run test to verify it fails or passes for the right reason**

Run: `cd orchestrator && go test ./internal/rwtaxonomy/ -v -run TestTechniqueDomain_MatchesRealCorpus`
Expected: Since `TechniqueDomain` was already written in Step 3 against the real corpus, this test is expected to PASS immediately. This is acceptable here — unlike a RED-GREEN cycle for new production code, this is a test *of* already-written data against ground truth, the same situation `internal/rwpropagation`'s plan documented for its own cross-package test. To confirm the test can actually fail, temporarily comment out the `"T1486": DomainEncryptionAndDestruction,` line in `mapping.go`, re-run, and confirm:

Expected (with the line commented out): FAIL — `real corpus references technique "T1486", not in TechniqueDomain -- mapping is stale (unmapped technique introduced)`.

Then restore the line and re-run to confirm PASS again.

- [ ] **Step 7: Run the full package test suite**

Run: `cd orchestrator && go test ./internal/rwtaxonomy/ -v`
Expected: PASS, all tests green (Task 1's 4 + Task 2's 6 construction tests + 1 corpus test = 11 tests).

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/rwtaxonomy/mapping.go orchestrator/internal/rwtaxonomy/mapping_test.go orchestrator/internal/rwtaxonomy/mapping_corpus_test.go
git commit -m "feat(rwtaxonomy): technique-to-domain mapping with fail-closed corpus validation

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 3: Final package regression

**Files:**
- None (verification-only task; no new code).

**Interfaces:**
- Consumes: everything from Tasks 1-2.
- Produces: nothing — this is the plan's terminal verification layer.

- [ ] **Step 1: Run the full regression**

Run: `cd orchestrator && go test ./internal/rwtaxonomy/ -v`
Expected: `ok  	github.com/audspect/bas/internal/rwtaxonomy`, 0 FAIL. Note: this package is pure Go with no testcontainers and no DB/HTTP dependency anywhere — unlike most other sub-projects this session, there is no memory-pressure constraint and no need to run this alone or in the background. A plain foreground run is sufficient.

- [ ] **Step 2: If everything passes, there is nothing to commit for this task** — it exists only to confirm the whole package together, one final time, exactly as a reader encountering it fresh would run it.
