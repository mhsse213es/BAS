# WAF BAS Mastery Phase 9: Industry and Regional Profiles Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `internal/wafprofile`, a reference/bundling layer that packages waf.txt Phase 9's 6 named industry/regional profiles (BFSI, NBFC, manufacturing, healthcare, India, UAE), each tying a subset of `wafcatalog`'s real attack-vector IDs to the compliance frameworks that make them relevant.

**Architecture:** Three layers: a `ComplianceReference` value type that forces every compliance claim to carry an explicit verification status and explanatory note (Task 1); a `Profile` type plus a catalog cross-reference function that confirms a profile's referenced vector IDs actually exist in the real `wafcatalog` (Task 2); and a seed catalog of the 6 named profiles, validated against the real, live `wafcatalog.AudspectWAFAttackCatalog()` output rather than a fixture (Task 3). This phase has no evidence-evaluation logic of its own — it is a bundling layer, not a claim evaluator.

**Tech Stack:** Go 1.26.6, stdlib only (`fmt`), `internal/wafcatalog` (already merged, read-only dependency).

**Spec:** `docs/superpowers/specs/2026-10-16-waf-bas-phase9-wafprofile-design.md`

## Global Constraints

- Package `internal/wafprofile` depends only on `internal/wafcatalog` (+ stdlib `fmt`); it does not depend on `internal/wafval` or any other WAF-phase package (`wafpolicygap`, `wafevasion`, `wafapiflow`, `wafbotabuse`, `waforigin`, `wafdetection`), and none of those depend on it either.
- This phase has no evidence-evaluation logic of its own — it is a bundling/reference layer only. No function in this package evaluates a `wafval.Result` or any correlation evidence.
- Per spec §2, no `ComplianceReference` anywhere in the seed catalog may assert a specific regulatory clause, circular number, or rule number as fact — only a framework name, general scope, and an explicit `Unverified` status with a `Note` disclosing what was and wasn't confirmed against a primary source.
- `wafcatalog.AttackVector`'s exact fields (confirmed against `orchestrator/internal/wafcatalog/types.go`): `ID, Version, Family, Name, Severity, Preconditions, Malicious, BenignCounterpart, NoBenignCounterpartReason, Standards, Provenance`. `wafcatalog.AudspectWAFAttackCatalog() ([]AttackVector, error)` is already merged and real.

## Review Focus

- `NewComplianceReference` must accept an empty `SourceURL` as valid — not every framework reference has one canonical URL. Pinned in Task 1.
- `NewProfile` must reject a `complianceReferences` entry assembled directly as a struct literal with an empty `Framework`/`Note`, not just one that skipped `NewComplianceReference` entirely — the re-validation must actually inspect field values, not just check `len(complianceReferences) > 0`. Pinned in Task 2.
- `NewProfile` must detect a duplicate `AttackVectorIDs` entry (e.g. `["SQLI-001", "SQLI-001"]`), not just an empty slice. Pinned in Task 2.
- `ValidateAgainstCatalog`'s error must name the specific missing ID, not a generic "validation failed" message. Pinned in Task 2.
- `AudspectWAFProfileCatalog`'s test must validate against the REAL `wafcatalog.AudspectWAFAttackCatalog()` output, not a hand-built fixture catalog — a fixture-based test would never catch a genuine drift between this phase's seed data and the real upstream catalog. Pinned in Task 3.

---

### Task 1: ComplianceReference type

**Files:**
- Create: `orchestrator/internal/wafprofile/compliance.go`
- Test: `orchestrator/internal/wafprofile/compliance_test.go`

**Interfaces:**
- Consumes: nothing from later tasks; stdlib `fmt` only.
- Produces: `VerificationStatus` (+ 2 constants: `Verified`, `Unverified`), `ComplianceReference{Framework, VerificationStatus, Note, SourceURL string}`, `NewComplianceReference(framework string, status VerificationStatus, note string, sourceURL string) (ComplianceReference, error)`.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/wafprofile/compliance_test.go
package wafprofile

import "testing"

func TestNewComplianceReference_Valid_Succeeds(t *testing.T) {
	c, err := NewComplianceReference("RBI Cyber Security Framework for banks", Unverified,
		"framework name and general existence only, drawn from secondary sources; no specific circular verified against RBI's own text",
		"https://ogma.in/rbi-cybersecurity-framework-2026-complete-compliance-guide-for-banks-and-nbfcs")
	if err != nil {
		t.Fatalf("NewComplianceReference: %v", err)
	}
	if c.Framework != "RBI Cyber Security Framework for banks" {
		t.Errorf("Framework = %q, want %q", c.Framework, "RBI Cyber Security Framework for banks")
	}
}

// Review Focus: not every framework reference has one canonical URL.
func TestNewComplianceReference_EmptySourceURL_Succeeds(t *testing.T) {
	c, err := NewComplianceReference("CERT-In Cyber Security Directions", Unverified,
		"framework name and the widely-reported 6-hour incident-reporting requirement only", "")
	if err != nil {
		t.Fatalf("NewComplianceReference: %v", err)
	}
	if c.SourceURL != "" {
		t.Errorf("SourceURL = %q, want empty", c.SourceURL)
	}
}

func TestNewComplianceReference_EmptyFramework_Rejected(t *testing.T) {
	_, err := NewComplianceReference("", Unverified, "x", "")
	if err == nil {
		t.Fatal("want error for empty framework, got nil")
	}
}

func TestNewComplianceReference_EmptyNote_Rejected(t *testing.T) {
	_, err := NewComplianceReference("x", Unverified, "", "")
	if err == nil {
		t.Fatal("want error for empty note, got nil")
	}
}

func TestNewComplianceReference_InvalidStatus_Rejected(t *testing.T) {
	_, err := NewComplianceReference("x", VerificationStatus("bogus_status"), "y", "")
	if err == nil {
		t.Fatal("want error for an unknown VerificationStatus, got nil")
	}
}

func TestNewComplianceReference_VerifiedStatus_Succeeds(t *testing.T) {
	c, err := NewComplianceReference("x", Verified, "explicitly confirmed against a primary source for this test", "")
	if err != nil {
		t.Fatalf("NewComplianceReference: %v", err)
	}
	if c.VerificationStatus != Verified {
		t.Errorf("VerificationStatus = %q, want %q", c.VerificationStatus, Verified)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/wafprofile/... -v`
Expected: FAIL — package doesn't exist yet (compile error naming undefined symbols).

- [ ] **Step 3: Write `compliance.go`**

```go
// orchestrator/internal/wafprofile/compliance.go
// Package wafprofile is a bundling/reference layer covering waf.txt
// Phase 9's industry-and-regional-profiles item. It is deliberately NOT
// an evidence evaluator: it depends only on internal/wafcatalog, to
// confirm that a profile's referenced attack-vector IDs actually exist
// in the real catalog, and never on internal/wafval or any other
// WAF-phase package. Every compliance claim this package can express
// carries an explicit VerificationStatus and a mandatory Note: this
// package's seed data (catalog.go) never asserts a specific regulatory
// clause, circular number, or rule number as fact -- only a framework
// name, general scope, and an honest account of what was and wasn't
// confirmed against a primary source. See the design spec's §2 for why:
// real research run before writing this package found no primary-source
// citation for the specific regulatory details it looked for.
package wafprofile

import "fmt"

// VerificationStatus names whether a ComplianceReference's framework
// claim has been confirmed against the regulator's or standard body's
// own primary text, or only against secondary sources (vendor blogs,
// compliance-consultancy pages).
type VerificationStatus string

const (
	Verified   VerificationStatus = "verified"
	Unverified VerificationStatus = "unverified"
)

func validVerificationStatus(s VerificationStatus) bool {
	switch s {
	case Verified, Unverified:
		return true
	default:
		return false
	}
}

// ComplianceReference is one compliance/regulatory framework that makes
// a Profile's attack vectors relevant to the industry or region it
// describes. Note is mandatory regardless of VerificationStatus: it
// states what is, and is not, being asserted about the framework.
type ComplianceReference struct {
	Framework          string
	VerificationStatus VerificationStatus
	Note               string
	SourceURL          string
}

// NewComplianceReference validates at construction time, never at
// render time. SourceURL is optional -- not every framework reference
// has one canonical URL -- so an empty string is accepted.
func NewComplianceReference(framework string, status VerificationStatus, note string, sourceURL string) (ComplianceReference, error) {
	if framework == "" {
		return ComplianceReference{}, fmt.Errorf("framework must not be empty")
	}
	if !validVerificationStatus(status) {
		return ComplianceReference{}, fmt.Errorf("status %q is not one of the known VerificationStatus constants", status)
	}
	if note == "" {
		return ComplianceReference{}, fmt.Errorf("note must not be empty")
	}
	return ComplianceReference{Framework: framework, VerificationStatus: status, Note: note, SourceURL: sourceURL}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/wafprofile/... -v`
Expected: PASS — all 6 test functions pass.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafprofile/compliance.go orchestrator/internal/wafprofile/compliance_test.go
git commit -m "feat(wafprofile): ComplianceReference type with mandatory verification status"
```

---

### Task 2: Profile type and catalog cross-reference

**Files:**
- Create: `orchestrator/internal/wafprofile/profile.go`
- Test: `orchestrator/internal/wafprofile/profile_test.go`

**Interfaces:**
- Consumes: `ComplianceReference`, `NewComplianceReference`, `Verified`, `Unverified` (Task 1); `wafcatalog.AttackVector{ID, ...}` (already merged, `internal/wafcatalog`).
- Produces: `ProfileKind` (+ 2 constants: `ProfileIndustry`, `ProfileRegional`), `Profile{ID, Name string, Kind ProfileKind, AttackVectorIDs []string, ComplianceReferences []ComplianceReference, Rationale, Provenance string}`, `NewProfile(id string, name string, kind ProfileKind, attackVectorIDs []string, complianceReferences []ComplianceReference, rationale string, provenance string) (Profile, error)`, `ValidateAgainstCatalog(profile Profile, catalog []wafcatalog.AttackVector) error`.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/wafprofile/profile_test.go
package wafprofile

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/wafcatalog"
)

func mustComplianceRef(t *testing.T) ComplianceReference {
	t.Helper()
	c, err := NewComplianceReference("x", Unverified, "y", "")
	if err != nil {
		t.Fatalf("NewComplianceReference: %v", err)
	}
	return c
}

func TestNewProfile_Valid_Succeeds(t *testing.T) {
	p, err := NewProfile("WAFPROFILE-BFSI", "Banking, Financial Services and Insurance", ProfileIndustry,
		[]string{"SQLI-001", "AUTH-001"}, []ComplianceReference{mustComplianceRef(t)}, "rationale text", "provenance text")
	if err != nil {
		t.Fatalf("NewProfile: %v", err)
	}
	if p.ID != "WAFPROFILE-BFSI" {
		t.Errorf("ID = %q, want %q", p.ID, "WAFPROFILE-BFSI")
	}
}

func TestNewProfile_EmptyID_Rejected(t *testing.T) {
	_, err := NewProfile("", "x", ProfileIndustry, []string{"SQLI-001"}, []ComplianceReference{mustComplianceRef(t)}, "r", "p")
	if err == nil {
		t.Fatal("want error for empty id, got nil")
	}
}

func TestNewProfile_EmptyName_Rejected(t *testing.T) {
	_, err := NewProfile("WAFPROFILE-BFSI", "", ProfileIndustry, []string{"SQLI-001"}, []ComplianceReference{mustComplianceRef(t)}, "r", "p")
	if err == nil {
		t.Fatal("want error for empty name, got nil")
	}
}

func TestNewProfile_InvalidKind_Rejected(t *testing.T) {
	_, err := NewProfile("WAFPROFILE-BFSI", "x", ProfileKind("bogus_kind"), []string{"SQLI-001"}, []ComplianceReference{mustComplianceRef(t)}, "r", "p")
	if err == nil {
		t.Fatal("want error for an unknown ProfileKind, got nil")
	}
}

func TestNewProfile_EmptyAttackVectorIDs_Rejected(t *testing.T) {
	_, err := NewProfile("WAFPROFILE-BFSI", "x", ProfileIndustry, []string{}, []ComplianceReference{mustComplianceRef(t)}, "r", "p")
	if err == nil {
		t.Fatal("want error for empty attackVectorIDs, got nil")
	}
}

// Review Focus: a duplicate ID must be detected, not just an empty slice.
func TestNewProfile_DuplicateAttackVectorID_Rejected(t *testing.T) {
	_, err := NewProfile("WAFPROFILE-BFSI", "x", ProfileIndustry, []string{"SQLI-001", "SQLI-001"}, []ComplianceReference{mustComplianceRef(t)}, "r", "p")
	if err == nil {
		t.Fatal("want error for a duplicate attackVectorIDs entry, got nil")
	}
}

func TestNewProfile_EmptyComplianceReferences_Rejected(t *testing.T) {
	_, err := NewProfile("WAFPROFILE-BFSI", "x", ProfileIndustry, []string{"SQLI-001"}, []ComplianceReference{}, "r", "p")
	if err == nil {
		t.Fatal("want error for empty complianceReferences, got nil")
	}
}

// Review Focus: a struct-literal ComplianceReference with an empty
// Framework must be caught, not just an empty slice -- the validation
// must inspect field values, not just len().
func TestNewProfile_ComplianceReferenceWithEmptyFramework_Rejected(t *testing.T) {
	bad := ComplianceReference{Framework: "", VerificationStatus: Unverified, Note: "y"}
	_, err := NewProfile("WAFPROFILE-BFSI", "x", ProfileIndustry, []string{"SQLI-001"}, []ComplianceReference{bad}, "r", "p")
	if err == nil {
		t.Fatal("want error for a complianceReferences entry with an empty Framework, got nil")
	}
}

func TestNewProfile_ComplianceReferenceWithEmptyNote_Rejected(t *testing.T) {
	bad := ComplianceReference{Framework: "x", VerificationStatus: Unverified, Note: ""}
	_, err := NewProfile("WAFPROFILE-BFSI", "x", ProfileIndustry, []string{"SQLI-001"}, []ComplianceReference{bad}, "r", "p")
	if err == nil {
		t.Fatal("want error for a complianceReferences entry with an empty Note, got nil")
	}
}

func TestNewProfile_EmptyRationale_Rejected(t *testing.T) {
	_, err := NewProfile("WAFPROFILE-BFSI", "x", ProfileIndustry, []string{"SQLI-001"}, []ComplianceReference{mustComplianceRef(t)}, "", "p")
	if err == nil {
		t.Fatal("want error for empty rationale, got nil")
	}
}

func TestNewProfile_EmptyProvenance_Rejected(t *testing.T) {
	_, err := NewProfile("WAFPROFILE-BFSI", "x", ProfileIndustry, []string{"SQLI-001"}, []ComplianceReference{mustComplianceRef(t)}, "r", "")
	if err == nil {
		t.Fatal("want error for empty provenance, got nil")
	}
}

func mustProfile(t *testing.T, ids []string) Profile {
	t.Helper()
	p, err := NewProfile("WAFPROFILE-BFSI", "x", ProfileIndustry, ids, []ComplianceReference{mustComplianceRef(t)}, "r", "p")
	if err != nil {
		t.Fatalf("NewProfile: %v", err)
	}
	return p
}

func TestValidateAgainstCatalog_AllPresent_ReturnsNil(t *testing.T) {
	profile := mustProfile(t, []string{"SQLI-001", "XSS-001"})
	catalog := []wafcatalog.AttackVector{{ID: "SQLI-001"}, {ID: "XSS-001"}, {ID: "AUTH-001"}}
	if err := ValidateAgainstCatalog(profile, catalog); err != nil {
		t.Fatalf("ValidateAgainstCatalog: %v", err)
	}
}

// Review Focus: the error must name the specific missing ID.
func TestValidateAgainstCatalog_MissingID_ReturnsErrorNamingIt(t *testing.T) {
	profile := mustProfile(t, []string{"SQLI-001", "NOTAREALID-999"})
	catalog := []wafcatalog.AttackVector{{ID: "SQLI-001"}}
	err := ValidateAgainstCatalog(profile, catalog)
	if err == nil {
		t.Fatal("want error for a missing attack-vector ID, got nil")
	}
	if !strings.Contains(err.Error(), "NOTAREALID-999") {
		t.Errorf("error = %q, want it to name the missing ID %q", err.Error(), "NOTAREALID-999")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/wafprofile/... -v`
Expected: FAIL — `ProfileIndustry`/`Profile`/`NewProfile`/`ValidateAgainstCatalog` undefined.

- [ ] **Step 3: Write `profile.go`**

```go
// orchestrator/internal/wafprofile/profile.go
package wafprofile

import (
	"fmt"

	"github.com/audspect/bas/internal/wafcatalog"
)

// ProfileKind distinguishes an industry profile from a regional one.
type ProfileKind string

const (
	ProfileIndustry ProfileKind = "industry"
	ProfileRegional ProfileKind = "regional"
)

func validProfileKind(k ProfileKind) bool {
	switch k {
	case ProfileIndustry, ProfileRegional:
		return true
	default:
		return false
	}
}

// Profile bundles a subset of wafcatalog's real attack-vector IDs with
// the compliance frameworks that make them relevant to a named industry
// or region. It evaluates nothing itself -- it is a reference layer.
type Profile struct {
	ID                   string
	Name                 string
	Kind                 ProfileKind
	AttackVectorIDs      []string
	ComplianceReferences []ComplianceReference
	Rationale            string
	Provenance           string
}

// NewProfile validates at construction time, never at render time. It
// re-validates each ComplianceReferences entry's own fields rather than
// trusting the caller already went through NewComplianceReference --
// a struct literal can bypass that constructor entirely.
func NewProfile(id string, name string, kind ProfileKind, attackVectorIDs []string, complianceReferences []ComplianceReference, rationale string, provenance string) (Profile, error) {
	if id == "" {
		return Profile{}, fmt.Errorf("id must not be empty")
	}
	if name == "" {
		return Profile{}, fmt.Errorf("name must not be empty")
	}
	if !validProfileKind(kind) {
		return Profile{}, fmt.Errorf("kind %q is not one of the known ProfileKind constants", kind)
	}
	if len(attackVectorIDs) == 0 {
		return Profile{}, fmt.Errorf("attackVectorIDs must not be empty")
	}
	seen := make(map[string]bool, len(attackVectorIDs))
	for _, vectorID := range attackVectorIDs {
		if vectorID == "" {
			return Profile{}, fmt.Errorf("attackVectorIDs must not contain an empty ID")
		}
		if seen[vectorID] {
			return Profile{}, fmt.Errorf("attackVectorIDs contains a duplicate ID %q", vectorID)
		}
		seen[vectorID] = true
	}
	if len(complianceReferences) == 0 {
		return Profile{}, fmt.Errorf("complianceReferences must not be empty")
	}
	for _, ref := range complianceReferences {
		if ref.Framework == "" {
			return Profile{}, fmt.Errorf("a complianceReferences entry has an empty Framework")
		}
		if !validVerificationStatus(ref.VerificationStatus) {
			return Profile{}, fmt.Errorf("a complianceReferences entry has status %q, not one of the known VerificationStatus constants", ref.VerificationStatus)
		}
		if ref.Note == "" {
			return Profile{}, fmt.Errorf("a complianceReferences entry has an empty Note")
		}
	}
	if rationale == "" {
		return Profile{}, fmt.Errorf("rationale must not be empty")
	}
	if provenance == "" {
		return Profile{}, fmt.Errorf("provenance must not be empty")
	}
	return Profile{ID: id, Name: name, Kind: kind, AttackVectorIDs: attackVectorIDs, ComplianceReferences: complianceReferences, Rationale: rationale, Provenance: provenance}, nil
}

// ValidateAgainstCatalog confirms every one of profile's AttackVectorIDs
// actually exists in catalog, returning an error naming the first one
// that does not -- catching a typo'd or since-removed vector ID.
func ValidateAgainstCatalog(profile Profile, catalog []wafcatalog.AttackVector) error {
	known := make(map[string]bool, len(catalog))
	for _, vector := range catalog {
		known[vector.ID] = true
	}
	for _, vectorID := range profile.AttackVectorIDs {
		if !known[vectorID] {
			return fmt.Errorf("profile %q references attack-vector ID %q, which does not exist in the given catalog", profile.ID, vectorID)
		}
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/wafprofile/... -v`
Expected: PASS — every test in the package so far passes.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafprofile/profile.go orchestrator/internal/wafprofile/profile_test.go
git commit -m "feat(wafprofile): Profile type and catalog cross-reference"
```

---

### Task 3: Seed catalog

**Files:**
- Create: `orchestrator/internal/wafprofile/catalog.go`
- Test: `orchestrator/internal/wafprofile/catalog_test.go`

**Interfaces:**
- Consumes: `NewComplianceReference`, `Unverified` (Task 1); `ProfileIndustry`, `ProfileRegional`, `NewProfile`, `ValidateAgainstCatalog` (Task 2); `wafcatalog.AudspectWAFAttackCatalog() ([]wafcatalog.AttackVector, error)` (already merged, `internal/wafcatalog`).
- Produces: `AudspectWAFProfileCatalog() ([]Profile, error)`.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/wafprofile/catalog_test.go
package wafprofile

import (
	"testing"

	"github.com/audspect/bas/internal/wafcatalog"
)

func TestAudspectWAFProfileCatalog_ReturnsSixProfiles(t *testing.T) {
	profiles, err := AudspectWAFProfileCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFProfileCatalog: %v", err)
	}
	if len(profiles) != 6 {
		t.Fatalf("len(profiles) = %d, want 6", len(profiles))
	}
	var industry, regional int
	for _, p := range profiles {
		switch p.Kind {
		case ProfileIndustry:
			industry++
		case ProfileRegional:
			regional++
		}
	}
	if industry != 4 {
		t.Errorf("industry profiles = %d, want 4", industry)
	}
	if regional != 2 {
		t.Errorf("regional profiles = %d, want 2", regional)
	}
}

// Review Focus: validate against the REAL wafcatalog output, not a
// fixture -- this test would catch a genuine drift between this
// phase's seed data and the real upstream catalog.
func TestAudspectWAFProfileCatalog_EachProfileValidatesAgainstRealCatalog(t *testing.T) {
	profiles, err := AudspectWAFProfileCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFProfileCatalog: %v", err)
	}
	realCatalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		t.Fatalf("wafcatalog.AudspectWAFAttackCatalog: %v", err)
	}
	for _, p := range profiles {
		if err := ValidateAgainstCatalog(p, realCatalog); err != nil {
			t.Errorf("profile %q failed ValidateAgainstCatalog against the real catalog: %v", p.ID, err)
		}
	}
}

func TestAudspectWAFProfileCatalog_EveryComplianceReferenceIsUnverifiedWithANote(t *testing.T) {
	profiles, err := AudspectWAFProfileCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFProfileCatalog: %v", err)
	}
	for _, p := range profiles {
		for _, ref := range p.ComplianceReferences {
			if ref.VerificationStatus != Unverified {
				t.Errorf("profile %q reference %q has status %q, want %q", p.ID, ref.Framework, ref.VerificationStatus, Unverified)
			}
			if ref.Note == "" {
				t.Errorf("profile %q reference %q has an empty Note", p.ID, ref.Framework)
			}
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/wafprofile/... -run TestAudspectWAFProfileCatalog -v`
Expected: FAIL — `AudspectWAFProfileCatalog` undefined.

- [ ] **Step 3: Write `catalog.go`**

```go
// orchestrator/internal/wafprofile/catalog.go
package wafprofile

import (
	"fmt"

	"github.com/audspect/bas/internal/wafcatalog"
)

// AudspectWAFProfileCatalog returns Audspect's real, current seed
// industry-and-regional-profile set: the 6 named profiles from waf.txt
// Phase 9, each validated against the real, live wafcatalog output.
func AudspectWAFProfileCatalog() ([]Profile, error) {
	realCatalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	rbiBanks, err := NewComplianceReference("RBI Cyber Security Framework for banks", Unverified,
		"framework name and general existence only, drawn from secondary/vendor sources in this session's research; no specific circular number or clause verified against RBI's own text", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	pciDSS, err := NewComplianceReference("PCI-DSS", Unverified,
		"framework name only; payment-card-data scope not independently verified in this session", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	bfsi, err := NewProfile("WAFPROFILE-BFSI", "Banking, Financial Services and Insurance", ProfileIndustry,
		[]string{"SQLI-001", "AUTH-001", "AUTH-003", "API-001", "RATE-001"},
		[]ComplianceReference{rbiBanks, pciDSS},
		"BFSI internet-facing apps concentrate on authenticated payment/account flows and APIs, where SQL injection, auth-bypass/credential and broken-object-level-authorization patterns, and burst-rate abuse are the highest-severity vectors already in wafcatalog",
		"manually authored from waf.txt Phase 9's named BFSI item")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	rbiNBFC, err := NewComplianceReference("RBI IT Governance requirements for NBFCs", Unverified,
		"framework name and general applicability (asset-threshold-gated) only, from secondary sources; no specific circular number verified against RBI's own text", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	nbfc, err := NewProfile("WAFPROFILE-NBFC", "Non-Banking Financial Companies", ProfileIndustry,
		[]string{"API-002", "AUTH-001", "SQLI-002", "FILEUP-001"},
		[]ComplianceReference{rbiNBFC},
		"many NBFCs run digital-lending apps with undocumented-field mass-assignment risk, credential-stuffing-exposed logins, blind SQL injection in form flows, and loan-document upload endpoints",
		"manually authored from waf.txt Phase 9's named NBFC item")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	certIn, err := NewComplianceReference("CERT-In Cyber Security Directions", Unverified,
		"framework name and the widely-reported 6-hour incident-reporting requirement only; this session's research found no manufacturing-specific or WAF-specific clause, and that gap is disclosed rather than filled in", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	manufacturing, err := NewProfile("WAFPROFILE-MANUFACTURING", "Manufacturing and OT-adjacent critical infrastructure", ProfileIndustry,
		[]string{"SSRF-002", "PATHTRAV-001", "HTTPPARSE-001"},
		[]ComplianceReference{certIn},
		"manufacturing/OT-adjacent management interfaces are exposed to cloud-metadata SSRF, directory traversal, and request-smuggling against legacy HTTP parsers",
		"manually authored from waf.txt Phase 9's named manufacturing item")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	dpdpHealth, err := NewComplianceReference("India DPDP Act 2023 (+ Rules)", Unverified,
		"framework name and general existence of technical-safeguard rules only; specific rule numbers and retention periods surfaced by research are not asserted here, pending primary-source confirmation", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	abdm, err := NewComplianceReference("Ayushman Bharat Digital Mission (ABDM)", Unverified,
		"framework name only; specific technical-specification clauses not verified", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	healthcare, err := NewProfile("WAFPROFILE-HEALTHCARE", "Healthcare", ProfileIndustry,
		[]string{"AUTH-002", "API-003", "CACHE-001", "SQLI-003"},
		[]ComplianceReference{dpdpHealth, abdm},
		"healthcare apps expose patient-record account enumeration, verbose API data exposure, cache-poisoning leakage of cached PHI responses, and error-based SQL injection against record-ID parameters",
		"manually authored from waf.txt Phase 9's named healthcare item")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	dpdpIndia, err := NewComplianceReference("India DPDP Act 2023", Unverified,
		"nationwide applicability asserted at the framework-name level only", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	certInIndia, err := NewComplianceReference("CERT-In Cyber Security Directions", Unverified,
		"nationwide incident-reporting framework, name-level only", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	india, err := NewProfile("WAFPROFILE-INDIA", "India (cross-industry baseline)", ProfileRegional,
		[]string{"SQLI-001", "XSS-001", "AUTH-001", "RATE-002"},
		[]ComplianceReference{dpdpIndia, certInIndia},
		"a cross-industry baseline of the highest-severity, most-common vectors applicable regardless of sector for India-based deployments",
		"manually authored from waf.txt Phase 9's named India item")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	uaeIAS, err := NewComplianceReference("UAE Information Assurance Standards (NESA-origin)", Unverified,
		"framework name only; this session's research found disagreement across sources on the current overseeing authority's name, which is disclosed here rather than resolved by picking one", "")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}
	uae, err := NewProfile("WAFPROFILE-UAE", "United Arab Emirates (cross-industry baseline)", ProfileRegional,
		[]string{"SQLI-002", "XSS-002", "SSRF-001", "API-002"},
		[]ComplianceReference{uaeIAS},
		"a cross-industry baseline of blind SQL injection, stored XSS, webhook-callback SSRF, and mass-assignment API abuse applicable regardless of sector for UAE-based deployments",
		"manually authored from waf.txt Phase 9's named UAE item")
	if err != nil {
		return nil, fmt.Errorf("loading seed profile catalog: %w", err)
	}

	profiles := []Profile{bfsi, nbfc, manufacturing, healthcare, india, uae}
	for _, p := range profiles {
		if err := ValidateAgainstCatalog(p, realCatalog); err != nil {
			return nil, fmt.Errorf("loading seed profile catalog: %w", err)
		}
	}
	return profiles, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/wafprofile/... -v`
Expected: PASS — every test in the package passes.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafprofile/catalog.go orchestrator/internal/wafprofile/catalog_test.go
git commit -m "feat(wafprofile): AudspectWAFProfileCatalog seeding all 6 named profiles"
```
