# dlpprofile Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `internal/dlpprofile`, a new Go package that maps India/UAE industry and regional profiles onto Audspect's real, existing DLP scenario coverage, with an honest `Verified`/`Unverified` compliance flag and a structural guarantee that no profile can reference a scenario that doesn't exist.

**Architecture:** A direct structural clone of `internal/avprofile` (and `internal/wafprofile`, the second real instance of this pattern): `Profile` + `ComplianceReference` + `ControlObjectiveCoverage` value types, all validated at construction time, plus one seed-catalog function (`AudspectDLPProfileCatalog`) that builds and self-validates 7 profiles. The one structural difference from `avprofile`: there is no `dlpcatalog` package to validate `VectorIDs` against, so this package defines its own ground-truth list of real scenario IDs (`RealDLPScenarioIDs`) and `ValidateAgainstCatalog` takes that `[]string` directly instead of `[]avcatalog.Vector`.

**Tech Stack:** Go (standard library only — `fmt`, `testing`). No new dependencies.

**Spec:** `orchestrator/docs/superpowers/specs/2026-10-16-dlpprofile-design.md`

## Global Constraints

- Package lives at `orchestrator/internal/dlpprofile`, new files only — **no existing file outside this package is modified.**
- No `dlpcatalog`, `dlpsim`, `dlpvendor`, `dlpevidence`, `dlpefficacy`, `dlpcorrelate`, or `dlpreport` package is created. This is `dlpprofile` only.
- No profile may reference `dlp-exfiltration-multichannel` in `VectorIDs` (its own description overclaims — see spec) — `VectorIDs` entries must come only from the other 9 real scenario IDs.
- Every `ComplianceReference` has `VerificationStatus: Unverified` and a mandatory, non-empty `Note` — never a claim verified against a primary regulatory source.
- Nothing in this package may describe any scenario as "vendor-validated" — today's ground truth for every DLP scenario is the sink-receipt/local-marker model, never a real vendor API.
- Industry grouping follows `dlp.txt` §4's own 5 headings exactly (not AV's 6-way split): BFSI+NBFCs combined, Healthcare, Manufacturing, Government+Legal+HR combined, IT/SaaS/BPO/Telecom combined. Plus 2 regional baselines: India, UAE.
- BFSI/NBFC and India profiles get a flat `VectorIDs`-only shape (no `ControlObjectives`) because their real payload (PAN/Aadhaar/SWIFT/UPI/credit-card) is the one every scenario actually tests. BFSI's `ComplianceReferences` cite only India-specific frameworks (RBI/SEBI/DPDP) — **not** UAE Central Bank, since BFSI's payload has no UAE-shaped data to back a UAE compliance claim; the UAE angle on BFSI is instead folded into the UAE regional profile's own gap note.
- Healthcare, Manufacturing, Government, IT/SaaS, and UAE each get flat channel-level `VectorIDs` (channel delivery mechanics are industry-agnostic) **plus exactly one** `ControlObjectiveCoverage` entry, `Status: Gap`, naming the sector/region-specific sensitive-data-type fidelity gap (e.g. Healthcare's gap names patient/clinical-record data; UAE's gap names Emirates ID/IBAN formats) — never a disguised `Covered` entry for something no scenario payload actually tests.

## Review Focus

- A profile that silently claims coverage of a scenario ID that never existed or was renamed — covered by `ValidateAgainstCatalog`'s rejection test in Task 4/5.
- A profile that smuggles `dlp-exfiltration-multichannel` into `VectorIDs` as if it proved "full channel coverage," when that scenario is missing 4 of the 9 real channels — explicit test in Task 5.
- A `ComplianceReference` marked `Verified` or left with an empty `Note`, silently overclaiming regulatory confirmation — explicit catalog-wide test in Task 5 (mirrors `avprofile`'s own regression test for this).
- BFSI or India (the two profiles whose real payload matches) incorrectly carrying a payload-fidelity `Gap`, which would be a false negative understating real coverage — explicit test in Task 5.
- Healthcare/Manufacturing/Government/IT-SaaS/UAE incorrectly carrying **no** payload-fidelity gap (silently overclaiming industry-specific coverage DLP never tested) — explicit test in Task 5, the direct regression test for the builder-check finding this plan exists to fix.

---

### Task 1: Real scenario ID ground truth

**Files:**
- Create: `orchestrator/internal/dlpprofile/scenarios.go`
- Test: `orchestrator/internal/dlpprofile/scenarios_test.go`

**Interfaces:**
- Produces: `RealDLPScenarioIDs() []string` — used by every later task as the validation ground truth.

- [ ] **Step 1: Write the failing test**

```go
func TestRealDLPScenarioIDs_ReturnsExactlyTheTenRealIDs(t *testing.T) {
	ids := RealDLPScenarioIDs()
	want := []string{
		"dlp-exfiltration-validation",
		"dlp-exfiltration-sink-https",
		"dlp-exfiltration-dns-tunnel",
		"dlp-exfiltration-sftp",
		"dlp-exfiltration-smtp",
		"dlp-exfiltration-cloud-storage",
		"dlp-exfiltration-webhook",
		"dlp-exfiltration-coderepo",
		"dlp-exfiltration-telnet",
		"dlp-exfiltration-multichannel",
	}
	if len(ids) != len(want) {
		t.Fatalf("len(ids) = %d, want %d", len(ids), len(want))
	}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		seen[id] = true
	}
	for _, w := range want {
		if !seen[w] {
			t.Errorf("missing expected scenario ID %q", w)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/dlpprofile/... -run TestRealDLPScenarioIDs -v` (from `orchestrator/`)
Expected: FAIL — `RealDLPScenarioIDs` undefined

- [ ] **Step 3: Implement `RealDLPScenarioIDs() []string` in `scenarios.go`**

Package doc comment on this file: this is the ground truth for what scenario IDs actually exist under `scenarios/dlp-*.yaml` today (confirmed via `grep ^id: scenarios/dlp-*.yaml`, 2026-10-16/17) — not a `dlpcatalog` package, deliberately out of scope (see spec Non-goals). Returns the exact 10 IDs listed in the test above, as a literal slice.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/dlpprofile/... -run TestRealDLPScenarioIDs -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/dlpprofile/scenarios.go orchestrator/internal/dlpprofile/scenarios_test.go
git commit -m "feat(dlpprofile): add real DLP scenario ID ground truth"
```

---

### Task 2: Compliance reference type

**Files:**
- Create: `orchestrator/internal/dlpprofile/compliance.go`
- Test: `orchestrator/internal/dlpprofile/compliance_test.go`

**Interfaces:**
- Produces: `VerificationStatus` (`Verified`, `Unverified` consts), `ComplianceReference{Framework, VerificationStatus, Note, SourceURL string}`, `NewComplianceReference(framework string, status VerificationStatus, note string, sourceURL string) (ComplianceReference, error)`.

This is a verbatim structural clone of `orchestrator/internal/avprofile/compliance.go` (already read in full) with only the package name changed from `avprofile` to `dlpprofile` and the file-level doc comment adapted to name `dlp.txt` §4 instead of `av.txt` §3.

- [ ] **Step 1: Write the failing tests** (clone `avprofile/compliance_test.go`'s 5 test cases verbatim, package `dlpprofile`): `TestNewComplianceReference_Valid_Succeeds`, `TestNewComplianceReference_EmptySourceURL_Succeeds`, `TestNewComplianceReference_EmptyFramework_Rejected`, `TestNewComplianceReference_EmptyNote_Rejected`, `TestNewComplianceReference_InvalidStatus_Rejected`, `TestNewComplianceReference_VerifiedStatus_Succeeds`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/dlpprofile/... -run TestNewComplianceReference -v`
Expected: FAIL — `NewComplianceReference`/`ComplianceReference`/`Verified`/`Unverified` undefined

- [ ] **Step 3: Implement `compliance.go`** — identical body to `avprofile/compliance.go` lines 17-59 (the `VerificationStatus` type/consts/`validVerificationStatus`, `ComplianceReference` struct, `NewComplianceReference`), package `dlpprofile`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/dlpprofile/... -run TestNewComplianceReference -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/dlpprofile/compliance.go orchestrator/internal/dlpprofile/compliance_test.go
git commit -m "feat(dlpprofile): add ComplianceReference type"
```

---

### Task 3: Control objective coverage type

**Files:**
- Create: `orchestrator/internal/dlpprofile/objectives.go`
- Test: `orchestrator/internal/dlpprofile/objectives_test.go`

**Interfaces:**
- Consumes: nothing from Task 1/2.
- Produces: `CoverageStatus` (`CoverageStatusCovered`, `CoverageStatusGap` consts), `ControlObjectiveCoverage{Objective, VectorID, Rationale, RequiredEvidence string, Status CoverageStatus}`, `NewControlObjectiveCoverage(objective, vectorID, rationale, requiredEvidence string, status CoverageStatus) (ControlObjectiveCoverage, error)`, `ValidateControlObjectivesAgainstCatalog(objectives []ControlObjectiveCoverage, knownIDs map[string]bool) error` — used by Task 4's `ValidateAgainstCatalog`.

Verbatim structural clone of `orchestrator/internal/avprofile/objectives.go` (already read in full), package `dlpprofile`, no logic changes — this file is already catalog-agnostic (`knownIDs map[string]bool`), so nothing about the missing `dlpcatalog` package affects it.

- [ ] **Step 1: Write the failing tests** — clone `avprofile/objectives_test.go`'s cases verbatim (construction validation for both `Covered` requiring non-empty `VectorID`/`RequiredEvidence`, and `Gap` requiring both empty; invalid status rejection; `ValidateControlObjectivesAgainstCatalog` catching a stale `VectorID`).

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/dlpprofile/... -run TestNewControlObjectiveCoverage -v` and `-run TestValidateControlObjectivesAgainstCatalog -v`
Expected: FAIL — types undefined

- [ ] **Step 3: Implement `objectives.go`** — identical body to `avprofile/objectives.go` lines 5-85, package `dlpprofile`.

- [ ] **Step 4: Run tests to verify they pass**

Run: same commands as Step 2
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/dlpprofile/objectives.go orchestrator/internal/dlpprofile/objectives_test.go
git commit -m "feat(dlpprofile): add ControlObjectiveCoverage type"
```

---

### Task 4: Profile type and catalog-free validation

**Files:**
- Create: `orchestrator/internal/dlpprofile/profile.go`
- Test: `orchestrator/internal/dlpprofile/profile_test.go`

**Interfaces:**
- Consumes: `ComplianceReference`/`VerificationStatus`/`validVerificationStatus` (Task 2), `ControlObjectiveCoverage`/`ValidateControlObjectivesAgainstCatalog` (Task 3), `RealDLPScenarioIDs()` (Task 1, used only in this task's tests, not in the production code).
- Produces: `ProfileKind` (`ProfileIndustry`, `ProfileRegional` consts), `Profile{ID, Name string, Kind ProfileKind, VectorIDs []string, ComplianceReferences []ComplianceReference, Rationale, Provenance string, ControlObjectives []ControlObjectiveCoverage}`, `NewProfile(id, name string, kind ProfileKind, vectorIDs []string, complianceReferences []ComplianceReference, rationale, provenance string) (Profile, error)`, `WithControlObjectives(profile Profile, objectives []ControlObjectiveCoverage) (Profile, error)`, `ValidateAgainstCatalog(profile Profile, realScenarioIDs []string) error` — used by Task 5.

`NewProfile` and `WithControlObjectives` are identical in body to `avprofile/profile.go` lines 71-115 and 53-66 respectively (same field validation, same duplicate/empty checks). `ValidateAgainstCatalog`'s signature changes per the spec's resolution: second parameter is `realScenarioIDs []string`, not `catalog []avcatalog.Vector`, since there is no `dlpcatalog.Vector` type.

- [ ] **Step 1: Write the failing tests** — clone `avprofile/profile_test.go`'s construction-validation cases verbatim (empty ID/name/kind/vectorIDs/complianceReferences rejected, duplicate vectorIDs rejected, a bad struct-literal ComplianceReference with empty Framework/Note rejected, empty rationale/provenance rejected), plus:

```go
func TestValidateAgainstCatalog_RejectsUnknownScenarioID(t *testing.T) {
	ref, _ := NewComplianceReference("x", Unverified, "y", "")
	p, err := NewProfile("DLPPROFILE-TEST", "x", ProfileIndustry,
		[]string{"dlp-exfiltration-does-not-exist"}, []ComplianceReference{ref}, "r", "p")
	if err != nil {
		t.Fatalf("NewProfile: %v", err)
	}
	if err := ValidateAgainstCatalog(p, RealDLPScenarioIDs()); err == nil {
		t.Fatal("want error for a VectorIDs entry that is not a real scenario ID, got nil")
	}
}

func TestValidateAgainstCatalog_AcceptsRealScenarioID(t *testing.T) {
	ref, _ := NewComplianceReference("x", Unverified, "y", "")
	p, err := NewProfile("DLPPROFILE-TEST", "x", ProfileIndustry,
		[]string{"dlp-exfiltration-sftp"}, []ComplianceReference{ref}, "r", "p")
	if err != nil {
		t.Fatalf("NewProfile: %v", err)
	}
	if err := ValidateAgainstCatalog(p, RealDLPScenarioIDs()); err != nil {
		t.Errorf("ValidateAgainstCatalog: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/dlpprofile/... -run TestNewProfile -v` and `-run TestValidateAgainstCatalog -v`
Expected: FAIL — types/functions undefined

- [ ] **Step 3: Implement `profile.go`**

`ProfileKind`, `validProfileKind`, `Profile`, `NewProfile`, `WithControlObjectives`: identical bodies to `avprofile/profile.go`. `ValidateAgainstCatalog`:

```go
func ValidateAgainstCatalog(profile Profile, realScenarioIDs []string) error {
	known := make(map[string]bool, len(realScenarioIDs))
	for _, id := range realScenarioIDs {
		known[id] = true
	}
	for _, vectorID := range profile.VectorIDs {
		if !known[vectorID] {
			return fmt.Errorf("profile %q references scenario ID %q, which does not exist in the given real scenario ID list", profile.ID, vectorID)
		}
	}
	if err := ValidateControlObjectivesAgainstCatalog(profile.ControlObjectives, known); err != nil {
		return fmt.Errorf("profile %q: %w", profile.ID, err)
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: same commands as Step 2
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/dlpprofile/profile.go orchestrator/internal/dlpprofile/profile_test.go
git commit -m "feat(dlpprofile): add Profile type with catalog-free validation"
```

---

### Task 5: Seed profile catalog

**Files:**
- Create: `orchestrator/internal/dlpprofile/catalog.go`
- Test: `orchestrator/internal/dlpprofile/catalog_test.go`

**Interfaces:**
- Consumes: everything from Tasks 1-4 (`RealDLPScenarioIDs`, `NewComplianceReference`/`Unverified`, `NewControlObjectiveCoverage`/`CoverageStatusGap`/`WithControlObjectives`, `NewProfile`/`ProfileIndustry`/`ProfileRegional`/`ValidateAgainstCatalog`).
- Produces: `AudspectDLPProfileCatalog() ([]Profile, error)` — the package's public entry point; no later task consumes it (this is the last task), but any future console/reporting integration would.

Seven profiles, built with `NewProfile`/`NewComplianceReference`/`ValidateAgainstCatalog` exactly as `avprofile/catalog.go` demonstrates (read in full already), applying this plan's Global Constraints:

| Profile ID | Kind | `VectorIDs` (from `RealDLPScenarioIDs()`, never `dlp-exfiltration-multichannel`) | `ControlObjectives` |
|---|---|---|---|
| `DLPPROFILE-BFSI` | Industry | implementer's choice of real IDs matching BFSI's named channels in `dlp.txt` §4 (e.g. cloud-storage, webhook, sftp, smtp) | none (flat) |
| `DLPPROFILE-HEALTHCARE` | Industry | same real IDs, industry-appropriate subset | exactly 1 entry, `Gap`, naming patient/clinical-record data-type fidelity as untested |
| `DLPPROFILE-MANUFACTURING` | Industry | industry-appropriate subset (e.g. coderepo, cloud-storage, sftp) | exactly 1 entry, `Gap`, naming CAD/engineering-design/source-code data-type fidelity as untested |
| `DLPPROFILE-GOVERNMENT` | Industry | industry-appropriate subset | exactly 1 entry, `Gap`, naming citizen-record/case-file/legal-privilege data-type fidelity as untested |
| `DLPPROFILE-ITSAAS` | Industry | industry-appropriate subset (e.g. coderepo, webhook, cloud-storage) | exactly 1 entry, `Gap`, naming source-code/API-credential-specific data-type fidelity as untested (the coderepo *channel* is covered; its payload still isn't source-code-shaped — see spec) |
| `DLPPROFILE-INDIA` | Regional | a representative subset of real IDs (all 9 standalone scenarios' payload is India-shaped) | none (flat) |
| `DLPPROFILE-UAE` | Regional | same channel-level subset as India (channels are region-agnostic) | exactly 1 entry, `Gap`, naming UAE-specific identifier-format (Emirates ID, IBAN) fidelity as untested |

`ComplianceReferences`: every entry `Unverified` with a non-empty `Note`, following `dlp.txt` §4's own named frameworks per industry (RBI/SEBI/India-DPDP for BFSI — **not** UAE Central Bank, per Global Constraints; India/UAE health-data rules for Healthcare; CERT-In for Manufacturing; best-effort baseline, disclosed as such, for Government and IT/SaaS where `dlp.txt` names no specific framework, mirroring how `avprofile/catalog.go`'s `nistGov` disclosed the same gap for AV's Government profile).

Each profile is validated via `ValidateAgainstCatalog(p, RealDLPScenarioIDs())` in a loop before `AudspectDLPProfileCatalog` returns, exactly as `avprofile/catalog.go` lines 133-138 do.

- [ ] **Step 1: Write the failing tests**

```go
func TestAudspectDLPProfileCatalog_ReturnsSevenProfiles(t *testing.T) {
	profiles, err := AudspectDLPProfileCatalog()
	if err != nil {
		t.Fatalf("AudspectDLPProfileCatalog: %v", err)
	}
	if len(profiles) != 7 {
		t.Fatalf("len(profiles) = %d, want 7", len(profiles))
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
	if industry != 5 {
		t.Errorf("industry profiles = %d, want 5", industry)
	}
	if regional != 2 {
		t.Errorf("regional profiles = %d, want 2", regional)
	}
}

func TestAudspectDLPProfileCatalog_EachProfileValidatesAgainstRealScenarioIDs(t *testing.T) {
	profiles, err := AudspectDLPProfileCatalog()
	if err != nil {
		t.Fatalf("AudspectDLPProfileCatalog: %v", err)
	}
	for _, p := range profiles {
		if err := ValidateAgainstCatalog(p, RealDLPScenarioIDs()); err != nil {
			t.Errorf("profile %q failed ValidateAgainstCatalog: %v", p.ID, err)
		}
	}
}

func TestAudspectDLPProfileCatalog_EveryComplianceReferenceIsUnverifiedWithANote(t *testing.T) {
	profiles, err := AudspectDLPProfileCatalog()
	if err != nil {
		t.Fatalf("AudspectDLPProfileCatalog: %v", err)
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

// Review Focus: no profile may cite the stale dlp-exfiltration-multichannel
// scenario as evidence of coverage (see spec: it's missing 4 of 9 real
// channels despite its own description claiming full coverage).
func TestAudspectDLPProfileCatalog_NoProfileCitesStaleMultichannelScenario(t *testing.T) {
	profiles, err := AudspectDLPProfileCatalog()
	if err != nil {
		t.Fatalf("AudspectDLPProfileCatalog: %v", err)
	}
	for _, p := range profiles {
		for _, id := range p.VectorIDs {
			if id == "dlp-exfiltration-multichannel" {
				t.Errorf("profile %q cites dlp-exfiltration-multichannel, which is stale relative to its own description and must never be used as a coverage claim", p.ID)
			}
		}
	}
}

// Review Focus: BFSI and India are the two profiles whose real payload
// (PAN/Aadhaar/SWIFT/UPI/credit-card) matches what the scenarios actually
// test -- they must NOT carry a payload-fidelity gap, which would be a
// false-negative regression understating real coverage.
func TestAudspectDLPProfileCatalog_BFSIAndIndiaHaveNoControlObjectives(t *testing.T) {
	profiles, err := AudspectDLPProfileCatalog()
	if err != nil {
		t.Fatalf("AudspectDLPProfileCatalog: %v", err)
	}
	for _, id := range []string{"DLPPROFILE-BFSI", "DLPPROFILE-INDIA"} {
		found := false
		for _, p := range profiles {
			if p.ID == id {
				found = true
				if len(p.ControlObjectives) != 0 {
					t.Errorf("profile %q has %d ControlObjectives, want 0 -- its real payload matches what the scenarios test, so no payload-fidelity gap applies", id, len(p.ControlObjectives))
				}
			}
		}
		if !found {
			t.Errorf("profile %q not found in catalog", id)
		}
	}
}

// Review Focus: the direct regression test for the builder-check finding
// this plan exists to fix -- Healthcare/Manufacturing/Government/ITSAAS/UAE
// must each honestly record their payload-fidelity gap, never silently
// claim full coverage via a flat VectorIDs list alone.
func TestAudspectDLPProfileCatalog_NonBFSIProfilesRecordPayloadFidelityGap(t *testing.T) {
	profiles, err := AudspectDLPProfileCatalog()
	if err != nil {
		t.Fatalf("AudspectDLPProfileCatalog: %v", err)
	}
	for _, id := range []string{"DLPPROFILE-HEALTHCARE", "DLPPROFILE-MANUFACTURING", "DLPPROFILE-GOVERNMENT", "DLPPROFILE-ITSAAS", "DLPPROFILE-UAE"} {
		found := false
		for _, p := range profiles {
			if p.ID == id {
				found = true
				if len(p.ControlObjectives) != 1 {
					t.Errorf("profile %q has %d ControlObjectives, want exactly 1 payload-fidelity gap", id, len(p.ControlObjectives))
					continue
				}
				if p.ControlObjectives[0].Status != CoverageStatusGap {
					t.Errorf("profile %q ControlObjectives[0].Status = %v, want Gap", id, p.ControlObjectives[0].Status)
				}
			}
		}
		if !found {
			t.Errorf("profile %q not found in catalog", id)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/dlpprofile/... -v` (from `orchestrator/`)
Expected: FAIL — `AudspectDLPProfileCatalog` undefined

- [ ] **Step 3: Implement `catalog.go`**

`AudspectDLPProfileCatalog() ([]Profile, error)` building the 7 profiles per the table above, following `avprofile/catalog.go`'s exact construction pattern (sequential `NewComplianceReference`/`NewProfile`/`NewControlObjectiveCoverage`/`WithControlObjectives` calls, each error-wrapped and returned early; final loop calling `ValidateAgainstCatalog(p, RealDLPScenarioIDs())` on every profile before returning).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/dlpprofile/... -v`
Expected: PASS, all tests in the package

- [ ] **Step 5: Run the full package test suite one more time to confirm no regressions**

Run: `go test ./internal/dlpprofile/... -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/dlpprofile/catalog.go orchestrator/internal/dlpprofile/catalog_test.go
git commit -m "feat(dlpprofile): add seed India/UAE industry and regional profile catalog"
```

---

## Final verification

- [ ] Run `go build ./...` from `orchestrator/` — confirm the whole module still builds (Global Constraint: no existing file touched, so this should be a no-op check, not a real risk).
- [ ] Run `go test ./internal/dlpprofile/... -v` — confirm all tests across all 5 tasks pass together.
- [ ] Re-read `orchestrator/docs/superpowers/specs/2026-10-16-dlpprofile-design.md` once more and confirm every Goal is met: package shape ✓, seed catalog with 5 industries + India/UAE ✓, `ValidateAgainstCatalog` against real scenario IDs ✓, full test coverage mirroring `avprofile` ✓, no `dlpcatalog`/new scenario content/fixture/evidence-model/connector work introduced ✓.
