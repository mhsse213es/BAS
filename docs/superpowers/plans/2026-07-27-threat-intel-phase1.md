# Threat Intelligence Center Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire connector-generated intel scenarios (MISP/OpenCTI/OTX) to real detection profiles automatically (Detection Profile Inheritance), and ship a read-only "Technique Coverage" view showing, per ATT&CK technique, whether a simulation/detection profile/purple exercise/compliance mapping exists.

**Architecture:** Add `TechniqueIDs []string` to `DetectionProfile` (28 existing profile files get this field, derived from real existing scenario wiring). `internal/connector.Generator` builds a technique→profile index from loaded profiles and auto-attaches `detection_profiles:` when generating intel scenarios. A new `internal/coverage` package (pure computation, no new tables) joins four technique-ID membership sets — simulation, detection profile, purple exercise, compliance — into rows, exposed via `GET /api/coverage/matrix` and a new "Technique Coverage" UI tab.

**Tech Stack:** Go (`internal/scenario`, `internal/connector`, `internal/coverage`, `internal/api`), YAML content migration, vanilla JS/HTML (`wwwroot/index.html`).

## Global Constraints

- `TechniqueIDs` is additive metadata only — never changes `DetectionProfile` resolution, `extends` inheritance, or scoring.
- Detection Profile Inheritance is forward-only — no backfill of existing `scenarios/intel/*.yaml` files.
- Exact technique-ID match only (`T1562.001` never matches a profile declaring only `T1562`). Ambiguity (multiple profiles claiming one technique) is resolved by first-match-by-sorted-name, logged, never blocks generation.
- The new UI tab is named **"Technique Coverage"** (`data-tab="attack-coverage"`), not "ATT&CK Coverage [Matrix]" — the existing `data-tab="coverage"` panel already carries that exact title in `TAB_TITLES`.
- Response Playbook coverage is always `N/A` (`nil` in the `Row` struct) — no technique-level linkage exists in `internal/actions` today; never faked as `false`.
- `windows_credential_access` (the abstract base profile others `extends`) is excluded from the `technique_ids:` migration.
- All 28 modified profile files must be re-signed (`go run scripts/signer.go sign private_key.pem <path>`, run from `orchestrator/`) before they will load.

---

## Task 1: `DetectionProfile.TechniqueIDs` Schema + Content Migration

**Files:**
- Modify: `orchestrator/internal/scenario/detection.go:98-117` (`DetectionProfile` struct)
- Modify: 28 files under `scenarios/detection-profiles/*.yaml` (add `technique_ids:`)

**Interfaces:**
- Produces: `DetectionProfile.TechniqueIDs []string` — consumed by Task 2 (`buildTechniqueIndex`) and Task 4 (`BuildProfileIndex`).

- [ ] **Step 1: Add the `TechniqueIDs` field**

In `orchestrator/internal/scenario/detection.go`, replace the `DetectionProfile` struct (lines 98-117) with:

```go
// DetectionProfile is a reusable, versioned, behavioral bundle of expected
// detections loaded from scenarios/detection-profiles/*.yaml. Profiles are named
// by behavior (e.g. "windows_lsass_access"), not ATT&CK ID, because one behavior
// maps to several techniques and one technique yields different detections by
// implementation. A profile may extend one or more parent profiles.
type DetectionProfile struct {
	// Profile is the unique behavioral name referenced by steps.
	Profile string `yaml:"profile" json:"profile"`

	// Version increments when expectations change. Recorded on each run's report
	// so historical expectations never shift under a re-versioned profile.
	Version int `yaml:"version" json:"version"`

	// Extends names parent profiles whose expectations are inherited. A child
	// overrides an inherited expectation by re-declaring the same id. Cycles are
	// rejected at load time.
	Extends []string `yaml:"extends,omitempty" json:"extends,omitempty"`

	// Expected is this profile's own expectations (before inheritance merge).
	Expected []ExpectedDetection `yaml:"expected_detection" json:"expectedDetection"`

	// Source is set at load time from the file location; not persisted. Mirrors
	// Scenario.Source semantics ("builtin" content must be signature-verified).
	Source string `yaml:"-" json:"source,omitempty"`

	// TechniqueIDs lists the ATT&CK techniques this behavioral profile is
	// relevant to. Additive metadata only -- does not change resolution,
	// inheritance, or scoring. A many-to-many hint, consistent with this
	// struct's design philosophy above: one profile can cover several
	// techniques (e.g. windows_dlp_exfiltration spans 5 DLP channels), and
	// one technique can legitimately have several profiles for different
	// sub-behaviors (e.g. T1562.001 has windows_defender_tampering,
	// windows_security_process_termination, and
	// windows_vulnerable_driver_load -- three different implementations
	// of "impair defenses"). Consumed by connector.Generator (Detection
	// Profile Inheritance) and internal/coverage (Coverage Matrix).
	TechniqueIDs []string `yaml:"technique_ids,omitempty" json:"techniqueIds,omitempty"`
}
```

- [ ] **Step 2: Add `technique_ids:` to each of the 28 profile files**

Add a `technique_ids:` line immediately after each file's `version: 1` line. Exact values per file:

| File | Add |
|---|---|
| `windows_ad_discovery.yaml` | `technique_ids: [T1087.002]` |
| `windows_archive_staging.yaml` | `technique_ids: [T1560.001]` |
| `windows_asrep_roast.yaml` | `technique_ids: [T1558.004]` |
| `windows_backup_service_stop.yaml` | `technique_ids: [T1489]` |
| `windows_cloud_egress.yaml` | `technique_ids: [T1567.002]` |
| `windows_data_destruction.yaml` | `technique_ids: [T1485]` |
| `windows_defender_tampering.yaml` | `technique_ids: [T1562.001]` |
| `windows_dlp_exfiltration.yaml` | `technique_ids: [T1052, T1052.001, T1074.001, T1115, T1560.001]` |
| `windows_dns_c2.yaml` | `technique_ids: [T1071.004]` |
| `windows_encoded_powershell.yaml` | `technique_ids: [T1059.001]` |
| `windows_file_discovery.yaml` | `technique_ids: [T1083]` |
| `windows_kerberoast.yaml` | `technique_ids: [T1558.003]` |
| `windows_log_manipulation.yaml` | `technique_ids: [T1070.001]` |
| `windows_lolbin_download_cradle.yaml` | `technique_ids: [T1105]` |
| `windows_malicious_service.yaml` | `technique_ids: [T1543.003]` |
| `windows_netsh_portproxy.yaml` | `technique_ids: [T1090.001]` |
| `windows_network_share_discovery.yaml` | `technique_ids: [T1135]` |
| `windows_ransomware_encryption.yaml` | `technique_ids: [T1486]` |
| `windows_rdp_nla_posture.yaml` | `technique_ids: [T1021.001]` |
| `windows_runkey_persistence.yaml` | `technique_ids: [T1547.001]` |
| `windows_sam_theft.yaml` | `technique_ids: [T1003.002]` |
| `windows_schtask_persistence.yaml` | `technique_ids: [T1053.005]` |
| `windows_security_process_termination.yaml` | `technique_ids: [T1562.001]` |
| `windows_security_software_discovery.yaml` | `technique_ids: [T1518.001]` |
| `windows_smb_lateral_probe.yaml` | `technique_ids: [T1021.002]` |
| `windows_vss_inhibition.yaml` | `technique_ids: [T1490]` |
| `windows_vulnerable_driver_load.yaml` | `technique_ids: [T1562.001]` |
| `windows_webmail_egress.yaml` | `technique_ids: [T1567]` |

`windows_credential_access.yaml` is **not** modified (abstract base profile, never referenced directly by any scenario step).

Example for `windows_sam_theft.yaml` (before/after the `version:` line):
```yaml
profile: windows_sam_theft
version: 1
technique_ids: [T1003.002]
extends:
  - windows_credential_access
```

Example for `windows_dlp_exfiltration.yaml` (the multi-technique one):
```yaml
profile: windows_dlp_exfiltration
version: 1
technique_ids: [T1052, T1052.001, T1074.001, T1115, T1560.001]
expected_detection:
```

- [ ] **Step 3: Validate all 28 modified files parse as valid YAML with the new field**

```bash
python3 -c "
import yaml, glob
expected = {
  'windows_ad_discovery': ['T1087.002'],
  'windows_archive_staging': ['T1560.001'],
  'windows_asrep_roast': ['T1558.004'],
  'windows_backup_service_stop': ['T1489'],
  'windows_cloud_egress': ['T1567.002'],
  'windows_data_destruction': ['T1485'],
  'windows_defender_tampering': ['T1562.001'],
  'windows_dlp_exfiltration': ['T1052','T1052.001','T1074.001','T1115','T1560.001'],
  'windows_dns_c2': ['T1071.004'],
  'windows_encoded_powershell': ['T1059.001'],
  'windows_file_discovery': ['T1083'],
  'windows_kerberoast': ['T1558.003'],
  'windows_log_manipulation': ['T1070.001'],
  'windows_lolbin_download_cradle': ['T1105'],
  'windows_malicious_service': ['T1543.003'],
  'windows_netsh_portproxy': ['T1090.001'],
  'windows_network_share_discovery': ['T1135'],
  'windows_ransomware_encryption': ['T1486'],
  'windows_rdp_nla_posture': ['T1021.001'],
  'windows_runkey_persistence': ['T1547.001'],
  'windows_sam_theft': ['T1003.002'],
  'windows_schtask_persistence': ['T1053.005'],
  'windows_security_process_termination': ['T1562.001'],
  'windows_security_software_discovery': ['T1518.001'],
  'windows_smb_lateral_probe': ['T1021.002'],
  'windows_vss_inhibition': ['T1490'],
  'windows_vulnerable_driver_load': ['T1562.001'],
  'windows_webmail_egress': ['T1567'],
}
for name, want in expected.items():
    doc = yaml.safe_load(open(f'scenarios/detection-profiles/{name}.yaml'))
    got = doc.get('technique_ids')
    assert got == want, f'{name}: got {got}, want {want}'
    print(name, 'OK')
print('all 28 OK')
"
```
Expected: `<name> OK` × 28, then `all 28 OK`, no assertion errors.

- [ ] **Step 4: Re-sign all 28 modified files**

From `orchestrator/`:
```bash
for f in windows_ad_discovery windows_archive_staging windows_asrep_roast windows_backup_service_stop windows_cloud_egress windows_data_destruction windows_defender_tampering windows_dlp_exfiltration windows_dns_c2 windows_encoded_powershell windows_file_discovery windows_kerberoast windows_log_manipulation windows_lolbin_download_cradle windows_malicious_service windows_netsh_portproxy windows_network_share_discovery windows_ransomware_encryption windows_rdp_nla_posture windows_runkey_persistence windows_sam_theft windows_schtask_persistence windows_security_process_termination windows_security_software_discovery windows_smb_lateral_probe windows_vss_inhibition windows_vulnerable_driver_load windows_webmail_egress; do
  go run scripts/signer.go sign private_key.pem "../scenarios/detection-profiles/$f.yaml"
done
```
Expected: 28 `[+] Signed ...` lines, no errors.

- [ ] **Step 5: Confirm the scenario package still loads everything cleanly**

Run: `go test ./internal/scenario/... -v -count=1`
Expected: 100% PASS — this confirms `technique_ids:` doesn't break existing YAML parsing or profile loading/inheritance checks for any of the 28 modified files or any scenario that references them.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/scenario/detection.go scenarios/detection-profiles/*.yaml scenarios/detection-profiles/*.yaml.sig
git commit -m "feat(scenario): add TechniqueIDs to DetectionProfile, migrate 28 existing profiles"
git push
```

---

## Task 2: Technique Index + Profile Resolution

**Files:**
- Create: `orchestrator/internal/connector/technique_index.go`
- Test: `orchestrator/internal/connector/technique_index_test.go`

**Interfaces:**
- Consumes: `scenario.DetectionProfile.TechniqueIDs` (Task 1).
- Produces: `buildTechniqueIndex(profiles map[string]*scenario.DetectionProfile) map[string][]string` and `resolveProfile(idx map[string][]string, techID string) string` — both consumed by Task 3 (`Generator`).

- [ ] **Step 1: Write the failing tests**

```go
package connector

import (
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func TestBuildTechniqueIndex_SingleMatch(t *testing.T) {
	profiles := map[string]*scenario.DetectionProfile{
		"windows_sam_theft": {Profile: "windows_sam_theft", TechniqueIDs: []string{"T1003.002"}},
	}
	idx := buildTechniqueIndex(profiles)
	if got := idx["T1003.002"]; len(got) != 1 || got[0] != "windows_sam_theft" {
		t.Errorf("idx[T1003.002] = %v, want [windows_sam_theft]", got)
	}
}

func TestBuildTechniqueIndex_MultipleProfilesSameTechnique(t *testing.T) {
	profiles := map[string]*scenario.DetectionProfile{
		"windows_defender_tampering":           {Profile: "windows_defender_tampering", TechniqueIDs: []string{"T1562.001"}},
		"windows_security_process_termination": {Profile: "windows_security_process_termination", TechniqueIDs: []string{"T1562.001"}},
		"windows_vulnerable_driver_load":        {Profile: "windows_vulnerable_driver_load", TechniqueIDs: []string{"T1562.001"}},
	}
	idx := buildTechniqueIndex(profiles)
	want := []string{"windows_defender_tampering", "windows_security_process_termination", "windows_vulnerable_driver_load"}
	got := idx["T1562.001"]
	if len(got) != len(want) {
		t.Fatalf("idx[T1562.001] = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("idx[T1562.001][%d] = %q, want %q (sorted order)", i, got[i], want[i])
		}
	}
}

func TestBuildTechniqueIndex_ProfileWithNoTechniqueIDsContributesNothing(t *testing.T) {
	profiles := map[string]*scenario.DetectionProfile{
		"windows_credential_access": {Profile: "windows_credential_access"}, // abstract base, no TechniqueIDs
	}
	idx := buildTechniqueIndex(profiles)
	if len(idx) != 0 {
		t.Errorf("expected empty index for a profile with no TechniqueIDs, got %v", idx)
	}
}

func TestBuildTechniqueIndex_ProfileWithMultipleTechniqueIDs(t *testing.T) {
	profiles := map[string]*scenario.DetectionProfile{
		"windows_dlp_exfiltration": {Profile: "windows_dlp_exfiltration", TechniqueIDs: []string{"T1052", "T1052.001", "T1074.001", "T1115", "T1560.001"}},
	}
	idx := buildTechniqueIndex(profiles)
	for _, tid := range []string{"T1052", "T1052.001", "T1074.001", "T1115", "T1560.001"} {
		if got := idx[tid]; len(got) != 1 || got[0] != "windows_dlp_exfiltration" {
			t.Errorf("idx[%s] = %v, want [windows_dlp_exfiltration]", tid, got)
		}
	}
}

func TestResolveProfile_NoMatch(t *testing.T) {
	idx := map[string][]string{}
	if got := resolveProfile(idx, "T9999"); got != "" {
		t.Errorf("resolveProfile with no matches = %q, want empty string", got)
	}
}

func TestResolveProfile_ExactMatchOnly(t *testing.T) {
	idx := map[string][]string{"T1562.001": {"windows_defender_tampering"}}
	if got := resolveProfile(idx, "T1562"); got != "" {
		t.Errorf("resolveProfile(T1562) = %q, want empty string -- T1562 must not match a T1562.001-only entry", got)
	}
	if got := resolveProfile(idx, "T1562.001"); got != "windows_defender_tampering" {
		t.Errorf("resolveProfile(T1562.001) = %q, want windows_defender_tampering", got)
	}
}

func TestResolveProfile_CaseInsensitive(t *testing.T) {
	idx := map[string][]string{"T1003.002": {"windows_sam_theft"}}
	if got := resolveProfile(idx, "t1003.002"); got != "windows_sam_theft" {
		t.Errorf("resolveProfile(t1003.002) = %q, want windows_sam_theft (case-insensitive match)", got)
	}
}

func TestResolveProfile_MultipleMatchesFirstWins(t *testing.T) {
	idx := map[string][]string{"T1562.001": {"windows_defender_tampering", "windows_security_process_termination", "windows_vulnerable_driver_load"}}
	if got := resolveProfile(idx, "T1562.001"); got != "windows_defender_tampering" {
		t.Errorf("resolveProfile with 3 candidates = %q, want windows_defender_tampering (first by sorted name)", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/connector/... -run 'TestBuildTechniqueIndex|TestResolveProfile' -v`
Expected: FAIL — `buildTechniqueIndex`/`resolveProfile` undefined.

- [ ] **Step 3: Implement**

```go
package connector

import (
	"log"
	"sort"
	"strings"

	"github.com/audspect/bas/internal/scenario"
)

// buildTechniqueIndex maps each ATT&CK technique ID to the profile names
// that declare it via TechniqueIDs, sorted for deterministic first-match
// resolution. Profiles with no TechniqueIDs (e.g. abstract base profiles
// meant only to be extend-ed) contribute nothing.
func buildTechniqueIndex(profiles map[string]*scenario.DetectionProfile) map[string][]string {
	idx := make(map[string][]string)
	for name, p := range profiles {
		for _, tid := range p.TechniqueIDs {
			up := strings.ToUpper(tid)
			idx[up] = append(idx[up], name)
		}
	}
	for tid := range idx {
		sort.Strings(idx[tid])
	}
	return idx
}

// resolveProfile returns the profile name to attach for a technique, or ""
// if none match. Exact match only -- T1562.001 never matches a profile
// declaring only T1562. When multiple profiles claim the same technique,
// the first by sorted name wins and every candidate is logged, surfacing
// the conflict for a human to resolve rather than guessing silently.
func resolveProfile(idx map[string][]string, techID string) string {
	candidates := idx[strings.ToUpper(techID)]
	if len(candidates) == 0 {
		return ""
	}
	if len(candidates) > 1 {
		log.Printf("[connector/gen] technique %s matches multiple detection profiles %v -- attaching %q, review for consolidation", techID, candidates, candidates[0])
	}
	return candidates[0]
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/connector/... -run 'TestBuildTechniqueIndex|TestResolveProfile' -v`
Expected: PASS, all 7 tests.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/connector/technique_index.go orchestrator/internal/connector/technique_index_test.go
git commit -m "feat(connector): technique-to-profile index and resolution for Detection Profile Inheritance"
git push
```

---

## Task 3: Wire Generator to Attach Inherited Detection Profiles

**Files:**
- Modify: `orchestrator/internal/connector/generator.go`
- Modify: `orchestrator/internal/connector/generator_test.go` (fix 3 existing call sites + add new tests)
- Modify: `orchestrator/cmd/server/main.go:248`

**Interfaces:**
- Consumes: `buildTechniqueIndex`, `resolveProfile` (Task 2).
- Produces: `NewGenerator(scenariosDir string, sectors, regions []string, profiles map[string]*scenario.DetectionProfile) *Generator` (signature change — 4th parameter added).

- [ ] **Step 1: Update the 3 existing tests for the new `NewGenerator` signature**

In `orchestrator/internal/connector/generator_test.go`, each of the 3 existing calls passes `nil` for the new 4th parameter (no profiles configured — exercises the "zero matches, generate exactly as before" path):

```go
package connector

import (
	"strings"
	"testing"
)

func TestBuildYAML_TagsSectorAndRegionRelevance(t *testing.T) {
	g := NewGenerator(t.TempDir(), []string{"government"}, []string{"south-asia"}, nil)
	actor := ThreatActor{
		Name:       "APT36",
		Sectors:    []string{"government"},
		Regions:    []string{"south-asia"},
		Techniques: []TechniqueRef{{ID: "T1059.001"}, {ID: "T1566.001"}},
	}
	yaml := g.buildYAML(actor, "abc123")
	if !strings.Contains(yaml, "sector-relevant") {
		t.Error("expected sector-relevant tag when actor sector matches configured sector")
	}
	if !strings.Contains(yaml, "region-relevant") {
		t.Error("expected region-relevant tag when actor region matches configured region")
	}
}

func TestBuildYAML_NoTagsWhenNoOverlap(t *testing.T) {
	g := NewGenerator(t.TempDir(), []string{"financial-services"}, []string{"emea"}, nil)
	actor := ThreatActor{
		Name:       "SomeOtherActor",
		Sectors:    []string{"government"},
		Regions:    []string{"south-asia"},
		Techniques: []TechniqueRef{{ID: "T1059.001"}, {ID: "T1566.001"}},
	}
	yaml := g.buildYAML(actor, "def456")
	if strings.Contains(yaml, "sector-relevant") {
		t.Error("did not expect sector-relevant tag when no sector overlap")
	}
	if strings.Contains(yaml, "region-relevant") {
		t.Error("did not expect region-relevant tag when no region overlap")
	}
}

func TestBuildYAML_NoTagsWhenNotConfigured(t *testing.T) {
	g := NewGenerator(t.TempDir(), nil, nil, nil)
	actor := ThreatActor{
		Name:       "APT36",
		Sectors:    []string{"government"},
		Regions:    []string{"south-asia"},
		Techniques: []TechniqueRef{{ID: "T1059.001"}, {ID: "T1566.001"}},
	}
	yaml := g.buildYAML(actor, "ghi789")
	if strings.Contains(yaml, "sector-relevant") || strings.Contains(yaml, "region-relevant") {
		t.Error("did not expect relevance tags when deployment sector/region is unconfigured")
	}
}

func TestBuildYAML_NoDetectionProfilesWhenNoneConfigured(t *testing.T) {
	g := NewGenerator(t.TempDir(), nil, nil, nil)
	actor := ThreatActor{
		Name:       "APT29",
		Techniques: []TechniqueRef{{ID: "T1003.002"}},
	}
	yaml := g.buildYAML(actor, "jkl012")
	if strings.Contains(yaml, "detection_profiles:") {
		t.Error("did not expect detection_profiles: block when no profiles are configured -- must match pre-inheritance behavior exactly")
	}
}

func TestBuildYAML_AttachesMatchingDetectionProfile(t *testing.T) {
	profiles := map[string]*scenario.DetectionProfile{
		"windows_sam_theft": {Profile: "windows_sam_theft", TechniqueIDs: []string{"T1003.002"}},
	}
	g := NewGenerator(t.TempDir(), nil, nil, profiles)
	actor := ThreatActor{
		Name:       "APT29",
		Techniques: []TechniqueRef{{ID: "T1003.002"}},
	}
	yaml := g.buildYAML(actor, "mno345")
	if !strings.Contains(yaml, "detection_profiles:") {
		t.Fatal("expected a detection_profiles: block")
	}
	if !strings.Contains(yaml, "- windows_sam_theft") {
		t.Errorf("expected windows_sam_theft in detection_profiles:, got:\n%s", yaml)
	}
}

func TestBuildYAML_UnmatchedTechniqueGetsNoDetectionProfiles(t *testing.T) {
	profiles := map[string]*scenario.DetectionProfile{
		"windows_sam_theft": {Profile: "windows_sam_theft", TechniqueIDs: []string{"T1003.002"}},
	}
	g := NewGenerator(t.TempDir(), nil, nil, profiles)
	actor := ThreatActor{
		Name:       "SomeActor",
		Techniques: []TechniqueRef{{ID: "T9999"}}, // no profile declares this
	}
	yaml := g.buildYAML(actor, "pqr678")
	if strings.Contains(yaml, "detection_profiles:") {
		t.Errorf("did not expect detection_profiles: block for an unmatched technique, got:\n%s", yaml)
	}
}
```

Note the new tests import `"github.com/audspect/bas/internal/scenario"` — add that to the `import` block.

- [ ] **Step 2: Run tests to verify the new ones fail (and the 3 existing ones now compile)**

Run: `go test ./internal/connector/... -run TestBuildYAML -v`
Expected: compile succeeds (proving the 3 existing tests' new `nil` argument is accepted once Step 3 below changes the signature — if this step is run before Step 3's signature change, it will instead FAIL to compile with "too many arguments," which is the expected starting state). Run this after Step 3's implementation to see the 2 new tests FAIL on missing `detection_profiles:` wiring and the 4 pre-existing/adjacent tests PASS.

- [ ] **Step 3: Implement the Generator changes**

In `orchestrator/internal/connector/generator.go`:

1. Add the import: `"github.com/audspect/bas/internal/scenario"`.
2. Add a field to `Generator`:
```go
type Generator struct {
	intelDir string
	sectors  []string
	regions  []string

	// techniqueIdx maps ATT&CK technique ID -> candidate detection-profile
	// names (Detection Profile Inheritance). Built once at construction
	// time from the profiles the caller already loaded.
	techniqueIdx map[string][]string
}
```
3. Change `NewGenerator`:
```go
// NewGenerator creates a Generator that writes to intelDir, tagging
// generated scenarios as sector/region-relevant when a threat actor's own
// Sectors/Regions overlap the given values, and auto-attaching a
// detection_profiles: entry for any technique that exact-matches a loaded
// profile's TechniqueIDs (Detection Profile Inheritance). profiles may be
// nil (no inheritance attempted, scenarios generate exactly as before).
func NewGenerator(scenariosDir string, sectors, regions []string, profiles map[string]*scenario.DetectionProfile) *Generator {
	return &Generator{
		intelDir:     filepath.Join(scenariosDir, "intel"),
		sectors:      sectors,
		regions:      regions,
		techniqueIdx: buildTechniqueIndex(profiles),
	}
}
```
4. In `buildYAML`, after the existing `techIDs`-collection loop (which builds `techIDs []string` from `actor.Techniques`), add a second collection pass and emit the new block right after the existing `art_techniques:` block:
```go
	sb.WriteString("art_techniques:\n")
	for _, t := range techIDs {
		sb.WriteString(fmt.Sprintf("  - %s\n", t))
	}

	// Detection Profile Inheritance: attach any profile whose TechniqueIDs
	// exactly matches one of this actor's techniques.
	var detectionProfiles []string
	seenProfiles := make(map[string]bool)
	for _, id := range techIDs {
		if name := resolveProfile(g.techniqueIdx, id); name != "" && !seenProfiles[name] {
			seenProfiles[name] = true
			detectionProfiles = append(detectionProfiles, name)
		}
	}
	if len(detectionProfiles) > 0 {
		sort.Strings(detectionProfiles)
		sb.WriteString("detection_profiles:\n")
		for _, p := range detectionProfiles {
			sb.WriteString(fmt.Sprintf("  - %s\n", p))
		}
	}

	return sb.String()
```
(This replaces the existing `return sb.String()` at the end of `buildYAML` — the new block goes immediately before it, after the existing `art_techniques:` loop.)

- [ ] **Step 4: Update the call site in `main.go`**

In `orchestrator/cmd/server/main.go`, change line 248 from:
```go
gen := connector.NewGenerator(cfg.ScenariosDir, cfg.ThreatIntelSectors, cfg.ThreatIntelRegions)
```
to:
```go
gen := connector.NewGenerator(cfg.ScenariosDir, cfg.ThreatIntelSectors, cfg.ThreatIntelRegions, engine.Profiles())
```
Safe because `engine.Load()` (line 142) already runs before this call site (line 248) — `engine.Profiles()` is fully populated.

- [ ] **Step 5: Run all connector tests to verify everything passes**

Run: `go test ./internal/connector/... -v -count=1`
Expected: 100% PASS — all pre-existing tests (unchanged behavior except the 3 signature-updated ones) plus all new tests from Task 2 and this task.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/connector/generator.go orchestrator/internal/connector/generator_test.go orchestrator/cmd/server/main.go
git commit -m "feat(connector): Detection Profile Inheritance -- Generator auto-attaches matching profiles"
git push
```

---

## Task 4: `internal/coverage` Package

**Files:**
- Create: `orchestrator/internal/coverage/matrix.go`
- Test: `orchestrator/internal/coverage/matrix_test.go`

**Interfaces:**
- Consumes: `scenario.Scenario`, `scenario.Step.TechniqueID`, `scenario.Scenario.Tags`, `scenario.DetectionProfile.TechniqueIDs` (all pre-existing except the last, from Task 1).
- Produces: `coverage.Row`, `coverage.Compute(techniqueIDs []string, simulation, profile, purpleExercise, compliance map[string]bool) []Row`, `coverage.BuildSimulationIndex([]*scenario.Scenario) map[string]bool`, `coverage.BuildComplianceIndex([]*scenario.Scenario) map[string]bool`, `coverage.BuildProfileIndex(map[string]*scenario.DetectionProfile) map[string]bool` — all consumed by Task 5 (`CoverageMatrix` handler).

- [ ] **Step 1: Write the failing tests**

```go
package coverage

import (
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func TestCompute_JoinsFourSetsCorrectly(t *testing.T) {
	sim := map[string]bool{"T1003.002": true, "T1083": true}
	profile := map[string]bool{"T1003.002": true}
	purple := map[string]bool{"T1003.002": true, "T1083": true}
	compliance := map[string]bool{}

	rows := Compute([]string{"T1003.002", "T1083", "T9999"}, sim, profile, purple, compliance)
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3", len(rows))
	}

	r0 := rows[0]
	if r0.TechniqueID != "T1003.002" || !r0.SimulationExists || !r0.DetectionProfileExists || !r0.PurpleExerciseExists || r0.ComplianceMappingExists {
		t.Errorf("row 0 (T1003.002) = %+v, unexpected", r0)
	}

	r1 := rows[1]
	if r1.TechniqueID != "T1083" || !r1.SimulationExists || r1.DetectionProfileExists || !r1.PurpleExerciseExists {
		t.Errorf("row 1 (T1083) = %+v, unexpected", r1)
	}

	r2 := rows[2]
	if r2.TechniqueID != "T9999" || r2.SimulationExists || r2.DetectionProfileExists || r2.PurpleExerciseExists || r2.ComplianceMappingExists {
		t.Errorf("row 2 (T9999, unknown to every set) = %+v, want all false", r2)
	}
}

func TestCompute_ResponsePlaybookAlwaysNil(t *testing.T) {
	rows := Compute([]string{"T1003.002"}, map[string]bool{"T1003.002": true}, map[string]bool{"T1003.002": true}, map[string]bool{"T1003.002": true}, map[string]bool{"T1003.002": true})
	if rows[0].ResponsePlaybookExists != nil {
		t.Errorf("ResponsePlaybookExists = %v, want nil (always N/A -- no technique-level response-action linkage exists)", rows[0].ResponsePlaybookExists)
	}
}

func TestBuildSimulationIndex(t *testing.T) {
	scenarios := []*scenario.Scenario{
		{Steps: []scenario.Step{{TechniqueID: "T1003.002"}, {TechniqueID: "T1083"}}},
		{Steps: []scenario.Step{{TechniqueID: "T1490"}}},
	}
	idx := BuildSimulationIndex(scenarios)
	for _, id := range []string{"T1003.002", "T1083", "T1490"} {
		if !idx[id] {
			t.Errorf("expected %s in simulation index", id)
		}
	}
	if idx["T9999"] {
		t.Error("did not expect T9999 in simulation index")
	}
}

func TestBuildComplianceIndex_OnlyComplianceTaggedScenarios(t *testing.T) {
	scenarios := []*scenario.Scenario{
		{Tags: []string{"compliance", "cscrf"}, Steps: []scenario.Step{{TechniqueID: "T1490"}}},
		{Tags: []string{"ransomware"}, Steps: []scenario.Step{{TechniqueID: "T1486"}}}, // not compliance-tagged
	}
	idx := BuildComplianceIndex(scenarios)
	if !idx["T1490"] {
		t.Error("expected T1490 in compliance index (scenario is compliance-tagged)")
	}
	if idx["T1486"] {
		t.Error("did not expect T1486 in compliance index (scenario is not compliance-tagged)")
	}
}

func TestBuildProfileIndex(t *testing.T) {
	profiles := map[string]*scenario.DetectionProfile{
		"windows_sam_theft":         {TechniqueIDs: []string{"T1003.002"}},
		"windows_credential_access": {}, // no TechniqueIDs, abstract base
	}
	idx := BuildProfileIndex(profiles)
	if !idx["T1003.002"] {
		t.Error("expected T1003.002 in profile index")
	}
	if len(idx) != 1 {
		t.Errorf("expected exactly 1 entry, got %d: %v", len(idx), idx)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/coverage/... -v`
Expected: FAIL — package/functions don't exist yet.

- [ ] **Step 3: Implement**

```go
// Package coverage computes, for a set of ATT&CK techniques, whether a
// simulation, detection profile, purple-team exercise, or compliance
// mapping exists -- a read-only diagnostic view, not a new storage model.
// Every Build*Index function derives its set from data the caller already
// has loaded (scenarios, detection profiles); Compute is a pure join with
// no I/O of its own, so it's trivially testable with map literals.
package coverage

import "github.com/audspect/bas/internal/scenario"

// Row is one ATT&CK technique's coverage status across five dimensions.
type Row struct {
	TechniqueID             string `json:"techniqueId"`
	SimulationExists        bool   `json:"simulationExists"`
	DetectionProfileExists  bool   `json:"detectionProfileExists"`
	PurpleExerciseExists    bool   `json:"purpleExerciseExists"`
	ComplianceMappingExists bool   `json:"complianceMappingExists"`

	// ResponsePlaybookExists is always nil -- renders as "N/A" in the UI.
	// internal/actions (EPP isolate/kill/quarantine) has no technique-level
	// linkage today; faking a bool here would be a false negative for
	// every technique, which is worse than an honest N/A.
	ResponsePlaybookExists *bool `json:"responsePlaybookExists"`
}

// Compute joins four precomputed technique-ID membership sets into one row
// per requested technique ID, in the order given.
func Compute(techniqueIDs []string, simulation, profile, purpleExercise, compliance map[string]bool) []Row {
	rows := make([]Row, 0, len(techniqueIDs))
	for _, id := range techniqueIDs {
		rows = append(rows, Row{
			TechniqueID:             id,
			SimulationExists:        simulation[id],
			DetectionProfileExists:  profile[id],
			PurpleExerciseExists:    purpleExercise[id],
			ComplianceMappingExists: compliance[id],
			ResponsePlaybookExists:  nil,
		})
	}
	return rows
}

// BuildSimulationIndex returns the set of technique IDs covered by at
// least one step across the given scenarios.
func BuildSimulationIndex(scenarios []*scenario.Scenario) map[string]bool {
	idx := make(map[string]bool)
	for _, sc := range scenarios {
		for _, step := range sc.Steps {
			if step.TechniqueID != "" {
				idx[step.TechniqueID] = true
			}
		}
	}
	return idx
}

// BuildComplianceIndex returns the set of technique IDs covered by at
// least one step in a scenario tagged "compliance" -- the existing tag
// convention already used by cis-ubuntu-l1.yaml and cscrf-mii-drill.yaml.
func BuildComplianceIndex(scenarios []*scenario.Scenario) map[string]bool {
	idx := make(map[string]bool)
	for _, sc := range scenarios {
		if !containsTag(sc.Tags, "compliance") {
			continue
		}
		for _, step := range sc.Steps {
			if step.TechniqueID != "" {
				idx[step.TechniqueID] = true
			}
		}
	}
	return idx
}

// BuildProfileIndex returns the set of technique IDs declared by at least
// one loaded detection profile's TechniqueIDs.
func BuildProfileIndex(profiles map[string]*scenario.DetectionProfile) map[string]bool {
	idx := make(map[string]bool)
	for _, p := range profiles {
		for _, tid := range p.TechniqueIDs {
			idx[tid] = true
		}
	}
	return idx
}

func containsTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/coverage/... -v`
Expected: PASS, all 5 tests.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/coverage/matrix.go orchestrator/internal/coverage/matrix_test.go
git commit -m "feat(coverage): new internal/coverage package -- pure technique coverage-matrix computation"
git push
```

---

## Task 5: API Handlers + Routes

**Files:**
- Create: `orchestrator/internal/api/coverage_handlers.go`
- Test: `orchestrator/internal/api/coverage_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go`

**Interfaces:**
- Consumes: `coverage.Compute`, `coverage.BuildSimulationIndex`, `coverage.BuildComplianceIndex`, `coverage.BuildProfileIndex` (Task 4); `attackdata.GroupTechniqueIndex()` (pre-existing); `exercise.BuiltinTemplates` (pre-existing); `h.engine.List()`, `h.engine.Profiles()` (pre-existing).
- Produces: `GET /api/coverage/matrix?actor=` and `GET /api/coverage/actors` — consumed by Task 6 (UI).

- [ ] **Step 1: Write the failing test**

Neither handler touches `h.db` (both only use `h.engine`, `attackdata`, and `exercise.BuiltinTemplates`), so this test constructs the `Handler` directly with a `nil` pool — confirmed safe: `New()` (`orchestrator/internal/api/handlers.go:93`) is a plain struct literal, `db` is stored but never dereferenced at construction. No Postgres container needed for this test, unlike most other `*_handlers_test.go` files in this package.

```go
package api

import (
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestCoverageMatrix_ReturnsRowsForKnownActor(t *testing.T) {
	engine := scenario.NewEngine(t.TempDir())
	if err := engine.Load(); err != nil {
		t.Fatalf("engine.Load: %v", err)
	}
	h := New(nil, ws.NewHub(), engine, "")

	req := httptest.NewRequest("GET", "/api/coverage/matrix?actor=Wizard Spider", nil)
	w := httptest.NewRecorder()
	h.CoverageMatrix(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
	}
	if w.Body.Len() == 0 {
		t.Fatal("expected a non-empty JSON body")
	}
}

func TestCoverageActors_ReturnsSortedNonEmptyList(t *testing.T) {
	engine := scenario.NewEngine(t.TempDir())
	if err := engine.Load(); err != nil {
		t.Fatalf("engine.Load: %v", err)
	}
	h := New(nil, ws.NewHub(), engine, "")

	req := httptest.NewRequest("GET", "/api/coverage/actors", nil)
	w := httptest.NewRecorder()
	h.CoverageActors(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
	}
	if w.Body.Len() == 0 {
		t.Fatal("expected a non-empty JSON body -- attackdata.GroupTechniqueIndex() ships bundled MITRE groups, list should never be empty")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/api/... -run 'TestCoverageMatrix|TestCoverageActors' -v`
Expected: FAIL — `CoverageMatrix`/`CoverageActors` undefined.

- [ ] **Step 3: Implement the handlers**

```go
package api

import (
	"net/http"
	"sort"

	"github.com/audspect/bas/internal/coverage"
	"github.com/audspect/bas/internal/exercise"
	"github.com/audspect/bas/internal/reporting/attackdata"
)

// GET /api/coverage/matrix?actor=<name>
//
// If actor is omitted, returns rows for the union of every technique in
// attackdata.GroupTechniqueIndex() (the bundled MITRE STIX baseline) --
// i.e. every technique associated with any known ATT&CK group. If actor
// is given, returns just that actor's technique list from the same index.
//
// This is content-existence coverage (does a simulation/profile/exercise/
// mapping exist at all), distinct from the pre-existing
// GET /api/coverage/analytics (run-result pass/fail aggregation across
// executed runs) -- no overlap, no shared code path.
func (h *Handler) CoverageMatrix(w http.ResponseWriter, r *http.Request) {
	actor := r.URL.Query().Get("actor")
	idx := attackdata.GroupTechniqueIndex()

	var techIDs []string
	if actor != "" {
		techIDs = idx[actor]
	} else {
		seen := make(map[string]bool)
		for _, ids := range idx {
			for _, id := range ids {
				if !seen[id] {
					seen[id] = true
					techIDs = append(techIDs, id)
				}
			}
		}
		sort.Strings(techIDs)
	}

	scenarios := h.engine.List()
	sim := coverage.BuildSimulationIndex(scenarios)
	compliance := coverage.BuildComplianceIndex(scenarios)
	profileIdx := coverage.BuildProfileIndex(h.engine.Profiles())

	purple := make(map[string]bool)
	for _, tmpl := range exercise.BuiltinTemplates {
		for _, id := range tmpl.ExpectedTechniques {
			purple[id] = true
		}
	}

	rows := coverage.Compute(techIDs, sim, profileIdx, purple, compliance)
	respond(w, rows)
}

// GET /api/coverage/actors
//
// Returns the sorted list of ATT&CK group names known to
// attackdata.GroupTechniqueIndex() -- populates the actor picker on the
// Technique Coverage tab.
func (h *Handler) CoverageActors(w http.ResponseWriter, r *http.Request) {
	idx := attackdata.GroupTechniqueIndex()
	names := make([]string, 0, len(idx))
	for name := range idx {
		names = append(names, name)
	}
	sort.Strings(names)
	respond(w, map[string][]string{"actors": names})
}
```

- [ ] **Step 4: Register the routes**

In `orchestrator/internal/api/routes.go`, immediately after the existing `r.Get("/api/coverage/analytics", h.GetCoverageAnalytics)` line:
```go
		// Technique Coverage -- content-existence matrix (simulation/detection
		// profile/purple exercise/compliance mapping), distinct from
		// /api/coverage/analytics above (run-result aggregation).
		r.Get("/api/coverage/matrix", h.CoverageMatrix)
		r.Get("/api/coverage/actors", h.CoverageActors)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/api/... -run 'TestCoverageMatrix|TestCoverageActors' -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/api/coverage_handlers.go orchestrator/internal/api/coverage_handlers_test.go orchestrator/internal/api/routes.go
git commit -m "feat(api): GET /api/coverage/matrix and /api/coverage/actors -- Technique Coverage endpoints"
git push
```

---

## Task 6: "Technique Coverage" UI Tab

**Files:**
- Modify: `orchestrator/wwwroot/index.html`

**Interfaces:**
- Consumes: `GET /api/coverage/matrix?actor=`, `GET /api/coverage/actors` (Task 5).

- [ ] **Step 1: Add the nav item**

Immediately after the existing `<div class="nav-item" data-tab="exercises" ...>` block (around line 1297-1302), add:
```html
        <div class="nav-item" data-tab="attack-coverage" onclick="showTab('attack-coverage')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <path d="M1 1h6v6H1zM9 1h6v6H9zM1 9h6v6H1zM9 9h6v6H9z"/>
          </svg>
          Technique Coverage
        </div>
```

- [ ] **Step 2: Add the tab panel**

Immediately after the `tab-exercises` panel's closing `</div>` (find it by locating `id="tab-exercises"` and its matching close), add a new sibling panel:
```html
      <div id="tab-attack-coverage" style="display:none">
        <div class="card" style="margin-bottom:1rem;padding:1rem 1.2rem">
          <div class="card-title">Technique Coverage</div>
          <div style="margin:0.5rem 0 1rem;display:flex;gap:0.75rem;align-items:center">
            <label class="tiny muted" for="cov-actor-select">Actor</label>
            <select id="cov-actor-select" onchange="loadCoverageMatrix()">
              <option value="">All techniques</option>
            </select>
          </div>
          <div class="tbl-wrap">
            <table>
              <thead>
                <tr>
                  <th>Technique</th>
                  <th>Simulation</th>
                  <th>Detection Profile</th>
                  <th>Purple Exercise</th>
                  <th>Compliance Mapping</th>
                  <th>Response Playbook</th>
                </tr>
              </thead>
              <tbody id="cov-matrix-body"></tbody>
            </table>
          </div>
          <div id="cov-matrix-empty" class="empty" style="display:none">No techniques to show.</div>
        </div>
      </div>
```

- [ ] **Step 3: Add JS load/render functions**

Immediately after the existing `loadRecommendations`/`renderRecommendations` functions (or any other convenient location in the same `<script>` block), add:
```javascript
function covStatusCell(val) {
  if (val === null) return '<span class="tiny muted">N/A</span>';
  return val ? '<span style="color:var(--success)">&#10003;</span>' : '<span class="tiny muted">&mdash;</span>';
}

function loadCoverageActors() {
  var sel = document.getElementById('cov-actor-select');
  apicall('/api/coverage/actors')
    .then(function(data) {
      var actors = (data && data.actors) || [];
      actors.forEach(function(name) {
        var opt = document.createElement('option');
        opt.value = name;
        opt.textContent = name;
        sel.appendChild(opt);
      });
    })
    .catch(function(e) { console.error('loadCoverageActors failed', e); });
}

function loadCoverageMatrix() {
  var sel = document.getElementById('cov-actor-select');
  var actor = sel ? sel.value : '';
  var body = document.getElementById('cov-matrix-body');
  var empty = document.getElementById('cov-matrix-empty');
  body.innerHTML = '<tr><td colspan="6" class="empty">Loading&hellip;</td></tr>';
  var url = '/api/coverage/matrix' + (actor ? '?actor=' + encodeURIComponent(actor) : '');
  apicall(url)
    .then(function(rows) {
      rows = rows || [];
      if (!rows.length) {
        body.innerHTML = '';
        empty.style.display = '';
        return;
      }
      empty.style.display = 'none';
      body.innerHTML = rows.map(function(r) {
        return '<tr>' +
          '<td style="font-weight:600">' + x(r.techniqueId) + '</td>' +
          '<td>' + covStatusCell(r.simulationExists) + '</td>' +
          '<td>' + covStatusCell(r.detectionProfileExists) + '</td>' +
          '<td>' + covStatusCell(r.purpleExerciseExists) + '</td>' +
          '<td>' + covStatusCell(r.complianceMappingExists) + '</td>' +
          '<td>' + covStatusCell(r.responsePlaybookExists) + '</td>' +
          '</tr>';
      }).join('');
    })
    .catch(function(e) {
      body.innerHTML = '<tr><td colspan="6" class="empty" style="color:var(--danger)">Failed to load: ' + x(e.message) + '</td></tr>';
    });
}
```

- [ ] **Step 4: Wire tab activation**

In `activateTab()` (line 4006), add `'attack-coverage'` to the hardcoded array:
```javascript
function activateTab(name) {
  ['dashboard','agents','scenarios','runs','campaigns','coverage','findings','remediation','reports','verification','compliance','settings','variants','em','attackpath','exposure','exec-dashboard','recommendations','integrations','exercises','attack-coverage'].forEach(function(t) {
```

In `TAB_TITLES` (line 3874), add `'attack-coverage':'Technique Coverage'`:
```javascript
var TAB_TITLES = { dashboard:'Dashboard', agents:'Agents', scenarios:'Scenarios', runs:'Live Runs', campaigns:'Campaigns', coverage:'ATT&CK Coverage', findings:'Findings', remediation:'Remediation', reports:'Reports', verification:'Detection Verification', users:'Users', compliance:'Compliance', settings:'Settings', variants:'Variant Executor', em:'Endpoint Mastery', exposure:'Exposure Explorer', 'exec-dashboard':'Executive Dashboard', recommendations:'Recommendations', exercises:'Exercises', 'attack-coverage':'Technique Coverage' };
```

In `showTab()` (near line 4016-4020), add a load trigger:
```javascript
function showTab(name) {
  try { localStorage.setItem('bas_last_tab', name); } catch(e) {}
  activateTab(name);
  if (name === 'agents') loadAgents();
  if (name === 'runs') loadRuns();
  if (name === 'attack-coverage') { loadCoverageActors(); loadCoverageMatrix(); }
```
(Insert the new `if` line alongside the existing ones in this function, without altering any existing line.)

- [ ] **Step 5: Structural verification**

Since this session has no browser tool available (same caveat as the OpenAEV/Exercises tab work), verify structurally:
```bash
python3 -c "
content = open('orchestrator/wwwroot/index.html', encoding='utf-8').read()
assert content.count('id=\"tab-attack-coverage\"') == 1, 'tab panel id must appear exactly once'
assert content.count('data-tab=\"attack-coverage\"') == 1, 'nav item data-tab must appear exactly once'
assert 'function loadCoverageMatrix' in content
assert 'function loadCoverageActors' in content
assert 'function covStatusCell' in content
assert \"'attack-coverage'\" in content.split('function activateTab')[1][:600]
print('structural checks OK')
"
```
Expected: `structural checks OK`, no assertion errors.

A manual visual spot-check of the "Technique Coverage" tab is recommended once a browser is available, same as the standing caveat on the OpenAEV/Exercises tabs.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(ui): Technique Coverage tab -- actor picker + 5-column coverage matrix"
git push
```

---

## Task 7: Final Regression

- [ ] **Step 1: Run the full test suite**

Run (from `orchestrator/`): `go test ./... -v -count=1`
Expected: 100% PASS across every package, including `internal/scenario`, `internal/connector`, `internal/coverage`, `internal/api`, and every other pre-existing package untouched by this plan.

- [ ] **Step 2: Build the whole module**

Run: `go build ./...`
Expected: no errors, no output.

- [ ] **Step 3: Vet the whole module**

Run: `go vet ./...`
Expected: no output.

- [ ] **Step 4: Confirm nothing else changed unexpectedly**

Run: `git status --short`
Expected: clean working tree (everything already committed task-by-task in Tasks 1-6).
