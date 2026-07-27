# Threat Intelligence Center — Phase 1: Detection Profile Inheritance + ATT&CK Coverage Matrix — Design

**Scope:** Phase 1 of a larger user-proposed vision to make MISP/OpenCTI/OTX a decision-making/orchestration layer rather than just a content source (9-item vision, discussed and decomposed with the user). This deliverable covers exactly 2 of those 9 items — the two judged smallest-lift and highest-leverage, both building on infrastructure that already exists. Items 2 (Campaign Timeline), 3 (IOC Validation), 6 (Actor relationship graph), 8 (Variant Generation), 9 (Continuous Updates), and the full Threat Intelligence Center UI are explicitly out of scope, deferred to later phases.

## Problem

MISP/OpenCTI/OTX threat actors already auto-generate real, runnable BAS scenarios (`internal/connector.Generator`, wired live into the sync scheduler) — but those generated scenarios carry only `art_techniques:` (a generic ART-execution list). They never get `detection_profiles:`, so a customer running an auto-generated "APT29 — Active Campaign" scenario gets PASS/FAIL telemetry but not a Detection Validation gap-analysis report, unlike every hand-authored scenario shipped this cycle (ransomware families, Insider Threat, DLP Suite). Separately, there is no single view answering "for technique X, does a simulation exist? A detection profile? A Purple Team exercise? A compliance mapping?" — answering that today means manually cross-referencing scenario files, profile files, and exercise-template Go code.

## Non-goals

- **No Campaign Timeline, IOC Validation, actor relationship graph, Variant Generation, or Continuous Updates versioning UI.** All explicitly later phases.
- **No full Threat Intelligence Center UI** (Threat Actors/Campaigns/Malware/Ransomware Families/Emerging Threats/etc.). This ships one new minimal tab as the seed, nothing more.
- **No new persistent storage.** Both pieces compute from data that already exists at request/generation time — no new database tables.
- **No change to existing `/api/coverage/analytics` or the existing "Coverage Analytics" UI panel.** That is run-result aggregation (pass/fail breakdown across executed runs) — a different, pre-existing feature. This deliverable adds a sibling `/api/coverage/matrix` endpoint and a differently-named "ATT&CK Coverage Matrix" tab; there is no overlap and no intent to modify or replace the existing feature.
- **No backfill of already-generated `scenarios/intel/*.yaml` files.** Detection Profile Inheritance applies forward-only — existing intel scenarios pick it up naturally the next time their actor's technique set changes and the file regenerates (the existing fingerprint-based skip-if-unchanged mechanism is untouched).
- **No Response Playbook per-technique linkage.** `internal/actions` (EPP isolate/kill/quarantine) has zero technique-level linkage today; that column in the Coverage Matrix is always `N/A`, not faked.
- **No change to `DetectionProfile` resolution, scoring, or the `extends`/inheritance mechanism.** `TechniqueIDs` is purely additive metadata, consumed only by the two new pieces below.

## Architecture

### Part 1 — Detection Profile Inheritance

**Schema addition** (`orchestrator/internal/scenario/detection.go`, `DetectionProfile` struct):
```go
type DetectionProfile struct {
	Profile  string               `yaml:"profile" json:"profile"`
	Version  int                  `yaml:"version" json:"version"`
	Extends  []string             `yaml:"extends,omitempty" json:"extends,omitempty"`
	Expected []ExpectedDetection  `yaml:"expected_detection" json:"expectedDetection"`
	Source   string               `yaml:"-" json:"source,omitempty"`

	// TechniqueIDs lists the ATT&CK techniques this behavioral profile is
	// relevant to. Additive metadata only -- does not change resolution,
	// inheritance, or scoring. A many-to-many hint, consistent with this
	// struct's existing design philosophy ("one behavior maps to several
	// techniques and one technique yields different detections by
	// implementation"): one profile can cover several techniques (e.g.
	// windows_dlp_exfiltration spans 5 DLP channels), and one technique
	// can legitimately have several profiles for different sub-behaviors
	// (e.g. T1562.001 has windows_defender_tampering,
	// windows_security_process_termination, and
	// windows_vulnerable_driver_load -- three different implementations
	// of "impair defenses"). Consumed by connector.Generator (Detection
	// Profile Inheritance) and internal/coverage (Coverage Matrix).
	TechniqueIDs []string `yaml:"technique_ids,omitempty" json:"techniqueIds,omitempty"`
}
```

**Content migration** — derived by scanning every existing scenario file's `technique_id` + `detection_profiles` step pairs (exact data, not re-derived at implementation time):

| Profile | `technique_ids:` |
|---|---|
| `windows_ad_discovery` | `[T1087.002]` |
| `windows_archive_staging` | `[T1560.001]` |
| `windows_asrep_roast` | `[T1558.004]` |
| `windows_backup_service_stop` | `[T1489]` |
| `windows_cloud_egress` | `[T1567.002]` |
| `windows_data_destruction` | `[T1485]` |
| `windows_defender_tampering` | `[T1562.001]` |
| `windows_dlp_exfiltration` | `[T1052, T1052.001, T1074.001, T1115, T1560.001]` |
| `windows_dns_c2` | `[T1071.004]` |
| `windows_encoded_powershell` | `[T1059.001]` |
| `windows_file_discovery` | `[T1083]` |
| `windows_kerberoast` | `[T1558.003]` |
| `windows_log_manipulation` | `[T1070.001]` |
| `windows_lolbin_download_cradle` | `[T1105]` |
| `windows_malicious_service` | `[T1543.003]` |
| `windows_netsh_portproxy` | `[T1090.001]` |
| `windows_network_share_discovery` | `[T1135]` |
| `windows_ransomware_encryption` | `[T1486]` |
| `windows_rdp_nla_posture` | `[T1021.001]` |
| `windows_runkey_persistence` | `[T1547.001]` |
| `windows_sam_theft` | `[T1003.002]` |
| `windows_schtask_persistence` | `[T1053.005]` |
| `windows_security_process_termination` | `[T1562.001]` |
| `windows_security_software_discovery` | `[T1518.001]` |
| `windows_smb_lateral_probe` | `[T1021.002]` |
| `windows_vss_inhibition` | `[T1490]` |
| `windows_vulnerable_driver_load` | `[T1562.001]` |
| `windows_webmail_egress` | `[T1567]` |

`windows_credential_access` (the abstract base profile other profiles `extends` — never referenced directly by any scenario step) is **excluded** from this migration; it stays without `technique_ids:`.

**Index + matching** (new file `orchestrator/internal/connector/technique_index.go`):
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
// resolution. Profiles with no TechniqueIDs (e.g. abstract base profiles)
// contribute nothing.
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

**Generator wiring** (`orchestrator/internal/connector/generator.go`):
- `Generator` struct gains `techniqueIdx map[string][]string`.
- `NewGenerator` signature changes to `NewGenerator(scenariosDir string, sectors, regions []string, profiles map[string]*scenario.DetectionProfile) *Generator`, building `techniqueIdx` once via `buildTechniqueIndex(profiles)`.
- `buildYAML()` — for each unique technique ID already being collected into `techIDs` (existing loop), also calls `resolveProfile(g.techniqueIdx, id)`; if non-empty, collect into a `detectionProfiles []string` slice (deduplicated). After the existing `art_techniques:` block, emit:
```go
if len(detectionProfiles) > 0 {
	sb.WriteString("detection_profiles:\n")
	for _, p := range detectionProfiles {
		sb.WriteString(fmt.Sprintf("  - %s\n", p))
	}
}
```
- Call site (`cmd/server/main.go:248`) changes from `connector.NewGenerator(cfg.ScenariosDir, cfg.ThreatIntelSectors, cfg.ThreatIntelRegions)` to `connector.NewGenerator(cfg.ScenariosDir, cfg.ThreatIntelSectors, cfg.ThreatIntelRegions, engine.Profiles())` — safe because `engine.Load()` (line 142) already runs before this call site (line 248), so `engine.Profiles()` is fully populated.

### Part 2 — ATT&CK Coverage Matrix

**New package** `orchestrator/internal/coverage/matrix.go` — pure computation, no new tables, no dependency on the `exercise` or `connector` packages (callers pass in precomputed sets, keeping this package trivially unit-testable):
```go
package coverage

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

**API handler** (new `orchestrator/internal/api/coverage_handlers.go`):
```go
// GET /api/coverage/matrix?actor=<name>
//
// If actor is omitted, returns rows for the union of every technique in
// attackdata.GroupTechniqueIndex() (the bundled MITRE STIX baseline) --
// i.e. every technique associated with any known ATT&CK group. If actor
// is given, returns just that actor's technique list from the same index.
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

	scenarios := h.engine.List() // existing accessor (internal/scenario/engine.go:115), same one every list-scenarios handler already uses
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
```

Route registration (`orchestrator/internal/api/routes.go`, alongside the existing `/api/ti/*` group, Viewer+ read tier — same RBAC level as `GetTIReadiness`):
```go
r.Get("/api/coverage/matrix", h.CoverageMatrix)
```

**UI** — new tab "ATT&CK Coverage Matrix" in `wwwroot/index.html`, following the established tab/`activateTab()` convention: an actor `<select>` (populated from the existing threat-actor listing already used elsewhere) defaulting to "All techniques," rendering the 5-column table (`✓`/`—` for the four real columns, literal `N/A` styled distinctly for Response Playbook).

### File and task structure

**Go changes** (no new tables):
- Modify: `orchestrator/internal/scenario/detection.go` (add `TechniqueIDs` field)
- Create: `orchestrator/internal/connector/technique_index.go` (`buildTechniqueIndex`, `resolveProfile`)
- Modify: `orchestrator/internal/connector/generator.go` (`Generator` struct + `NewGenerator` signature + `buildYAML` wiring)
- Modify: `orchestrator/cmd/server/main.go` (line 248 call-site update)
- Create: `orchestrator/internal/coverage/matrix.go` (`Row`, `Compute`, `BuildSimulationIndex`, `BuildComplianceIndex`, `BuildProfileIndex`, `containsTag`)
- Create: `orchestrator/internal/api/coverage_handlers.go` (`CoverageMatrix`)
- Modify: `orchestrator/internal/api/routes.go` (new route)
- Modify: `wwwroot/index.html` (new tab, hardlinked copy per existing convention)

**Content migration** (28 files, each re-signed):
- Modify: 28 files under `scenarios/detection-profiles/*.yaml` (add `technique_ids:`), each `go run scripts/signer.go sign private_key.pem <path>` re-run.

### Testing, signing, migration

- **Go unit tests**: `technique_index_test.go` (single match, zero match, the real 3-way T1562.001 collision as a fixture, case-insensitivity), `generator_test.go` extension (a technique with a known profile now produces `detection_profiles:` in the generated YAML; a technique with none produces the same output as before this change), `matrix_test.go` (each of the 4 real columns independently, `ResponsePlaybookExists` always `nil`).
- **Content validation**: same `python3 -c "import yaml; ..."` structural check on all 28 modified profile files, confirming `technique_ids:` parses as a list.
- **Full regression**: `go test ./...` (not just `internal/scenario` — this touches `internal/connector`, `internal/coverage`, `internal/api` too), `go build ./...`, `go vet ./...`.
- **Signing**: all 28 modified profile files re-signed (no new content files beyond the profiles — `technique_index.go`, `matrix.go`, `coverage_handlers.go` are Go source, not signed builtin content).
- **Migration**: additive only. Existing profiles without `technique_ids:` (i.e. `windows_credential_access`) simply never match in the index — no error, no behavior change for them. Existing `scenarios/intel/*.yaml` files are untouched (forward-only, per Non-goals).
