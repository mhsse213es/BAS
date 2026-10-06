package connector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/scenario"
)

const minTechniques = 2 // minimum techniques before generating a scenario

// Registrar is the slice of the Content Registry the generator writes to.
type Registrar interface {
	RegisterGenerated(ctx context.Context, c contentregistry.GeneratedCandidate) (string, bool, error)
}

const (
	generatorName    = "connector/generator"
	generatorVersion = "2" // 2 = registry-backed, deterministic YAML (TCF Phase 1)
	mappingVersion   = "1"
)

// Generator converts ThreatActor profiles into BAS scenario YAML files.
type Generator struct {
	intelDir string // e.g. "scenarios/intel"
	// sectors/regions are the deployment's own configured values
	// (config.Config.ThreatIntelSectors/ThreatIntelRegions) — when a
	// generated actor's own Sectors/Regions overlap these, the scenario
	// gets an extra relevance tag. Empty means no tags are ever added. See
	// docs/superpowers/specs/2026-07-19-sp5-sector-region-weighting-design.md.
	sectors []string
	regions []string

	// techniqueIdx maps ATT&CK technique ID -> candidate detection-profile
	// names (Detection Profile Inheritance). Built once at construction
	// time from the profiles the caller already loaded.
	techniqueIdx map[string][]string

	registrar Registrar
}

// WithRegistrar makes the generator register every candidate as a
// LOCAL/UNTRUSTED/DRAFT version in the Content Registry.
func (g *Generator) WithRegistrar(r Registrar) *Generator {
	g.registrar = r
	return g
}

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

// GenerateResult summarises what was written in one sync.
type GenerateResult struct {
	Created int
	Updated int
	Skipped int
	// Changed counts working-copy files whose bytes differ from what was on
	// disk (new or rewritten), independent of the registry outcome. The
	// scheduler reloads the scenario engine when Changed > 0.
	Changed int
}

// Write generates scenario YAMLs for each actor and returns a result summary.
// Files are named by the actor-derived content ID (intelContentID), and the
// YAML is byte-deterministic for unchanged inputs. The working copy is
// rewritten only when its bytes differ; every candidate is registered with
// the Content Registry (which dedups identical bytes). Created counts
// versions the registry created; Skipped covers everything else.
func (g *Generator) Write(actors []ThreatActor) (GenerateResult, error) {
	if err := os.MkdirAll(g.intelDir, 0755); err != nil {
		return GenerateResult{}, fmt.Errorf("mkdir %s: %w", g.intelDir, err)
	}

	var res GenerateResult
	for _, actor := range actors {
		if len(actor.Techniques) < minTechniques {
			res.Skipped++
			continue
		}

		id := intelContentID(actor.Name)
		body := g.buildYAML(actor, id)
		fname := filepath.Join(g.intelDir, id+".yaml")
		if old, err := os.ReadFile(fname); err != nil || !bytes.Equal(old, []byte(body)) {
			if err := os.WriteFile(fname, []byte(body), 0644); err != nil {
				log.Printf("[connector/gen] write %s: %v", fname, err)
				continue
			}
			res.Changed++
		}
		if g.registrar == nil {
			res.Skipped++
			continue
		}
		_, created, err := g.registrar.RegisterGenerated(context.Background(), contentregistry.GeneratedCandidate{
			ContentID: id, Artifact: []byte(body), GenerationKey: generationKey(actor),
			Generation: map[string]any{"generator": generatorName, "generator_version": generatorVersion,
				"mapping_version": mappingVersion, "parameters": map[string]any{"min_techniques": minTechniques}},
			Sources: []contentregistry.SourceRef{{EntityType: "actor", EntityID: actor.Name, Provider: actor.Source,
				ExternalID: actor.SourceID, Role: "primary"}},
		})
		if err != nil {
			log.Printf("[connector/gen] register %s: %v", id, err)
			continue
		}
		if created {
			log.Printf("[connector/gen] new DRAFT %s (%s, %d techniques)", id, actor.Name, len(actor.Techniques))
			res.Created++
		} else {
			res.Skipped++
		}
	}
	return res, nil
}

// ── YAML builder ──────────────────────────────────────────────────────────────

// buildYAML renders the scenario YAML. It is deterministic: no wall-clock or
// last-seen values, so unchanged techniques/confidence give identical bytes.
func (g *Generator) buildYAML(actor ThreatActor, contentID string) string {
	id := contentID

	// Collect unique technique IDs
	techIDs := dedupedTechniqueIDs(actor.Techniques)

	// Derive MITRE phases from techniques
	phases := deriveMITREPhases(actor.Techniques)

	// Tags
	tags := []string{"intel", "auto-generated", strings.ToLower(strings.ReplaceAll(actor.Name, " ", "-"))}
	if len(actor.Sectors) > 0 {
		tags = append(tags, actor.Sectors...)
	}
	if intersects(actor.Sectors, g.sectors) {
		tags = append(tags, "sector-relevant")
	}
	if intersects(actor.Regions, g.regions) {
		tags = append(tags, "region-relevant")
	}

	// Description
	description := actor.Description
	if description == "" {
		description = fmt.Sprintf("%s threat actor profile.", actor.Name)
	}
	if len(description) > 200 {
		description = description[:200] + "..."
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("id: %s\n", id))
	sb.WriteString(fmt.Sprintf("name: \"%s — Active Campaign (Intel)\"\n", actor.Name))
	sb.WriteString(fmt.Sprintf("description: \"Auto-generated from %s. %s Confidence: %s.\"\n",
		actor.Source, strings.ReplaceAll(description, `"`, `'`), actor.Confidence))
	sb.WriteString(fmt.Sprintf("author: \"Threat Intel Connector (%s)\"\n", actor.Source))

	sb.WriteString("tags:\n")
	for _, tag := range tags {
		sb.WriteString(fmt.Sprintf("  - %s\n", tag))
	}

	sb.WriteString("mitre_phases:\n")
	for _, p := range phases {
		sb.WriteString(fmt.Sprintf("  - %s\n", p))
	}

	sb.WriteString(fmt.Sprintf("intel_source: %s\n", actor.Source))
	sb.WriteString(fmt.Sprintf("intel_source_id: \"%s\"\n", actor.SourceID))
	sb.WriteString(fmt.Sprintf("intel_actor: \"%s\"\n", actor.Name))
	sb.WriteString(fmt.Sprintf("intel_confidence: %s\n", actor.Confidence))

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
}

// ── helpers ───────────────────────────────────────────────────────────────────

// dedupedTechniqueIDs returns actor's technique IDs, uppercased,
// deduplicated, and sorted -- shared by buildYAML's art_techniques list
// and Scheduler.upsertActorProfiles' threat_actor_profiles.techniques
// column, so the two never drift into different dedup/casing behavior.
// Deliberately a distinct name/behavior from misp.go's techniqueIDs
// (bare .ID extraction, no dedup/normalize, used for
// intelligence.Campaign/Malware/Tool.TechniqueIDs) -- that helper serves a
// different purpose and is untouched by this change.
func dedupedTechniqueIDs(techs []TechniqueRef) []string {
	out := make([]string, 0, len(techs))
	seen := make(map[string]bool)
	for _, t := range techs {
		up := strings.ToUpper(t.ID)
		if !seen[up] {
			seen[up] = true
			out = append(out, up)
		}
	}
	sort.Strings(out)
	return out
}

// intelContentID is derived from the actor identity only, so technique-set
// changes become versions of one content id (spec 5.2).
func intelContentID(actorName string) string {
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(actorName))))
	return "intel-" + hex.EncodeToString(h[:])[:12]
}

func generationKey(a ThreatActor) string {
	b, _ := json.Marshal(map[string]any{
		"generator": generatorName, "generator_version": generatorVersion, "mapping_version": mappingVersion,
		"inputs":     []map[string]string{{"entity_type": "actor", "entity_id": a.Name, "provider": a.Source, "external_id": a.SourceID}},
		"techniques": dedupedTechniqueIDs(a.Techniques),
		"parameters": map[string]any{"min_techniques": minTechniques},
	})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

var tacticsForTechniquePrefix = map[string]string{
	"T1566": "initial-access", "T1190": "initial-access", "T1078": "initial-access", "T1133": "initial-access",
	"T1059": "execution", "T1053": "execution", "T1047": "execution", "T1204": "execution",
	"T1547": "persistence", "T1543": "persistence", "T1136": "persistence", "T1098": "persistence",
	"T1134": "privilege-escalation", "T1055": "privilege-escalation", "T1068": "privilege-escalation", "T1548": "privilege-escalation",
	"T1562": "defense-evasion", "T1027": "defense-evasion", "T1070": "defense-evasion", "T1036": "defense-evasion", "T1218": "defense-evasion",
	"T1003": "credential-access", "T1558": "credential-access", "T1555": "credential-access", "T1110": "credential-access",
	"T1087": "discovery", "T1082": "discovery", "T1083": "discovery", "T1018": "discovery",
	"T1021": "lateral-movement", "T1550": "lateral-movement", "T1570": "lateral-movement",
	"T1560": "collection", "T1113": "collection", "T1114": "collection", "T1005": "collection",
	"T1041": "exfiltration", "T1048": "exfiltration", "T1567": "exfiltration",
	"T1071": "command-and-control", "T1095": "command-and-control", "T1572": "command-and-control",
	"T1486": "impact", "T1490": "impact", "T1485": "impact", "T1489": "impact",
}

func deriveMITREPhases(techniques []TechniqueRef) []string {
	seen := make(map[string]bool)
	var phases []string
	for _, t := range techniques {
		tactic := t.Tactic
		if tactic == "" {
			// Derive from technique ID prefix
			base := strings.ToUpper(t.ID)
			if i := strings.Index(base, "."); i > 0 {
				base = base[:i]
			}
			tactic = tacticsForTechniquePrefix[base]
		}
		if tactic != "" && !seen[tactic] {
			seen[tactic] = true
			phases = append(phases, tactic)
		}
	}
	// Sort in kill-chain order
	order := map[string]int{
		"initial-access": 0, "execution": 1, "persistence": 2, "privilege-escalation": 3,
		"defense-evasion": 4, "credential-access": 5, "discovery": 6,
		"lateral-movement": 7, "collection": 8, "exfiltration": 9,
		"command-and-control": 10, "impact": 11,
	}
	sort.Slice(phases, func(i, j int) bool {
		return order[phases[i]] < order[phases[j]]
	})
	return phases
}
