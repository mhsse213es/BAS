package connector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/scenario"
)

const minTechniques = 2 // minimum techniques before generating a scenario

// Registrar is the slice of the Content Registry the generator writes to.
type Registrar interface {
	RegisterGenerated(ctx context.Context, c contentregistry.GeneratedCandidate) (string, bool, error)
}

const (
	generatorName = "connector/generator"
	// 2 = registry-backed, deterministic YAML (TCF Phase 1).
	// 3 = yaml.Marshal encoding + sanitized, rune-capped intel text (final
	//     review I3). New bytes => a new DRAFT version of the same content id.
	generatorVersion = "3"
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
	Updated int // no longer set by the generator; kept for existing readers
	Skipped int
	// Changed counts working-copy files whose bytes differ from what was on
	// disk (new or rewritten), independent of the registry outcome. The
	// scheduler reloads the scenario engine when Changed > 0.
	Changed int
	// Failed counts candidates that were not registered or written (registry
	// error, source/origin collision, file write error).
	Failed int
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

		// Register first: the version (with its provenance snapshot) must exist
		// before the file does, so a concurrent engine.Load() intake dedups by
		// hash instead of creating the version without sources. On failure the
		// file is left unwritten and the next sync retries.
		created := false
		if g.registrar != nil {
			var err error
			_, created, err = g.registrar.RegisterGenerated(context.Background(), contentregistry.GeneratedCandidate{
				ContentID: id, Artifact: []byte(body), GenerationKey: generationKey(actor),
				Generation: map[string]any{"generator": generatorName, "generator_version": generatorVersion,
					"mapping_version": mappingVersion, "parameters": map[string]any{"min_techniques": minTechniques}},
				Sources: []contentregistry.SourceRef{{EntityType: "actor", EntityID: actor.Name, Provider: actor.Source,
					ExternalID: actor.SourceID, Role: "primary"}},
			})
			if err != nil {
				switch {
				case errors.Is(err, contentregistry.ErrSourceCollision):
					log.Printf("[connector/gen] %s (%s) collides with a custom scenario of the same id; not written: %v", id, actor.Name, err)
				case errors.Is(err, contentregistry.ErrOriginCollision):
					log.Printf("[connector/gen] %s (%s) collides with content of a different origin; not written: %v", id, actor.Name, err)
				default:
					log.Printf("[connector/gen] register %s: %v", id, err)
				}
				res.Failed++
				continue
			}
		}
		if old, err := os.ReadFile(fname); err != nil || !bytes.Equal(old, []byte(body)) {
			if err := os.WriteFile(fname, []byte(body), 0644); err != nil {
				log.Printf("[connector/gen] write %s: %v", fname, err)
				res.Failed++
				continue
			}
			res.Changed++
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

// intelScenarioYAML fixes the generated document's key order. Every value
// goes through yaml.Marshal, so external intel text (MISP/OpenCTI/OTX) is
// always a quoted/escaped scalar and can never add keys such as steps:.
type intelScenarioYAML struct {
	ID                string   `yaml:"id"`
	Name              string   `yaml:"name"`
	Description       string   `yaml:"description"`
	Author            string   `yaml:"author"`
	Tags              []string `yaml:"tags"`
	MITREPhases       []string `yaml:"mitre_phases"`
	IntelSource       string   `yaml:"intel_source"`
	IntelSourceID     string   `yaml:"intel_source_id"`
	IntelActor        string   `yaml:"intel_actor"`
	IntelConfidence   string   `yaml:"intel_confidence"`
	ARTTechniques     []string `yaml:"art_techniques"`
	DetectionProfiles []string `yaml:"detection_profiles,omitempty"`
}

// Rune caps for actor-derived display text.
const (
	maxIntelNameRunes        = 128
	maxIntelDescriptionRunes = 200
	maxIntelFieldRunes       = 128 // source, source id, confidence, sector, technique id, tactic
)

// sanitizeIntelText drops invalid UTF-8 and every control character
// (including CR, LF, NUL and ESC) from external intel text, trims it, and
// caps it at max runes -- never mid-rune. truncated reports a cut.
func sanitizeIntelText(s string, max int) (out string, truncated bool) {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	n := 0
	for i := range s {
		if n == max {
			return strings.TrimSpace(s[:i]), true
		}
		n++
	}
	return s, false
}

func cleanIntel(s string) string {
	out, _ := sanitizeIntelText(s, maxIntelFieldRunes)
	return out
}

// buildYAML renders the scenario YAML. It is deterministic: no wall-clock or
// last-seen values, so unchanged techniques/confidence give identical bytes.
func (g *Generator) buildYAML(actor ThreatActor, contentID string) string {
	name, _ := sanitizeIntelText(actor.Name, maxIntelNameRunes)
	source := cleanIntel(actor.Source)
	confidence := cleanIntel(actor.Confidence)

	// Collect unique technique IDs (already sorted)
	techIDs := []string{}
	for _, t := range dedupedTechniqueIDs(actor.Techniques) {
		techIDs = append(techIDs, cleanIntel(t))
	}

	// Derive MITRE phases from techniques (kill-chain ordered)
	phases := []string{}
	for _, p := range deriveMITREPhases(actor.Techniques) {
		phases = append(phases, cleanIntel(p))
	}

	// Tags
	tags := []string{"intel", "auto-generated", strings.ToLower(strings.ReplaceAll(name, " ", "-"))}
	for _, sec := range actor.Sectors {
		tags = append(tags, cleanIntel(sec))
	}
	if intersects(actor.Sectors, g.sectors) {
		tags = append(tags, "sector-relevant")
	}
	if intersects(actor.Regions, g.regions) {
		tags = append(tags, "region-relevant")
	}

	// Description
	description, cut := sanitizeIntelText(actor.Description, maxIntelDescriptionRunes)
	if description == "" {
		description, cut = sanitizeIntelText(fmt.Sprintf("%s threat actor profile.", name), maxIntelDescriptionRunes)
	}
	if cut {
		description += "..."
	}

	// Detection Profile Inheritance: attach any profile whose TechniqueIDs
	// exactly matches one of this actor's techniques.
	var detectionProfiles []string
	seenProfiles := make(map[string]bool)
	for _, id := range techIDs {
		if pn := resolveProfile(g.techniqueIdx, id); pn != "" && !seenProfiles[pn] {
			seenProfiles[pn] = true
			detectionProfiles = append(detectionProfiles, pn)
		}
	}
	sort.Strings(detectionProfiles)

	doc := intelScenarioYAML{
		ID:                contentID,
		Name:              name + " — Active Campaign (Intel)",
		Description:       fmt.Sprintf("Auto-generated from %s. %s Confidence: %s.", source, description, confidence),
		Author:            fmt.Sprintf("Threat Intel Connector (%s)", source),
		Tags:              tags,
		MITREPhases:       phases,
		IntelSource:       source,
		IntelSourceID:     cleanIntel(actor.SourceID),
		IntelActor:        name,
		IntelConfidence:   confidence,
		ARTTechniques:     techIDs,
		DetectionProfiles: detectionProfiles,
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		// Only strings and string slices: Encode cannot fail on this type.
		panic(fmt.Sprintf("connector/generator: encode %s: %v", contentID, err))
	}
	_ = enc.Close()
	return buf.String()
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
		if order[phases[i]] != order[phases[j]] {
			return order[phases[i]] < order[phases[j]]
		}
		return phases[i] < phases[j] // unknown tactics tie at 0: order by name, not input order
	})
	return phases
}
