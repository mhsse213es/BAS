// Package openaev syncs scenario content from Filigran's OpenAEV (Adversary
// Emulation & Validation) platform into Audspect as a version-tracked content
// library. It does not execute synced scenarios — see
// docs/superpowers/specs/2026-07-15-openaev-connector-design.md.
package openaev

import (
	"context"
	"time"
)

// ScenarioRef is a lightweight listing entry from ContentProvider.List — cheap
// to fetch, used to decide which scenarios need a full Fetch this sync.
type ScenarioRef struct {
	ID            string
	Name          string
	SourceUpdated time.Time
}

// ContentProvider retrieves raw bundle bytes. It is transport-agnostic: a
// RESTProvider fetches over HTTP, a BundleProvider wraps an uploaded file —
// neither the Importer nor the Parser cares which.
type ContentProvider interface {
	Name() string
	List(ctx context.Context) ([]ScenarioRef, error)
	Fetch(ctx context.Context, id string) ([]byte, error)
}

// ParsedBundle is the decoded contents of one OpenAEV scenario export ZIP —
// only the fields this connector actually normalizes, not OpenAEV's full schema.
type ParsedBundle struct {
	ExportVersion int               `json:"export_version"`
	Scenario      ParsedScenario    `json:"scenario_information"`
	Objectives    []ParsedObjective `json:"scenario_objectives"`
	Injects       []ParsedInject    `json:"scenario_injects"`
	Tags          []ParsedTag       `json:"scenario_tags"`
	Variables     []ParsedVariable  `json:"scenario_variables"`

	// SourceType is not part of OpenAEV's wire format -- it is stamped by
	// ParseExerciseBundle ("exercise") and left as the zero value by
	// ParseBundle ("" -- Normalize treats this as "scenario"). Included with
	// a JSON tag (not json:"-") so it survives the exercise provider's
	// round-trip through marshalAsScenarioZip -> ParseBundle.
	SourceType string `json:"source_type,omitempty"`
}

type ParsedScenario struct {
	ID          string    `json:"scenario_id"`
	Name        string    `json:"scenario_name"`
	Description string    `json:"scenario_description"`
	Category    string    `json:"scenario_category"`
	Severity    string    `json:"scenario_severity"`
	UpdatedAt   time.Time `json:"scenario_updated_at"`
}

type ParsedObjective struct {
	ID          string `json:"objective_id"`
	Title       string `json:"objective_title"`
	Description string `json:"objective_description"`
}

type ParsedInject struct {
	ID             string                `json:"inject_id"`
	Title          string                `json:"inject_title"`
	AttackPatterns []ParsedAttackPattern `json:"inject_attack_patterns"`
}

type ParsedAttackPattern struct {
	ExternalID string   `json:"attack_pattern_external_id"`
	Name       string   `json:"attack_pattern_name"`
	Platforms  []string `json:"attack_pattern_platforms"`
}

type ParsedTag struct {
	Name string `json:"tag_name"`
}

type ParsedVariable struct {
	Key         string `json:"variable_key"`
	Description string `json:"variable_description"`
}

// Scenario is the normalized summary of one OpenAEV scenario — mirrors the
// openaev_scenarios table row. Kept separate from Detail so list views never
// touch the (potentially large) full bundle content.
// Every field carries an explicit json tag pinning its wire name to the exact
// Go identifier the frontend (and this package's own tests, via map[string]any
// assertions) already expect -- this build is compiled with garble, which
// renames unprotected struct fields, so an untagged field silently leaks a
// garbled identifier onto the wire instead of "Name"/"Category"/etc. (see
// docs/internal -- "Garble breaks reflection" is a known, established
// constraint on this codebase; every other JSON-serialized struct already
// follows it).
type Scenario struct {
	OpenAEVScenarioID string    `json:"OpenAEVScenarioID"`
	Name              string    `json:"Name"`
	Category          string    `json:"Category"`
	Severity          string    `json:"Severity"`
	Platforms         []string  `json:"Platforms"`
	TechniqueIDs      []string  `json:"TechniqueIDs"`
	Tags              []string  `json:"Tags"`
	ObjectivesCount   int       `json:"ObjectivesCount"`
	InjectsCount      int       `json:"InjectsCount"`
	SourceUpdatedAt   time.Time `json:"SourceUpdatedAt"`
	SourceType        string    `json:"SourceType"` // "scenario" or "exercise" -- see ParsedBundle.SourceType
}

// Detail is the richer normalized content stored in openaev_bundles.bundle —
// everything Scenario omits, kept even though nothing consumes it yet (the
// future Exercise Engine will).
type Detail struct {
	Description string            `json:"description"`
	Objectives  []DetailObjective `json:"objectives"`
	Injects     []DetailInject    `json:"injects"`
	Variables   []DetailVariable  `json:"variables"`
}

type DetailObjective struct {
	Title       string `json:"title"`
	Description string `json:"description"`
}

type DetailInject struct {
	Title        string   `json:"title"`
	TechniqueIDs []string `json:"techniqueIds"`
}

type DetailVariable struct {
	Key         string `json:"key"`
	Description string `json:"description"`
}
