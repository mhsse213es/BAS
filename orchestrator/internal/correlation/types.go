// Package correlation turns Threat Intelligence, IOC Pipeline, Scenario
// Engine, and Detection Validation into one queryable correlation layer.
// Three layers: Relationship Discovery (threatgraph, reporting, scenario --
// finds raw facts, never normalizes), Canonical Resolution
// (resolveCanonicalTechnique, wrapping attackdata.Lookup -- the sole place
// technique identity is resolved), and Correlation Output (Engine's
// Correlate* methods -- assembles the first two layers and adds the one
// judgment call, Recommendation). See
// docs/superpowers/specs/2026-08-05-intelligence-correlation-engine-design.md.
package correlation

import (
	"time"

	"github.com/audspect/bas/internal/threatgraph"
)

// CanonicalTechnique is the Canonical Resolution layer's output -- the one
// place technique identity (name/description/platforms/tactics) is
// resolved. Every TechniqueCorrelation embeds one; nothing downstream
// re-derives these fields from relationship data. Sourced exclusively from
// attackdata.Lookup (the same authoritative ATT&CK bundle
// GET /api/attack/technique/{id} already serves) -- never inferred from
// threatgraph neighborhoods. See resolveCanonicalTechnique.
type CanonicalTechnique struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Platforms   []string `json:"platforms,omitempty"`
	Tactics     []string `json:"tactics,omitempty"`
	URL         string   `json:"url,omitempty"`
}

// ScenarioRef is a scenario's stable identity -- just enough to link to it,
// not a full scenario.Scenario copy.
type ScenarioRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ValidationStatus is nil when a technique has never been validated by
// either path (no scenario_runs result, no verification_history entry).
type ValidationStatus struct {
	Verdict string    `json:"verdict"` // e.g. "pass"/"fail" (prevention) or "Detected"/"NotDetected" (validation)
	Source  string    `json:"source"`  // "prevention" | "detection"
	At      time.Time `json:"at"`
}

// Recommendation is the one judgment call this package makes -- everything
// else is a fetched/joined relationship.
type Recommendation struct {
	Action string `json:"action"` // "run" | "revalidate" | "none" | "no_scenario"
	Reason string `json:"reason"` // human-readable, e.g. "Never validated" / "Last run 132 days ago, fail"
}

// TechniqueCorrelation is the full correlated view of one ATT&CK technique.
// Technique is always fully populated -- see resolveCanonicalTechnique. The
// only place this type is constructed is inside internal/correlation itself.
type TechniqueCorrelation struct {
	Technique      CanonicalTechnique `json:"technique"`
	Actors         []threatgraph.Node `json:"actors"`
	Campaigns      []threatgraph.Node `json:"campaigns"`
	Malware        []threatgraph.Node `json:"malware"`
	Tools          []threatgraph.Node `json:"tools"`
	Scenarios      []ScenarioRef      `json:"scenarios"`
	Validation     *ValidationStatus  `json:"validation,omitempty"`
	Recommendation Recommendation     `json:"recommendation"`
}

// ActorCorrelation is one actor's full technique roster, each individually
// correlated -- NOT aggregated into a coverage percentage. Aggregation
// (Threat Coverage Analysis) is a later phase's job, reading this data, not
// this phase's.
type ActorCorrelation struct {
	ActorName  string                  `json:"actorName"`
	Campaigns  []threatgraph.Node      `json:"campaigns"`
	Malware    []threatgraph.Node      `json:"malware"`
	Tools      []threatgraph.Node      `json:"tools"`
	Techniques []TechniqueCorrelation  `json:"techniques"`
}

// IOCCorrelation walks IOC -> technique(s) (via ioc_sightings, already
// real) -> actor(s)/scenario(s)/validation for each.
type IOCCorrelation struct {
	IOCID      string                 `json:"iocId"`
	Type       string                 `json:"type"`
	Value      string                 `json:"value"`
	Techniques []TechniqueCorrelation `json:"techniques"`
}
