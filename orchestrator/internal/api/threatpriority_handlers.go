package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/coverage"
	"github.com/audspect/bas/internal/reporting/attackdata"
	"github.com/audspect/bas/internal/threatpriority"
)

// GET /api/threat-priority/actors
// Ranked list of every actor with a threat_actor_profiles row, sorted Score
// desc then ActorName asc (same determinism convention as
// internal/recommend's sort). Distinct from GET /api/coverage/matrix
// (technique-level content existence) and GET /api/recommend/simulations
// (technique-level ranking) -- this is the actor-level view.
func (h *Handler) ThreatPriorityActors(w http.ResponseWriter, r *http.Request) {
	if h.threatPriorityEngine == nil {
		respond(w, []threatpriority.ActorPriority{})
		return
	}
	scores, err := h.threatPriorityEngine.ScoreAll(r.Context())
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, scores)
}

// TechniqueCoverage is one technique's coverage-breakdown row for a given
// actor -- what content exists for it, and what real outcomes (if any)
// have been recorded. See
// docs/superpowers/specs/2026-08-11-actor-coverage-breakdown-design.md.
// Deliberately never called "exposure" anywhere in this type or its
// fields -- that word already means two unrelated things elsewhere in this
// codebase (internal/analytics.FleetExposure, internal/predict.ExposureWindows).
type TechniqueCoverage struct {
	TechniqueID   string `json:"techniqueId"`
	TechniqueName string `json:"techniqueName,omitempty"`
	HasSimulation bool   `json:"hasSimulation"`
	HasDetection  bool   `json:"hasDetection"`
	HasCompliance bool   `json:"hasCompliance"`
	// PreventionVerdict / DetectionVerdict are independent -- a control
	// blocking an attack (prevention, from scenario_runs) and a stack
	// alerting on it (detection, from verification_history) answer
	// different questions. A technique can have one without the other.
	PreventionVerdict string `json:"preventionVerdict,omitempty"`
	DetectionVerdict  string `json:"detectionVerdict,omitempty"`
	// Status is derived, in priority order: "gap-no-content" (no
	// simulation/detection/compliance content at all) > "untested" (has
	// content, but neither verdict has ever been recorded) > "has-outcomes"
	// (has content and at least one verdict exists).
	Status string `json:"status"`
}

// buildTechniqueCoverage computes the per-technique coverage-breakdown row
// for each of an actor's techniques. Pure function -- sim/detect/compliant
// and prevention/validation are all already computed by the caller (the
// same indexes UncoveredTechniques already relies on, plus the two
// exported verdict loaders internal/correlation already uses this way).
// Coverage indexes are keyed by raw technique-ID casing (matching
// UncoveredTechniques' existing lookups); verdict maps are keyed uppercase
// (matching threatpriority.Engine.scoreActor's own established contract),
// so verdict lookups uppercase the id and coverage lookups don't.
func buildTechniqueCoverage(
	techIDs []string,
	sim, detect, compliant map[string]bool,
	prevention, validation map[string]threatpriority.VerdictEntry,
) []TechniqueCoverage {
	out := make([]TechniqueCoverage, 0, len(techIDs))
	for _, id := range techIDs {
		tc := TechniqueCoverage{
			TechniqueID:   id,
			HasSimulation: sim[id],
			HasDetection:  detect[id],
			HasCompliance: compliant[id],
		}
		if e := attackdata.Lookup(id); e != nil {
			tc.TechniqueName = e.Name
		}
		upper := strings.ToUpper(id)
		if v, ok := prevention[upper]; ok {
			tc.PreventionVerdict = v.Verdict
		}
		if v, ok := validation[upper]; ok {
			tc.DetectionVerdict = v.Verdict
		}
		switch {
		case !tc.HasSimulation && !tc.HasDetection && !tc.HasCompliance:
			tc.Status = "gap-no-content"
		case tc.PreventionVerdict == "" && tc.DetectionVerdict == "":
			tc.Status = "untested"
		default:
			tc.Status = "has-outcomes"
		}
		out = append(out, tc)
	}
	return out
}

// ActorSource is one source's own raw, pre-merge assertions about an actor
// -- what MISP/OpenCTI/OTX each individually said, before MergeActors
// flattened them into a single first-arrival-wins profile row. Aliases/
// Sectors/Regions are always non-nil so the UI can distinguish "this source
// reported none" from a missing field. See
// docs/superpowers/specs/2026-08-11-source-provenance-design.md.
type ActorSource struct {
	Source         string     `json:"source"`
	SourceID       string     `json:"sourceId,omitempty"`
	Name           string     `json:"name"`
	Aliases        []string   `json:"aliases"`
	Sectors        []string   `json:"sectors"`
	Regions        []string   `json:"regions"`
	Confidence     string     `json:"confidence,omitempty"`
	TechniqueCount int        `json:"techniqueCount"`
	LastSeen       *time.Time `json:"lastSeen,omitempty"`
}

// loadActorSources returns every source's own record for one canonical
// actor, source-ordered for stable rendering.
func loadActorSources(ctx context.Context, db *pgxpool.Pool, actorName string) ([]ActorSource, error) {
	if db == nil {
		return []ActorSource{}, nil
	}
	rows, err := db.Query(ctx,
		`SELECT source, source_id, name, aliases, sectors, regions, confidence, technique_count, last_seen
		   FROM threat_actor_sources WHERE actor_name = $1 ORDER BY source`, actorName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ActorSource{}
	for rows.Next() {
		var a ActorSource
		if err := rows.Scan(&a.Source, &a.SourceID, &a.Name, &a.Aliases, &a.Sectors,
			&a.Regions, &a.Confidence, &a.TechniqueCount, &a.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// threatPriorityActorDetail is the GET /api/threat-priority/actors/{name}
// response shape: the actor's ActorPriority plus history, the concrete
// list of uncovered techniques, and the full per-technique coverage
// breakdown (feeds the Actor Details "Techniques"/"Coverage" tabs).
type threatPriorityActorDetail struct {
	threatpriority.ActorPriority
	History             []threatpriority.ActorPriorityHistory `json:"history"`
	UncoveredTechniques []string                              `json:"uncoveredTechniques"`
	TechniqueCoverage   []TechniqueCoverage                   `json:"techniqueCoverage"`
	Sources             []ActorSource                         `json:"sources"`
}

// GET /api/threat-priority/actors/{name}
func (h *Handler) ThreatPriorityActorDetail(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if h.threatPriorityEngine == nil {
		respond(w, threatPriorityActorDetail{UncoveredTechniques: []string{}, TechniqueCoverage: []TechniqueCoverage{}, Sources: []ActorSource{}})
		return
	}
	ap, err := h.threatPriorityEngine.Score(r.Context(), name)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hist, err := h.threatPriorityEngine.History(r.Context(), name, 30)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	scenarios := h.engine.List()
	sim := coverage.BuildSimulationIndex(scenarios)
	detect := coverage.BuildProfileIndex(h.engine.Profiles())
	compliant := coverage.BuildComplianceIndex(scenarios)

	uncovered := []string{}
	for _, id := range ap.TechniqueIDs {
		if !sim[id] && !detect[id] && !compliant[id] {
			uncovered = append(uncovered, id)
		}
	}

	prevention, err := threatpriority.LoadPreventionVerdicts(r.Context(), h.db)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	validation, err := threatpriority.LoadValidationVerdicts(r.Context(), h.db)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	techCoverage := buildTechniqueCoverage(ap.TechniqueIDs, sim, detect, compliant, prevention, validation)

	sources, err := loadActorSources(r.Context(), h.db, name)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	respond(w, threatPriorityActorDetail{
		ActorPriority: ap, History: hist, UncoveredTechniques: uncovered, TechniqueCoverage: techCoverage,
		Sources: sources,
	})
}
