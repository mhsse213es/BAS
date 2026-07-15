package api

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/exposure"
	"github.com/audspect/bas/internal/pathcorrelation"
)

// buildAssetGraph is the shared setup both exposure endpoints use: builds
// the attack-path graph, runs SP3 Correlate, loads enrolled agents, and
// calls exposure.Build. Nil-safe throughout — never errors on a missing
// optional subsystem (h.rules, h.relationships), matching this API's
// established convention.
func (h *Handler) buildAssetGraph(r *http.Request) (*exposure.AssetGraph, error) {
	cols := h.loadAttackPathCollections(r)
	g, s := attackpath.BuildGraphAndAnalyze(cols, h.loadAssetTags(r))

	// h.rules is a *rulelib.Engine; a nil pointer passed directly into an
	// interface parameter would be a non-nil interface wrapping nil (Go's
	// typed-nil trap) — guard explicitly, same as pathcorrelation_handlers.go.
	var rules pathcorrelation.RuleLibrary
	if h.rules != nil {
		rules = h.rules
	}
	paths := pathcorrelation.DefaultPaths(g, s)
	corr, err := pathcorrelation.Correlate(
		r.Context(), g, s, paths,
		pathcorrelation.DefaultEdgeTechniqueMapper{},
		pathcorrelation.NewSQLRunLookup(h.db),
		rules,
	)
	if err != nil {
		return nil, err
	}

	var rels exposure.RelationshipLookup
	if h.relationships != nil {
		rels = h.relationships
	}

	agents, err := h.loadAgentRows(r.Context())
	if err != nil {
		return nil, err
	}

	return exposure.Build(r.Context(), g, s, corr, rels,
		exposure.NewSQLCVEEnricher(h.db), exposure.NewSQLFindingsLookup(h.db), agents)
}

func (h *Handler) loadAgentRows(ctx context.Context) ([]exposure.AgentRow, error) {
	rows, err := h.db.Query(ctx, `SELECT agent_id, hostname, ip_address, os_version FROM agents`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []exposure.AgentRow
	for rows.Next() {
		var a exposure.AgentRow
		if rows.Scan(&a.AgentID, &a.Hostname, &a.IP, &a.OS) != nil {
			continue
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetExposureAssets returns the fleet asset index — SP4. Read-only (Viewer+).
// GET /api/exposure/assets
func (h *Handler) GetExposureAssets(w http.ResponseWriter, r *http.Request) {
	ag, err := h.buildAssetGraph(r)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, ag.Summaries())
}

// GetExposureAsset returns one asset's full profile — SP4. Read-only (Viewer+).
// GET /api/exposure/assets/{hostKey}
func (h *Handler) GetExposureAsset(w http.ResponseWriter, r *http.Request) {
	ag, err := h.buildAssetGraph(r)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	key := attackpath.NormalizeHostKey(chi.URLParam(r, "hostKey"))
	profile, ok := ag.Profile(key)
	if !ok {
		jsonError(w, "asset not found", http.StatusNotFound)
		return
	}
	respond(w, profile)
}
