package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/contentregistry"
)

func (h *Handler) registry(w http.ResponseWriter) (*contentregistry.Registry, bool) {
	var reg *contentregistry.Registry
	if h.engine != nil {
		reg, _ = h.engine.Registry().(*contentregistry.Registry)
	}
	if reg == nil {
		jsonError(w, "content registry unavailable", http.StatusServiceUnavailable)
		return nil, false
	}
	return reg, true
}

// GET /api/content-registry/content/{id}/versions
func (h *Handler) ListContentVersions(w http.ResponseWriter, r *http.Request) {
	reg, ok := h.registry(w)
	if !ok {
		return
	}
	vs, err := reg.ListVersions(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	type row struct {
		ID        string `json:"id"`
		Version   int    `json:"version"`
		Origin    string `json:"origin"`
		Trust     string `json:"trust"`
		Lifecycle string `json:"lifecycle"`
		SHA256    string `json:"artifactSha256"`
		CreatedBy string `json:"createdBy"`
		CreatedAt string `json:"createdAt"`
	}
	out := make([]row, 0, len(vs))
	for _, v := range vs {
		out = append(out, row{v.ID, v.Number, string(v.Origin), string(v.Trust), string(v.Lifecycle), v.SHA256, v.CreatedBy, v.CreatedAt.UTC().Format(time.RFC3339)})
	}
	respond(w, out)
}

// GET /api/content-registry/versions/{vid}
func (h *Handler) GetContentVersion(w http.ResponseWriter, r *http.Request) {
	reg, ok := h.registry(w)
	if !ok {
		return
	}
	d, err := reg.VersionDetail(r.Context(), chi.URLParam(r, "vid"))
	if errors.Is(err, contentregistry.ErrVersionNotFound) {
		jsonError(w, "content version not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, d)
}

// GET /api/content-registry/versions/{vid}/artifact -- exact stored bytes.
// The bytes are attacker-influenced (generated from external intel), so they
// are served as an inert plain-text download, never as renderable content.
func (h *Handler) GetContentArtifact(w http.ResponseWriter, r *http.Request) {
	reg, ok := h.registry(w)
	if !ok {
		return
	}
	v, err := reg.LoadVersion(r.Context(), chi.URLParam(r, "vid"))
	if errors.Is(err, contentregistry.ErrVersionNotFound) {
		jsonError(w, "content version not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", `attachment; filename="`+v.ID+`.yaml"`)
	w.Header().Set("X-Artifact-SHA256", v.SHA256)
	_, _ = w.Write(v.Artifact)
}

// POST /api/content-registry/versions/{vid}/transition {to, reason}
// The actor is derived from the authenticated claims only; the request body
// is never consulted for identity. All lifecycle rules live in
// Registry.Transition; this handler adds no bypass.
func (h *Handler) TransitionContentVersion(w http.ResponseWriter, r *http.Request) {
	reg, ok := h.registry(w)
	if !ok {
		return
	}
	var req struct {
		To     string `json:"to"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil || req.To == "" {
		jsonError(w, "body must be {to, reason}", http.StatusBadRequest)
		return
	}
	vid := chi.URLParam(r, "vid")
	err := reg.Transition(r.Context(), vid, contentregistry.Lifecycle(req.To), actorFor(r), req.Reason)
	var illegal *contentregistry.ErrIllegalTransition
	switch {
	case errors.Is(err, contentregistry.ErrVersionNotFound):
		jsonError(w, "content version not found", http.StatusNotFound)
		return
	case errors.As(err, &illegal):
		jsonError(w, err.Error(), http.StatusConflict)
		return
	case err != nil:
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "content_registry.transition", vid, map[string]any{"to": req.To, "reason": req.Reason}, "ok")
	d, err := reg.VersionDetail(r.Context(), vid)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, d)
}

// GET /api/content-registry/runs/{runId}/drift
func (h *Handler) GetRunDrift(w http.ResponseWriter, r *http.Request) {
	rep, err := h.checkRunDrift(r.Context(), chi.URLParam(r, "runId"))
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, rep)
}

// GET /api/content-registry/runs/{runId}/content -- provenance badge data.
// A transiently unreadable run (infrastructure failure) is a 500, never a
// permanent "unreadable" verdict.
func (h *Handler) GetRunContent(w http.ResponseWriter, r *http.Request) {
	rc := h.runContent(r.Context(), chi.URLParam(r, "runId"))
	if rc.Status == contentregistry.RunUnreadable && rc.Transient {
		jsonError(w, "run content temporarily unavailable", http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"status": rc.Status, "label": rc.Label(), "contentId": rc.ContentID,
		"version": rc.Version, "versionId": rc.VersionID, "trust": rc.Trust, "lifecycle": rc.Lifecycle})
}

// GET /api/content-registry/migration-report -- the stored one-time
// inventory plus the live blocked-schedule list (audit-free, safe to poll).
func (h *Handler) GetContentMigrationReport(w http.ResponseWriter, r *http.Request) {
	reg, ok := h.registry(w)
	if !ok {
		return
	}
	inv, done, err := reg.MigrationInventory(r.Context())
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	blocked, err := reg.BlockedSchedules(r.Context())
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"migrated": done, "inventory": inv, "blockedSchedules": blocked})
}
