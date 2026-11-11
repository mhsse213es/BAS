package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"

	"github.com/audspect/bas/internal/segprobe"
	"github.com/audspect/bas/internal/segprobe/runstore"
)

// Segmentation lab endpoints. Starting a run is admin only (it sends real
// traffic between lab zones). Reading runs is analyst and admin. Verdicts are
// returned exactly as stored; nothing here recomputes or softens them.

var segmentationRunIDRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// WithSegmentation attaches the lab service and its run store. A nil service
// leaves the run endpoints answering 503 (the lab is not configured).
func (h *Handler) WithSegmentation(svc *segprobe.Service, store *runstore.Store) *Handler {
	h.seg = svc
	h.segRuns = store
	return h
}

// ListSegmentationPacks returns the packs the lab can run. enabled is false
// when no lab is configured, so the console can say so instead of failing.
func (h *Handler) ListSegmentationPacks(w http.ResponseWriter, r *http.Request) {
	type packView struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	out := []packView{}
	for _, p := range segprobe.Packs() {
		out = append(out, packView{ID: p.ID, Name: p.Name, Description: p.Description})
	}
	// can_run lets the console show the Run control only to callers who hold the permission. The server
	// enforces it on the run route regardless.
	canRun := false
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		canRun = auth.HasPermission(c.Role, auth.CanRunSegmentation)
	}
	respond(w, map[string]any{"packs": out, "enabled": h.seg != nil, "can_run": canRun})
}

func (h *Handler) ListSegmentationRuns(w http.ResponseWriter, r *http.Request) {
	if h.segRuns == nil {
		jsonError(w, "segmentation lab is not configured on this server", http.StatusServiceUnavailable)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	runs, err := h.segRuns.List(r.Context(), limit)
	if err != nil {
		jsonError(w, "could not list segmentation runs", http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"runs": runs})
}

func (h *Handler) GetSegmentationRun(w http.ResponseWriter, r *http.Request) {
	if h.segRuns == nil {
		jsonError(w, "segmentation lab is not configured on this server", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	if !segmentationRunIDRE.MatchString(id) {
		jsonError(w, "segmentation run not found", http.StatusNotFound)
		return
	}
	run, probes, err := h.segRuns.Get(r.Context(), id)
	if errors.Is(err, runstore.ErrNotFound) {
		jsonError(w, "segmentation run not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "could not load segmentation run", http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"run": run, "probes": probes})
}

type segmentationRunBody struct {
	Pack string `json:"pack"`
}

// SubmitSegmentationRun starts a pack. The request is audited durably before
// anything runs: if the audit row cannot be written, no traffic is sent.
func (h *Handler) SubmitSegmentationRun(w http.ResponseWriter, r *http.Request) {
	if h.seg == nil {
		jsonError(w, "segmentation lab is not configured on this server", http.StatusServiceUnavailable)
		return
	}
	actor, ok := apibasActor(r)
	if !ok {
		jsonError(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	var b segmentationRunBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	if _, err := segprobe.LookupPack(b.Pack); err != nil {
		jsonError(w, "unknown segmentation pack", http.StatusBadRequest)
		return
	}
	if err := h.auditDurable(r.Context(), actor, "segmentation.run.request", "segmentation-pack:"+b.Pack,
		map[string]any{"pack": b.Pack}, "requested"); err != nil {
		jsonError(w, "could not record the request; no run was started", http.StatusInternalServerError)
		return
	}
	run, err := h.seg.Submit(r.Context(), b.Pack, actor)
	switch {
	case errors.Is(err, segprobe.ErrUnknownPack):
		jsonError(w, "unknown segmentation pack", http.StatusBadRequest)
		return
	case errors.Is(err, segprobe.ErrBusy):
		jsonError(w, "a segmentation run is already in progress", http.StatusConflict)
		return
	case err != nil:
		jsonError(w, "could not start the segmentation run", http.StatusInternalServerError)
		return
	}
	_ = h.auditDurable(r.Context(), actor, "segmentation.run.start", "segmentation-run:"+run.ID,
		map[string]any{"pack": b.Pack}, "success")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(run)
}
