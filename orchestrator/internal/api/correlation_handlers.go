package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/correlation"
)

// CorrelateTechnique returns the full correlated view of one ATT&CK
// technique -- actors/campaigns/malware/tools that use it, scenarios that
// cover it, its current validation status, and a recommendation.
// GET /api/correlation/technique/{id}
func (h *Handler) CorrelateTechnique(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if h.correlationEngine == nil {
		respond(w, correlation.TechniqueCorrelation{Technique: correlation.CanonicalTechnique{ID: id, Name: id}})
		return
	}
	tc, err := h.correlationEngine.CorrelateTechnique(r.Context(), id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, tc)
}

// CorrelateActor returns one actor's full, individually-correlated
// technique roster plus actor-level campaign/malware/tool relationships.
// GET /api/correlation/actor/{name}
func (h *Handler) CorrelateActor(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if h.correlationEngine == nil {
		respond(w, correlation.ActorCorrelation{ActorName: name})
		return
	}
	ac, err := h.correlationEngine.CorrelateActor(r.Context(), name)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, ac)
}

// CorrelateIOC returns an IOC's own identity plus every technique it's been
// sighted alongside, each individually correlated.
// GET /api/correlation/ioc/{id}
func (h *Handler) CorrelateIOC(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if h.correlationEngine == nil {
		respond(w, correlation.IOCCorrelation{IOCID: id})
		return
	}
	ic, err := h.correlationEngine.CorrelateIOC(r.Context(), id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, ic)
}
