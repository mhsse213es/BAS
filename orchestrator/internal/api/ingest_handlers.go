package api

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/audspect/bas/internal/ingest"
)

// validateIngestAuth checks the Authorization: Bearer <key> header against
// h.ingestAPIKey. Unlike validateAgentAuth, an unconfigured key means the
// endpoint is disabled, not open -- IngestEvents checks h.ingestAPIKey == ""
// itself and returns 404 before this is ever called with an empty key.
func (h *Handler) validateIngestAuth(r *http.Request) bool {
	provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return subtle.ConstantTimeCompare([]byte(provided), []byte(h.ingestAPIKey)) == 1
}

// IngestEvents handles POST /api/ingest/v1/events, the generic inbound
// detection/evidence ingestion endpoint for a customer's own SIEM/SOAR/ITSM
// tooling (see internal/ingest's package doc for the architecture note on
// why there is no tenant concept here). A malformed or unauthenticated
// request fails the whole call; an individual event's own validation
// failure (missing field, unknown ioc type) is reported per-event in the
// 200 response instead, since one bad event in a batch shouldn't force the
// caller to resubmit the rest.
func (h *Handler) IngestEvents(w http.ResponseWriter, r *http.Request) {
	if h.ingestAPIKey == "" {
		http.NotFound(w, r)
		return
	}
	if !h.validateIngestAuth(r) {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req ingest.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.SchemaVersion != 1 {
		jsonError(w, "unsupported schema_version (only 1 is supported)", http.StatusBadRequest)
		return
	}

	results := make([]ingest.EventResult, 0, len(req.Events))
	for _, ev := range req.Events {
		result, err := ingest.ProcessEvent(r.Context(), h.db, ev)
		if err != nil {
			h.auditLog(r, "ingest.events", "ingest", map[string]any{
				"source": ev.Source, "externalEventId": ev.ExternalEventID, "error": err.Error(),
			}, "error")
			jsonError(w, "internal error processing event batch", http.StatusInternalServerError)
			return
		}
		results = append(results, result)
	}

	h.auditLog(r, "ingest.events", "ingest", map[string]any{"count": len(results)}, "success")
	jsonOK(w, map[string]any{"results": results})
}
