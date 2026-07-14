// orchestrator/internal/api/rulelib_handlers.go
package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/rulelib"
)

// ListRules returns every rule in the library.
// GET /api/rules
func (h *Handler) ListRules(w http.ResponseWriter, r *http.Request) {
	if h.rules == nil {
		respond(w, []rulelib.Rule{})
		return
	}
	respond(w, h.rules.Search(rulelib.SearchFilter{}))
}

// GetRule returns one rule's full content, including every translation.
// GET /api/rules/{id}
func (h *Handler) GetRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if h.rules == nil {
		jsonError(w, "rule not found", http.StatusNotFound)
		return
	}
	rule, ok := h.rules.RuleByID(id)
	if !ok {
		jsonError(w, "rule not found", http.StatusNotFound)
		return
	}
	respond(w, rule)
}

// SearchRules filters the library by any combination of technique, backend,
// status, severity, log source, and free-text title.
// GET /api/rules/search?technique=&backend=&status=&severity=&logsource=&q=
func (h *Handler) SearchRules(w http.ResponseWriter, r *http.Request) {
	if h.rules == nil {
		respond(w, []rulelib.Rule{})
		return
	}
	q := r.URL.Query()
	respond(w, h.rules.Search(rulelib.SearchFilter{
		Technique: q.Get("technique"),
		Backend:   q.Get("backend"),
		Status:    q.Get("status"),
		Severity:  q.Get("severity"),
		LogSource: q.Get("logsource"),
		Query:     q.Get("q"),
	}))
}

// RulesByTechnique is a convenience wrapper over Search for one technique ID.
// GET /api/rules/technique/{id}
func (h *Handler) RulesByTechnique(w http.ResponseWriter, r *http.Request) {
	techniqueID := chi.URLParam(r, "id")
	if h.rules == nil {
		respond(w, []rulelib.Rule{})
		return
	}
	respond(w, h.rules.RulesByTechnique(techniqueID))
}

// ExportRule returns one rule's content as raw text in the requested format.
// GET /api/rules/export?id=&format=sigma|kql|spl|lucene|logscale
func (h *Handler) ExportRule(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	format := r.URL.Query().Get("format")
	if h.rules == nil {
		jsonError(w, "rule not found", http.StatusNotFound)
		return
	}
	rule, ok := h.rules.RuleByID(id)
	if !ok {
		jsonError(w, "rule not found", http.StatusNotFound)
		return
	}

	var text string
	switch format {
	case "sigma", "":
		text = rule.Detection
	case "kql", "spl", "lucene", "logscale":
		backend := exportFormatToBackend(format)
		found := false
		for _, t := range rule.Translations {
			if t.Backend == backend {
				text = t.Query
				found = true
				break
			}
		}
		if !found {
			jsonError(w, "no "+format+" translation available for this rule", http.StatusNotFound)
			return
		}
	default:
		jsonError(w, "format must be one of sigma|kql|spl|lucene|logscale", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(text))
}

// exportFormatToBackend maps an export format query param to the backend
// key it corresponds to. kql is ambiguous between Sentinel and Defender XDR
// (both produce KQL) — this picks Sentinel; a caller wanting Defender XDR's
// KQL specifically should use GetRule and read Translations directly.
func exportFormatToBackend(format string) string {
	switch format {
	case "kql":
		return "microsoft_sentinel"
	case "spl":
		return "splunk"
	case "lucene":
		return "elastic"
	case "logscale":
		return "crowdstrike"
	default:
		return ""
	}
}
