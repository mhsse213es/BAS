package api

import (
	"net/http"

	"github.com/audspect/bas/internal/connector"
)

// GetIntelSkippedActors lists the threat actors whose LATEST generator record is a skip for having too few
// techniques, so the Threat-Intel category can explain why they have no scenario instead of leaving a gap that
// reads as missing intelligence. An actor drops off the list as soon as a later cycle generates content.
// GET /api/scenarios/intel-skipped
func (h *Handler) GetIntelSkippedActors(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT t.title, a.reason_code
		   FROM (SELECT DISTINCT ON (threat_id) threat_id, outcome, reason_code
		           FROM content_generation_attempts
		          WHERE threat_id IS NOT NULL
		          ORDER BY threat_id, started_at DESC, completed_at DESC) a
		   JOIN threats t ON t.id = a.threat_id AND t.subject_type = 'actor'
		  WHERE a.outcome = 'skipped' AND a.reason_code = 'below_min_techniques'
		  ORDER BY lower(t.title)`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type actor struct {
		Name   string `json:"name"`
		Reason string `json:"reason"`
	}
	actors := []actor{}
	for rows.Next() {
		var a actor
		if err := rows.Scan(&a.Name, &a.Reason); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		actors = append(actors, a)
	}
	if err := rows.Err(); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"minTechniques": connector.MinTechniques, "actors": actors})
}
