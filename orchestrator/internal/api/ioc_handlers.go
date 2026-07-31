package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/db"
)

// GetRunIOCs returns the indicators extracted from a run's results.
// GET /api/scenarios/runs/{runId}/iocs?type={ip|domain|url|hash|cve}&search={substring}
func (h *Handler) GetRunIOCs(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "runId")
	typeFilter := r.URL.Query().Get("type")
	search := r.URL.Query().Get("search")

	indicators, err := db.GetRunIOCs(r.Context(), h.db, runID, typeFilter, search)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, indicators)
}

type iocRow struct {
	ID                string    `json:"id"`
	Type              string    `json:"type"`
	Value             string    `json:"value"`
	Source            string    `json:"source"`
	Origin            string    `json:"origin"`
	Status            string    `json:"status"`
	FirstSeen         time.Time `json:"firstSeen"`
	LastSeen          time.Time `json:"lastSeen"`
	SightingCount     int       `json:"sightingCount"`
	Suppressed        bool      `json:"suppressed"`
	SuppressionReason string    `json:"suppressionReason"`
}

// GetIOCs is the cross-run IOC registry search (Phase 0+A of the IOC handling
// initiative): iocs/ioc_sightings, populated today from DetectionAlert
// command_line/process values, deduped globally by (type, value) with a
// sighting per observation. This is distinct from GetRunIOCs above, which
// scans one run's raw stdout/stderr/check text for ip/domain/url/hash/cve
// and never dedups across runs -- the two are complementary IOC sources, not
// duplicates, pending a later phase that may converge them.
// GET /api/iocs?type=&value=&scenarioId=&agentId=&limit= -- flat IOC search.
// Viewer+. Full timeline/correlation views are a later phase; this is a
// direct query over the iocs/ioc_sightings tables only.
func (h *Handler) GetIOCs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 50
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}

	query := `SELECT DISTINCT i.id, i.type, i.value, i.source, i.origin, i.status,
	                  i.first_seen, i.last_seen, i.sighting_count, i.suppressed, i.suppression_reason
	          FROM iocs i`
	var joins, where string
	var args []any

	if scenarioID := q.Get("scenarioId"); scenarioID != "" {
		joins = " JOIN ioc_sightings s ON s.ioc_id = i.id"
		args = append(args, scenarioID)
		where += " AND s.scenario_id = $" + strconv.Itoa(len(args))
	}
	if agentID := q.Get("agentId"); agentID != "" {
		if joins == "" {
			joins = " JOIN ioc_sightings s ON s.ioc_id = i.id"
		}
		args = append(args, agentID)
		where += " AND s.agent_id = $" + strconv.Itoa(len(args))
	}
	if iocType := q.Get("type"); iocType != "" {
		args = append(args, iocType)
		where += " AND i.type = $" + strconv.Itoa(len(args))
	}
	if value := q.Get("value"); value != "" {
		args = append(args, "%"+value+"%")
		where += " AND i.value ILIKE $" + strconv.Itoa(len(args))
	}
	if techniqueID := q.Get("techniqueId"); techniqueID != "" {
		if joins == "" {
			joins = " JOIN ioc_sightings s ON s.ioc_id = i.id"
		}
		args = append(args, techniqueID)
		where += " AND s.technique_id = $" + strconv.Itoa(len(args))
	}
	if source := q.Get("source"); source != "" {
		args = append(args, source)
		where += " AND i.source = $" + strconv.Itoa(len(args))
	}
	if origin := q.Get("origin"); origin != "" {
		args = append(args, origin)
		where += " AND i.origin = $" + strconv.Itoa(len(args))
	}
	if status := q.Get("status"); status != "" {
		args = append(args, status)
		where += " AND i.status = $" + strconv.Itoa(len(args))
	}
	if since := q.Get("since"); since != "" {
		args = append(args, since)
		where += " AND i.last_seen >= $" + strconv.Itoa(len(args))
	}
	if until := q.Get("until"); until != "" {
		args = append(args, until)
		where += " AND i.last_seen <= $" + strconv.Itoa(len(args))
	}

	query += joins + " WHERE true" + where + " ORDER BY i.last_seen DESC LIMIT " + strconv.Itoa(limit)

	rows, err := h.db.Query(r.Context(), query, args...)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	out := []iocRow{}
	for rows.Next() {
		var row iocRow
		if err := rows.Scan(&row.ID, &row.Type, &row.Value, &row.Source, &row.Origin,
			&row.Status, &row.FirstSeen, &row.LastSeen, &row.SightingCount,
			&row.Suppressed, &row.SuppressionReason); err != nil {
			continue
		}
		out = append(out, row)
	}
	respond(w, out)
}
