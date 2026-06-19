package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/integrity"
)

// TamperEvent is the API representation of a tamper_events row.
type TamperEvent struct {
	ID           string     `json:"id"`
	DetectedAt   time.Time  `json:"detectedAt"`
	Path         string     `json:"path"`
	EventType    string     `json:"eventType"`
	Severity     string     `json:"severity"`
	Acknowledged bool       `json:"acknowledged"`
	AckedBy      string     `json:"ackedBy,omitempty"`
	AckedAt      *time.Time `json:"ackedAt,omitempty"`
}

// GetTamperEvents returns the last 100 tamper events, most recent first.
// Query param: ?unacknowledged=true to filter to unacknowledged only.
func (h *Handler) GetTamperEvents(w http.ResponseWriter, r *http.Request) {
	unackOnly := r.URL.Query().Get("unacknowledged") == "true"

	var rows []TamperEvent
	var err error

	if unackOnly {
		dbRows, dbErr := h.db.Query(r.Context(), `
			SELECT id, detected_at, path, event_type, severity,
			       acknowledged,
			       COALESCE(acked_by, ''),
			       acked_at
			FROM tamper_events
			WHERE acknowledged = false
			ORDER BY detected_at DESC
			LIMIT 100
		`)
		err = dbErr
		if err == nil {
			defer dbRows.Close()
			for dbRows.Next() {
				var e TamperEvent
				var ackedBy string
				var ackedAt *time.Time
				if scanErr := dbRows.Scan(&e.ID, &e.DetectedAt, &e.Path, &e.EventType,
					&e.Severity, &e.Acknowledged, &ackedBy, &ackedAt); scanErr != nil {
					continue
				}
				if ackedBy != "" {
					e.AckedBy = ackedBy
				}
				e.AckedAt = ackedAt
				rows = append(rows, e)
			}
		}
	} else {
		dbRows, dbErr := h.db.Query(r.Context(), `
			SELECT id, detected_at, path, event_type, severity,
			       acknowledged,
			       COALESCE(acked_by, ''),
			       acked_at
			FROM tamper_events
			ORDER BY detected_at DESC
			LIMIT 100
		`)
		err = dbErr
		if err == nil {
			defer dbRows.Close()
			for dbRows.Next() {
				var e TamperEvent
				var ackedBy string
				var ackedAt *time.Time
				if scanErr := dbRows.Scan(&e.ID, &e.DetectedAt, &e.Path, &e.EventType,
					&e.Severity, &e.Acknowledged, &ackedBy, &ackedAt); scanErr != nil {
					continue
				}
				if ackedBy != "" {
					e.AckedBy = ackedBy
				}
				e.AckedAt = ackedAt
				rows = append(rows, e)
			}
		}
	}

	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	if rows == nil {
		rows = []TamperEvent{} // return [] not null
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rows)
}

// AcknowledgeTamperEvent marks a single tamper event as acknowledged by the
// current admin user. Also clears DispatchBlocked if no more critical events remain.
func (h *Handler) AcknowledgeTamperEvent(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	userID := ""
	if claims, ok := auth.ClaimsFrom(r.Context()); ok {
		userID = claims.UserID
	}

	_, err := h.db.Exec(r.Context(), `
		UPDATE tamper_events
		SET acknowledged = true, acked_by = $1, acked_at = NOW()
		WHERE id = $2
	`, userID, id)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	// Re-enable dispatch if no unacknowledged critical events remain.
	var count int
	_ = h.db.QueryRow(r.Context(), `
		SELECT COUNT(*) FROM tamper_events
		WHERE acknowledged = false AND severity = 'critical'
	`).Scan(&count)
	if count == 0 {
		integrity.DispatchBlocked.Store(false)
	}

	h.auditLog(r, "tamper.acknowledge", id, nil, "ok")
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}

// AcknowledgeAllTamperEvents marks every unacknowledged tamper event as acknowledged.
func (h *Handler) AcknowledgeAllTamperEvents(w http.ResponseWriter, r *http.Request) {
	userID := ""
	if claims, ok := auth.ClaimsFrom(r.Context()); ok {
		userID = claims.UserID
	}
	_, err := h.db.Exec(r.Context(), `
		UPDATE tamper_events
		SET acknowledged = true, acked_by = $1, acked_at = NOW()
		WHERE acknowledged = false
	`, userID)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "tamper.acknowledge_all", "", nil, "ok")
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}
