package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/audspect/bas/internal/auth"
)

// AuditEntry is the wire type returned by GET /api/audit-logs.
type AuditEntry struct {
	ID        int64           `json:"id"`
	Ts        time.Time       `json:"ts"`
	ActorID   string          `json:"actorId"`
	ActorName string          `json:"actorName"`
	Action    string          `json:"action"`
	Resource  string          `json:"resource"`
	Detail    json.RawMessage `json:"detail"`
	IP        string          `json:"ip"`
	Outcome   string          `json:"outcome"`
}

// auditLogAs records a user action with an explicit actorID. Use this when the
// actor is known but no JWT context exists yet (e.g. the Login handler).
func (h *Handler) auditLogAs(r *http.Request, actorID, action, resource string, detail map[string]any, outcome string) {
	ip := r.Header.Get("X-Real-IP")
	if ip == "" {
		ip = r.RemoteAddr
	}
	detailJSON := []byte("{}")
	if detail != nil {
		if b, err := json.Marshal(detail); err == nil {
			detailJSON = b
		}
	}
	go func() {
		_, _ = h.db.Exec(context.Background(),
			`INSERT INTO audit_logs (actor_id, action, resource, detail, ip, outcome)
			 VALUES ($1,$2,$3,$4,$5,$6)`,
			actorID, action, resource, detailJSON, ip, outcome)
	}()
}

// auditLog records a user action asynchronously (fire-and-forget). Actor ID is
// read from the JWT context. Use auditLogAs when no JWT context exists.
func (h *Handler) auditLog(r *http.Request, action, resource string, detail map[string]any, outcome string) {
	actorID := ""
	if claims, ok := auth.ClaimsFrom(r.Context()); ok {
		actorID = claims.UserID
	}
	h.auditLogAs(r, actorID, action, resource, detail, outcome)
}

// AuditLogSystem records a system/startup-time event with no HTTP request
// in scope (e.g. main.go detecting BAS_LEGACY_LISTENER_ENABLED=false at
// boot) -- auditLogAs above requires *http.Request (it reads r.Header and
// r.RemoteAddr unconditionally, so passing nil would panic), which no
// startup-time caller has. Exported: cmd/server/main.go (package main)
// calls this directly at startup, matching the existing cross-package
// convention (ReapNeverStartedRuns, StartRevalidationLoop, etc). actor_id
// is left empty; GetAuditLogs' existing query already renders an empty
// actor_id as "system" (COALESCE(u.username, CASE WHEN a.actor_id=”
// THEN 'system' ...)), so this needs no new display-side handling.
func (h *Handler) AuditLogSystem(ctx context.Context, action, resource string, detail map[string]any, outcome string) {
	detailJSON := []byte("{}")
	if detail != nil {
		if b, err := json.Marshal(detail); err == nil {
			detailJSON = b
		}
	}
	go func() {
		_, _ = h.db.Exec(context.Background(),
			`INSERT INTO audit_logs (actor_id, action, resource, detail, ip, outcome)
			 VALUES ('', $1, $2, $3, '', $4)`,
			action, resource, detailJSON, outcome)
	}()
}

// GetAuditLogs returns audit log entries, most-recent first. Admin only.
// Query params: limit (default 100, max 500), offset, action, actor (username).
// GET /api/audit-logs
func (h *Handler) GetAuditLogs(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	offset := 0
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	actionFilter := r.URL.Query().Get("action")
	actorFilter := r.URL.Query().Get("actor") // username substring

	// Build dynamic WHERE clauses.
	where := "WHERE 1=1"
	args := []any{}
	argc := 1
	if actionFilter != "" {
		where += " AND a.action = $" + strconv.Itoa(argc)
		args = append(args, actionFilter)
		argc++
	}
	if actorFilter != "" {
		where += " AND u.username ILIKE $" + strconv.Itoa(argc)
		args = append(args, "%"+actorFilter+"%")
		argc++
	}
	args = append(args, limit, offset)

	q := `SELECT a.id, a.ts, a.actor_id,
	             COALESCE(u.username, CASE WHEN a.actor_id='' THEN 'system' ELSE a.actor_id END) AS actor_name,
	             a.action, a.resource, a.detail, a.ip, a.outcome
	      FROM audit_logs a
	      LEFT JOIN users u ON u.id = a.actor_id
	      ` + where + `
	      ORDER BY a.ts DESC
	      LIMIT $` + strconv.Itoa(argc) + ` OFFSET $` + strconv.Itoa(argc+1)

	rows, err := h.db.Query(r.Context(), q, args...)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	entries := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		var detail []byte
		if err := rows.Scan(&e.ID, &e.Ts, &e.ActorID, &e.ActorName,
			&e.Action, &e.Resource, &detail, &e.IP, &e.Outcome); err != nil {
			continue
		}
		e.Detail = json.RawMessage(detail)
		entries = append(entries, e)
	}
	respond(w, map[string]any{"entries": entries, "limit": limit, "offset": offset})
}
