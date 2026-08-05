package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/notifications"
)

// GetNotifications returns notification history, most-recent first.
// Query params: limit (default 100, max 500), offset, jobId, severity, type.
// GET /api/notifications
func (h *Handler) GetNotifications(w http.ResponseWriter, r *http.Request) {
	if h.notificationsStore == nil {
		respond(w, map[string]any{"notifications": []any{}})
		return
	}
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
	filter := notifications.ListFilter{
		JobID:    r.URL.Query().Get("jobId"),
		Severity: r.URL.Query().Get("severity"),
		Type:     r.URL.Query().Get("type"),
		Limit:    limit,
		Offset:   offset,
	}
	events, err := h.notificationsStore.List(r.Context(), filter)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"notifications": events})
}

// ── Webhook config CRUD (Admin only) ────────────────────────────────────────

// CreateNotificationWebhook creates a new outbound webhook config.
// POST /api/notification-webhooks  body: {name, url, secret, minSeverity, enabled}
func (h *Handler) CreateNotificationWebhook(w http.ResponseWriter, r *http.Request) {
	if h.notificationsStore == nil {
		jsonError(w, "notifications not loaded", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Name        string `json:"name"`
		URL         string `json:"url"`
		Secret      string `json:"secret"`
		MinSeverity string `json:"minSeverity"`
		Enabled     bool   `json:"enabled"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Name == "" || req.URL == "" {
		jsonError(w, "name and url are required", http.StatusBadRequest)
		return
	}
	validSev := map[string]bool{"info": true, "warning": true, "error": true, "critical": true}
	if req.MinSeverity == "" {
		req.MinSeverity = "warning"
	}
	if !validSev[req.MinSeverity] {
		jsonError(w, "minSeverity must be info | warning | error | critical", http.StatusBadRequest)
		return
	}
	id, err := h.notificationsStore.CreateWebhook(r.Context(), notifications.Webhook{
		Name: req.Name, URL: req.URL, Secret: req.Secret, MinSeverity: req.MinSeverity, Enabled: req.Enabled,
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "notifications.webhook_created", id, map[string]any{"name": req.Name}, "ok")
	respond(w, map[string]any{"id": id})
}

// ListNotificationWebhooks lists all configured webhooks with secrets redacted.
// GET /api/notification-webhooks
func (h *Handler) ListNotificationWebhooks(w http.ResponseWriter, r *http.Request) {
	if h.notificationsStore == nil {
		respond(w, map[string]any{"webhooks": []any{}})
		return
	}
	hooks, err := h.notificationsStore.ListWebhooks(r.Context())
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(hooks))
	for _, hook := range hooks {
		secret := ""
		if hook.Secret != "" {
			secret = "***"
		}
		out = append(out, map[string]any{
			"id": hook.ID, "name": hook.Name, "url": hook.URL, "secret": secret,
			"minSeverity": hook.MinSeverity, "enabled": hook.Enabled, "createdAt": hook.CreatedAt,
		})
	}
	respond(w, map[string]any{"webhooks": out})
}

// DeleteNotificationWebhook deletes a webhook config.
// DELETE /api/notification-webhooks/{id}
func (h *Handler) DeleteNotificationWebhook(w http.ResponseWriter, r *http.Request) {
	if h.notificationsStore == nil {
		jsonError(w, "notifications not loaded", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	if err := h.notificationsStore.DeleteWebhook(r.Context(), id); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "notifications.webhook_deleted", id, nil, "ok")
	respond(w, map[string]any{"id": id, "deleted": true})
}
