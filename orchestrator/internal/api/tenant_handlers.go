package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// Tenant is one row from the tenants table.
type Tenant struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	Status    string `json:"status"`
	CreatedAt string `json:"createdAt"`
}

// CreateTenant provisions a new tenant. Platform-admin only.
// POST /api/tenants
func (h *Handler) CreateTenant(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.Slug == "" {
		jsonError(w, "name and slug are required", http.StatusBadRequest)
		return
	}
	var id string
	err := h.db.QueryRow(r.Context(),
		`INSERT INTO tenants (name, slug) VALUES ($1, $2) RETURNING id`,
		req.Name, req.Slug,
	).Scan(&id)
	if err != nil {
		if strings.Contains(err.Error(), "unique") {
			jsonError(w, "slug already exists", http.StatusConflict)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, Tenant{ID: id, Name: req.Name, Slug: req.Slug, Status: "active"})
}

// ListTenants returns every tenant. Platform-admin only.
// GET /api/tenants
func (h *Handler) ListTenants(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT id, name, slug, status, to_char(created_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') FROM tenants ORDER BY created_at ASC`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []Tenant{}
	for rows.Next() {
		var t Tenant
		if rows.Scan(&t.ID, &t.Name, &t.Slug, &t.Status, &t.CreatedAt) != nil {
			continue
		}
		out = append(out, t)
	}
	respond(w, out)
}

// UpdateTenant renames and/or suspends/reactivates a tenant. Platform-admin only.
// PATCH /api/tenants/{id}
func (h *Handler) UpdateTenant(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Name   *string `json:"name"`
		Status *string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Status != nil && *req.Status != "active" && *req.Status != "suspended" {
		jsonError(w, "status must be active or suspended", http.StatusBadRequest)
		return
	}
	if req.Name == nil && req.Status == nil {
		jsonError(w, "nothing to update", http.StatusBadRequest)
		return
	}
	tag, err := h.db.Exec(r.Context(),
		`UPDATE tenants SET name = COALESCE($2, name), status = COALESCE($3, status) WHERE id = $1`,
		id, req.Name, req.Status,
	)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if tag.RowsAffected() == 0 {
		jsonError(w, "tenant not found", http.StatusNotFound)
		return
	}
	respond(w, map[string]string{"status": "ok"})
}
