package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/scim"
)

func scimErrorResponse(w http.ResponseWriter, detail string, status int) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(scim.Error{
		Schemas: []string{scim.SchemaError},
		Status:  strconv.Itoa(status),
		Detail:  detail,
	})
}

func scimRespond(w http.ResponseWriter, v any, status int) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// SCIMServiceProviderConfig — GET /scim/v2/ServiceProviderConfig. Fetched
// by IdPs during SCIM app setup; they refuse to proceed without it.
func (h *Handler) SCIMServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	scimRespond(w, scim.ServiceProviderConfig{
		Schemas:        []string{scim.SchemaServiceProviderConfig},
		Patch:          scim.Supported{Supported: true},
		Bulk:           scim.BulkSupported{Supported: false},
		Filter:         scim.FilterSupported{Supported: true, MaxResults: 200},
		ChangePassword: scim.Supported{Supported: false},
		Sort:           scim.Supported{Supported: false},
		ETag:           scim.Supported{Supported: false},
	}, http.StatusOK)
}

// SCIMResourceTypes — GET /scim/v2/ResourceTypes.
func (h *Handler) SCIMResourceTypes(w http.ResponseWriter, r *http.Request) {
	scimRespond(w, []scim.ResourceType{{
		Schemas:     []string{scim.SchemaResourceType},
		ID:          "User",
		Name:        "User",
		Endpoint:    "/Users",
		Description: "Audspect user account",
		Schema:      scim.SchemaUser,
	}}, http.StatusOK)
}

// SCIMSchemas — GET /scim/v2/Schemas.
func (h *Handler) SCIMSchemas(w http.ResponseWriter, r *http.Request) {
	scimRespond(w, []scim.Schema{{
		Schemas:     []string{scim.SchemaSchema},
		ID:          scim.SchemaUser,
		Name:        "User",
		Description: "Audspect user account",
		Attributes: []scim.SchemaAttribute{
			{Name: "userName", Type: "string", Required: true, Mutability: "readWrite", Returned: "default", Uniqueness: "server"},
			{Name: "active", Type: "boolean", Mutability: "readWrite", Returned: "default", Uniqueness: "none"},
			{Name: "emails", Type: "complex", MultiValued: true, Mutability: "readWrite", Returned: "default", Uniqueness: "none"},
		},
	}}, http.StatusOK)
}

// SCIMCreateUser — POST /scim/v2/Users.
func (h *Handler) SCIMCreateUser(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := scimTenantFrom(r.Context())
	if !ok {
		scimErrorResponse(w, "no tenant context", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		scimErrorResponse(w, "invalid body", http.StatusBadRequest)
		return
	}
	var in scim.IncomingUser
	if err := json.Unmarshal(body, &in); err != nil || in.UserName == "" {
		scimErrorResponse(w, "userName is required", http.StatusBadRequest)
		return
	}
	var defaultRole string
	if err := h.db.QueryRow(r.Context(), `SELECT default_role FROM scim_configs WHERE tenant_id=$1`, tenantID).Scan(&defaultRole); err != nil {
		scimErrorResponse(w, "SCIM not configured for this tenant", http.StatusInternalServerError)
		return
	}
	placeholder, hErr := auth.HashPassword(randomSSOPlaceholder())
	if hErr != nil {
		scimErrorResponse(w, "internal error", http.StatusInternalServerError)
		return
	}
	var id, createdAt string
	err = h.db.QueryRow(r.Context(),
		`INSERT INTO users (username, password_hash, role, tenant_id, auth_source, is_active)
		 VALUES ($1,$2,$3,$4,'sso',$5) RETURNING id, to_char(created_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"')`,
		in.UserName, placeholder, defaultRole, tenantID, in.ActiveOrDefault(),
	).Scan(&id, &createdAt)
	if err != nil {
		if strings.Contains(err.Error(), "unique") {
			scimErrorResponse(w, "a user with this userName already exists", http.StatusConflict)
			return
		}
		scimErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "scim.user_provisioned", id, map[string]any{"username": in.UserName, "tenantId": tenantID}, "ok")
	scimRespond(w, scim.FromUserRow(scim.UserRow{
		ID: id, Username: in.UserName, Active: in.ActiveOrDefault(), CreatedAt: createdAt, UpdatedAt: createdAt,
	}), http.StatusCreated)
}

// SCIMListUsers — GET /scim/v2/Users. Supports the one filter shape
// (userName eq "value") and startIndex/count pagination.
func (h *Handler) SCIMListUsers(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := scimTenantFrom(r.Context())
	if !ok {
		scimErrorResponse(w, "no tenant context", http.StatusUnauthorized)
		return
	}
	q := r.URL.Query()
	startIndex := 1
	if v, err := strconv.Atoi(q.Get("startIndex")); err == nil && v > 0 {
		startIndex = v
	}
	count := 100
	if v, err := strconv.Atoi(q.Get("count")); err == nil && v > 0 {
		count = v
	}
	usernameFilter, err := scim.ParseUserNameFilter(q.Get("filter"))
	if err != nil {
		scimErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	var total int
	h.db.QueryRow(r.Context(),
		`SELECT COUNT(*) FROM users WHERE tenant_id=$1 AND ($2 = '' OR username = $2)`,
		tenantID, usernameFilter).Scan(&total)

	rows, err := h.db.Query(r.Context(),
		`SELECT id, username, is_active, to_char(created_at,'YYYY-MM-DD"T"HH24:MI:SS"Z"')
		   FROM users WHERE tenant_id=$1 AND ($2 = '' OR username = $2)
		  ORDER BY created_at ASC OFFSET $3 LIMIT $4`,
		tenantID, usernameFilter, startIndex-1, count)
	if err != nil {
		scimErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	resources := []scim.User{}
	for rows.Next() {
		var row scim.UserRow
		if rows.Scan(&row.ID, &row.Username, &row.Active, &row.CreatedAt) != nil {
			continue
		}
		row.UpdatedAt = row.CreatedAt
		resources = append(resources, scim.FromUserRow(row))
	}
	scimRespond(w, scim.ListResponse{
		Schemas:      []string{scim.SchemaListResponse},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: len(resources),
		Resources:    resources,
	}, http.StatusOK)
}

// loadSCIMUserRow reads one users row for the SCIM wire shape. The users
// table has no updated_at column (only created_at/last_login), so
// UpdatedAt is set from created_at too — the same convention
// SCIMCreateUser's response already uses for a freshly created row.
func (h *Handler) loadSCIMUserRow(r *http.Request, id, tenantID string) (*scim.UserRow, error) {
	var row scim.UserRow
	err := h.db.QueryRow(r.Context(),
		`SELECT id, username, is_active, to_char(created_at,'YYYY-MM-DD"T"HH24:MI:SS"Z"')
		   FROM users WHERE id=$1 AND tenant_id=$2`, id, tenantID,
	).Scan(&row.ID, &row.Username, &row.Active, &row.CreatedAt)
	if err != nil {
		return nil, err
	}
	row.UpdatedAt = row.CreatedAt
	return &row, nil
}

// SCIMGetUser — GET /scim/v2/Users/{id}.
func (h *Handler) SCIMGetUser(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := scimTenantFrom(r.Context())
	if !ok {
		scimErrorResponse(w, "no tenant context", http.StatusUnauthorized)
		return
	}
	row, err := h.loadSCIMUserRow(r, chi.URLParam(r, "id"), tenantID)
	if err != nil {
		scimErrorResponse(w, "User not found", http.StatusNotFound)
		return
	}
	scimRespond(w, scim.FromUserRow(*row), http.StatusOK)
}

// SCIMReplaceUser — PUT /scim/v2/Users/{id}.
func (h *Handler) SCIMReplaceUser(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := scimTenantFrom(r.Context())
	if !ok {
		scimErrorResponse(w, "no tenant context", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		scimErrorResponse(w, "invalid body", http.StatusBadRequest)
		return
	}
	var in scim.IncomingUser
	if err := json.Unmarshal(body, &in); err != nil || in.UserName == "" {
		scimErrorResponse(w, "userName is required", http.StatusBadRequest)
		return
	}
	ct, err := h.db.Exec(r.Context(),
		`UPDATE users SET username=$1, is_active=$2 WHERE id=$3 AND tenant_id=$4`,
		in.UserName, in.ActiveOrDefault(), id, tenantID)
	if err != nil {
		if strings.Contains(err.Error(), "unique") {
			scimErrorResponse(w, "a user with this userName already exists", http.StatusConflict)
			return
		}
		scimErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		scimErrorResponse(w, "User not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "scim.user_replaced", id, nil, "ok")
	row, err := h.loadSCIMUserRow(r, id, tenantID)
	if err != nil {
		scimErrorResponse(w, "User not found", http.StatusNotFound)
		return
	}
	scimRespond(w, scim.FromUserRow(*row), http.StatusOK)
}

// SCIMPatchUser — PATCH /scim/v2/Users/{id}. Only an active:true/false
// operation is supported — the only PATCH real IdPs send for a
// Users-only sync.
func (h *Handler) SCIMPatchUser(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := scimTenantFrom(r.Context())
	if !ok {
		scimErrorResponse(w, "no tenant context", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		scimErrorResponse(w, "invalid body", http.StatusBadRequest)
		return
	}
	active, found, err := scim.ParsePatchActive(body)
	if err != nil {
		scimErrorResponse(w, "invalid PatchOp body", http.StatusBadRequest)
		return
	}
	if !found {
		scimErrorResponse(w, "only an active operation is supported", http.StatusBadRequest)
		return
	}
	ct, err := h.db.Exec(r.Context(), `UPDATE users SET is_active=$1 WHERE id=$2 AND tenant_id=$3`, active, id, tenantID)
	if err != nil {
		scimErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		scimErrorResponse(w, "User not found", http.StatusNotFound)
		return
	}
	action := "scim.user_deactivated"
	if active {
		action = "scim.user_reactivated"
	}
	h.auditLog(r, action, id, nil, "ok")
	row, err := h.loadSCIMUserRow(r, id, tenantID)
	if err != nil {
		scimErrorResponse(w, "User not found", http.StatusNotFound)
		return
	}
	scimRespond(w, scim.FromUserRow(*row), http.StatusOK)
}

// SCIMDeleteUser — DELETE /scim/v2/Users/{id}. Soft-deactivates only
// (is_active=false) — never removes the row. Too many tables
// (audit_logs, scenario_runs, findings, campaigns) reference users.id.
func (h *Handler) SCIMDeleteUser(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := scimTenantFrom(r.Context())
	if !ok {
		scimErrorResponse(w, "no tenant context", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	ct, err := h.db.Exec(r.Context(), `UPDATE users SET is_active=false WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	if err != nil {
		scimErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		scimErrorResponse(w, "User not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "scim.user_deactivated", id, nil, "ok")
	w.WriteHeader(http.StatusNoContent)
}
