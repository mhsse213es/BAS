package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/remoteaccess"
)

const maxRemoteAccessImportRequestBytes = 5 << 20

// CreateRemoteAccessImport -- POST /api/remote-access-imports.
func (h *Handler) CreateRemoteAccessImport(w http.ResponseWriter, r *http.Request) {
	var req remoteaccess.RemoteAccessImport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRemoteAccessImportRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateRemoteAccessImport(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	var importedBy string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		importedBy = c.UserID
	}
	req.ID = newID()
	req.ImportedBy = importedBy

	if err := db.InsertRemoteAccessImport(r.Context(), h.db, &req); err != nil {
		h.auditLog(r, "remoteaccess.import", "", map[string]any{"error": err.Error()}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "remoteaccess.import", req.ID, map[string]any{"tunnelCount": len(req.Tunnels), "transitCount": len(req.Transits)}, "ok")
	respondStatus(w, req, http.StatusCreated)
}

func validateRemoteAccessImport(imp *remoteaccess.RemoteAccessImport) error {
	if len(imp.Tunnels) > remoteaccess.MaxTunnelsPerImport {
		return fmt.Errorf("too many tunnels — got %d, max %d", len(imp.Tunnels), remoteaccess.MaxTunnelsPerImport)
	}
	if len(imp.Transits) > remoteaccess.MaxTransitsPerImport {
		return fmt.Errorf("too many transits — got %d, max %d", len(imp.Transits), remoteaccess.MaxTransitsPerImport)
	}

	hasLimitations := len(imp.Limitations) > 0
	if (len(imp.Tunnels) > 0 || len(imp.Transits) > 0) && !hasLimitations {
		return fmt.Errorf("limitations must be non-empty whenever any tunnel or transit is declared — zone names are never cross-validated against a real network-topology import")
	}

	for i, tun := range imp.Tunnels {
		if tun.FromZone == "" || tun.ToZone == "" {
			return fmt.Errorf("tunnels[%d]: fromZone and toZone are both required", i)
		}
		switch tun.State {
		case remoteaccess.TunnelUp, remoteaccess.TunnelDown, remoteaccess.TunnelUnknown:
		default:
			return fmt.Errorf("tunnels[%d]: unknown state %q", i, tun.State)
		}
	}
	for i, t := range imp.Transits {
		if t.FromZone == "" || t.ToZone == "" || t.ViaZone == "" {
			return fmt.Errorf("transits[%d]: fromZone, toZone, and viaZone are all required", i)
		}
	}
	return nil
}

// ListRemoteAccessImports -- GET /api/remote-access-imports.
func (h *Handler) ListRemoteAccessImports(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	imports, err := db.ListRemoteAccessImports(r.Context(), h.db, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if imports == nil {
		imports = []*remoteaccess.RemoteAccessImport{}
	}
	respond(w, imports)
}

// GetRemoteAccessImport -- GET /api/remote-access-imports/{id}.
func (h *Handler) GetRemoteAccessImport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	imp, err := db.GetRemoteAccessImport(r.Context(), h.db, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "remote access import not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, imp)
}
