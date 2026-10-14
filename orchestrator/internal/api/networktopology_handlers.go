package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networktopology"
)

// maxNetworkTopologyImportRequestBytes mirrors Phase 2A's policy-import
// cap -- a real topology document can be as large as a real policy
// document.
const maxNetworkTopologyImportRequestBytes = 5 << 20

// CreateNetworkTopologyImport -- POST /api/network-topology-imports.
func (h *Handler) CreateNetworkTopologyImport(w http.ResponseWriter, r *http.Request) {
	var req networktopology.TopologyImport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxNetworkTopologyImportRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateNetworkTopologyImport(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	var importedBy string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		importedBy = c.UserID
	}
	req.ID = newID()
	req.ImportedBy = importedBy

	if err := db.InsertNetworkTopologyImport(r.Context(), h.db, &req); err != nil {
		h.auditLog(r, "networktopology.import", "", map[string]any{"error": err.Error()}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "networktopology.import", req.ID, map[string]any{"zoneCount": len(req.Zones), "edgeCount": len(req.Edges)}, "ok")
	respondStatus(w, req, http.StatusCreated)
}

func validateNetworkTopologyImport(imp *networktopology.TopologyImport) error {
	if len(imp.Zones) == 0 {
		return fmt.Errorf("at least one zone is required")
	}
	if len(imp.Zones) > networktopology.MaxZonesPerTopologyImport {
		return fmt.Errorf("too many zones — got %d, max %d", len(imp.Zones), networktopology.MaxZonesPerTopologyImport)
	}
	if len(imp.Edges) > networktopology.MaxEdgesPerTopologyImport {
		return fmt.Errorf("too many edges — got %d, max %d", len(imp.Edges), networktopology.MaxEdgesPerTopologyImport)
	}
	zoneNames := map[string]bool{}
	for i, z := range imp.Zones {
		if z.Name == "" {
			return fmt.Errorf("zones[%d]: name required", i)
		}
		if zoneNames[z.Name] {
			return fmt.Errorf("zones[%d]: duplicate zone name %q", i, z.Name)
		}
		zoneNames[z.Name] = true
		for _, c := range z.CIDRs {
			if _, _, err := net.ParseCIDR(c); err != nil {
				return fmt.Errorf("zones[%d]: invalid CIDR %q", i, c)
			}
		}
	}
	for i, e := range imp.Edges {
		if e.FromZone == e.ToZone {
			return fmt.Errorf("edges[%d]: fromZone and toZone must not be the same zone (%q)", i, e.FromZone)
		}
		if !zoneNames[e.FromZone] {
			return fmt.Errorf("edges[%d]: fromZone %q is not a declared zone", i, e.FromZone)
		}
		if !zoneNames[e.ToZone] {
			return fmt.Errorf("edges[%d]: toZone %q is not a declared zone", i, e.ToZone)
		}
	}
	return nil
}

// ListNetworkTopologyImports -- GET /api/network-topology-imports.
func (h *Handler) ListNetworkTopologyImports(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	imports, err := db.ListNetworkTopologyImports(r.Context(), h.db, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if imports == nil {
		imports = []*networktopology.TopologyImport{}
	}
	respond(w, imports)
}

// GetNetworkTopologyImport -- GET /api/network-topology-imports/{id}.
func (h *Handler) GetNetworkTopologyImport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	imp, err := db.GetNetworkTopologyImport(r.Context(), h.db, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "network topology import not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, imp)
}
