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
	"github.com/audspect/bas/internal/networkpolicy"
)

// maxNetworkPolicyImportRequestBytes is larger than Phase 1's equivalent
// caps -- a real policy document (up to MaxRulesPerImport rules) is
// bigger than a target list, but still ships from the start, not as a
// follow-up fix.
const maxNetworkPolicyImportRequestBytes = 5 << 20

// CreateNetworkPolicyImport -- POST /api/network-policy-imports.
func (h *Handler) CreateNetworkPolicyImport(w http.ResponseWriter, r *http.Request) {
	var req networkpolicy.PolicyImport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxNetworkPolicyImportRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateNetworkPolicyImport(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	var importedBy string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		importedBy = c.UserID
	}
	req.ID = newID()
	req.ImportedBy = importedBy

	if err := db.InsertNetworkPolicyImport(r.Context(), h.db, &req); err != nil {
		h.auditLog(r, "networkpolicy.import", "", map[string]any{"error": err.Error()}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "networkpolicy.import", req.ID, map[string]any{"ruleCount": len(req.Rules), "zoneCount": len(req.Zones)}, "ok")
	respondStatus(w, req, http.StatusCreated)
}

func validateNetworkPolicyImport(imp *networkpolicy.PolicyImport) error {
	if len(imp.Zones) == 0 {
		return fmt.Errorf("at least one zone is required")
	}
	if len(imp.Zones) > networkpolicy.MaxZonesPerImport {
		return fmt.Errorf("too many zones — got %d, max %d", len(imp.Zones), networkpolicy.MaxZonesPerImport)
	}
	if len(imp.Rules) == 0 {
		return fmt.Errorf("at least one rule is required")
	}
	if len(imp.Rules) > networkpolicy.MaxRulesPerImport {
		return fmt.Errorf("too many rules — got %d, max %d", len(imp.Rules), networkpolicy.MaxRulesPerImport)
	}
	if imp.DefaultPolicy != networkpolicy.DefaultAllow && imp.DefaultPolicy != networkpolicy.DefaultDeny {
		return fmt.Errorf("defaultPolicy must be %q or %q", networkpolicy.DefaultAllow, networkpolicy.DefaultDeny)
	}
	for i, z := range imp.Zones {
		if z.Name == "" {
			return fmt.Errorf("zones[%d]: name required", i)
		}
		for _, c := range z.CIDRs {
			if _, _, err := net.ParseCIDR(c); err != nil {
				return fmt.Errorf("zones[%d]: invalid CIDR %q", i, c)
			}
		}
	}
	hasLimitations := len(imp.Limitations) > 0
	for i, rule := range imp.Rules {
		switch rule.Action {
		case networkpolicy.ActionAllow, networkpolicy.ActionDeny:
		case networkpolicy.ActionUnresolved:
			if rule.Note == "" {
				return fmt.Errorf("rules[%d]: note required when action is unresolved", i)
			}
			if !hasLimitations {
				return fmt.Errorf("limitations must be non-empty when any rule is unresolved")
			}
		default:
			return fmt.Errorf("rules[%d]: unknown action %q", i, rule.Action)
		}
		if rule.SourceCIDR != "" {
			if _, _, err := net.ParseCIDR(rule.SourceCIDR); err != nil {
				return fmt.Errorf("rules[%d]: invalid sourceCidr %q", i, rule.SourceCIDR)
			}
		}
		if rule.DestCIDR != "" {
			if _, _, err := net.ParseCIDR(rule.DestCIDR); err != nil {
				return fmt.Errorf("rules[%d]: invalid destCidr %q", i, rule.DestCIDR)
			}
		}
		if _, _, _, err := networkpolicy.ParsePortRange(rule.PortRange); err != nil {
			return fmt.Errorf("rules[%d]: %v", i, err)
		}
	}
	return nil
}

// ListNetworkPolicyImports -- GET /api/network-policy-imports.
func (h *Handler) ListNetworkPolicyImports(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	imports, err := db.ListNetworkPolicyImports(r.Context(), h.db, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if imports == nil {
		imports = []*networkpolicy.PolicyImport{}
	}
	respond(w, imports)
}

// GetNetworkPolicyImport -- GET /api/network-policy-imports/{id}.
func (h *Handler) GetNetworkPolicyImport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	imp, err := db.GetNetworkPolicyImport(r.Context(), h.db, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "network policy import not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, imp)
}
