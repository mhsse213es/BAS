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
	"github.com/audspect/bas/internal/cloudtopology"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networkpolicy"
)

const maxCloudTopologyImportRequestBytes = 5 << 20

// CreateCloudTopologyImport -- POST /api/cloud-topology-imports.
func (h *Handler) CreateCloudTopologyImport(w http.ResponseWriter, r *http.Request) {
	var req cloudtopology.CloudTopologyImport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxCloudTopologyImportRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateCloudTopologyImport(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	var importedBy string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		importedBy = c.UserID
	}
	req.ID = newID()
	req.ImportedBy = importedBy

	if err := db.InsertCloudTopologyImport(r.Context(), h.db, &req); err != nil {
		h.auditLog(r, "cloudtopology.import", "", map[string]any{"error": err.Error()}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "cloudtopology.import", req.ID, map[string]any{"subnetCount": len(req.Subnets), "ruleCount": len(req.Rules)}, "ok")
	respondStatus(w, req, http.StatusCreated)
}

func validateCloudTopologyImport(imp *cloudtopology.CloudTopologyImport) error {
	if len(imp.Subnets) == 0 {
		return fmt.Errorf("at least one subnet is required")
	}
	if len(imp.Subnets) > cloudtopology.MaxSubnetsPerImport {
		return fmt.Errorf("too many subnets — got %d, max %d", len(imp.Subnets), cloudtopology.MaxSubnetsPerImport)
	}
	if len(imp.Rules) > cloudtopology.MaxRulesPerImport {
		return fmt.Errorf("too many rules — got %d, max %d", len(imp.Rules), cloudtopology.MaxRulesPerImport)
	}
	if len(imp.Routes) > cloudtopology.MaxRoutesPerImport {
		return fmt.Errorf("too many routes — got %d, max %d", len(imp.Routes), cloudtopology.MaxRoutesPerImport)
	}

	networkIDs := make(map[string]bool, len(imp.Networks))
	for i, n := range imp.Networks {
		if n.CanonicalID == "" {
			return fmt.Errorf("networks[%d]: canonicalId required", i)
		}
		networkIDs[n.CanonicalID] = true
		for _, c := range n.CIDRBlocks {
			if _, _, err := net.ParseCIDR(c); err != nil {
				return fmt.Errorf("networks[%d]: invalid cidrBlock %q", i, c)
			}
		}
	}
	subnetIDs := make(map[string]bool, len(imp.Subnets))
	for i, s := range imp.Subnets {
		if s.CanonicalID == "" {
			return fmt.Errorf("subnets[%d]: canonicalId required", i)
		}
		if !networkIDs[s.NetworkID] {
			return fmt.Errorf("subnets[%d]: networkId %q not found in networks", i, s.NetworkID)
		}
		if _, _, err := net.ParseCIDR(s.CIDRBlock); err != nil {
			return fmt.Errorf("subnets[%d]: invalid cidrBlock %q", i, s.CIDRBlock)
		}
		subnetIDs[s.CanonicalID] = true
	}

	hasLimitations := len(imp.Limitations) > 0
	groupIDs := make(map[string]bool, len(imp.Groups))
	for i, g := range imp.Groups {
		if g.CanonicalID == "" {
			return fmt.Errorf("groups[%d]: canonicalId required", i)
		}
		switch g.Scope {
		case cloudtopology.ScopeNetwork:
			if !networkIDs[g.NetworkID] {
				return fmt.Errorf("groups[%d]: networkId %q not found in networks", i, g.NetworkID)
			}
		case cloudtopology.ScopeSubnet:
			if !subnetIDs[g.SubnetID] {
				return fmt.Errorf("groups[%d]: subnetId %q not found in subnets", i, g.SubnetID)
			}
		case cloudtopology.ScopeUnresolved:
			if !hasLimitations {
				return fmt.Errorf("limitations must be non-empty when any group has unresolved scope")
			}
			if g.NetworkID == "" || !networkIDs[g.NetworkID] {
				return fmt.Errorf("groups[%d]: networkId %q not found in networks", i, g.NetworkID)
			}
			if g.SubnetID != "" && !subnetIDs[g.SubnetID] {
				return fmt.Errorf("groups[%d]: subnetId %q not found in subnets", i, g.SubnetID)
			}
		default:
			return fmt.Errorf("groups[%d]: unknown scope %q", i, g.Scope)
		}
		groupIDs[g.CanonicalID] = true
	}

	for i, rule := range imp.Rules {
		if !groupIDs[rule.GroupID] {
			return fmt.Errorf("rules[%d]: groupId %q not found in groups", i, rule.GroupID)
		}
		if rule.Direction != cloudtopology.DirectionInbound && rule.Direction != cloudtopology.DirectionOutbound {
			return fmt.Errorf("rules[%d]: direction must be %q or %q", i, cloudtopology.DirectionInbound, cloudtopology.DirectionOutbound)
		}
		if rule.CIDR == "" && rule.ReferencedGroupID == "" {
			return fmt.Errorf("rules[%d]: exactly one of cidr or referencedGroupId is required", i)
		}
		if rule.CIDR != "" && rule.ReferencedGroupID != "" {
			return fmt.Errorf("rules[%d]: exactly one of cidr or referencedGroupId is required, not both", i)
		}
		switch rule.Action {
		case cloudtopology.ActionAllow, cloudtopology.ActionDeny:
			if rule.ReferencedGroupID != "" {
				return fmt.Errorf("rules[%d]: a security-group-reference rule cannot be resolved by this schema -- action must be %q, not %q", i, cloudtopology.ActionUnresolved, rule.Action)
			}
		case cloudtopology.ActionUnresolved:
			if rule.Note == "" {
				return fmt.Errorf("rules[%d]: note required when action is unresolved", i)
			}
			if !hasLimitations {
				return fmt.Errorf("limitations must be non-empty when any rule is unresolved")
			}
		default:
			return fmt.Errorf("rules[%d]: unknown action %q", i, rule.Action)
		}
		if rule.CIDR != "" {
			if _, _, err := net.ParseCIDR(rule.CIDR); err != nil {
				return fmt.Errorf("rules[%d]: invalid cidr %q", i, rule.CIDR)
			}
		}
		if _, _, _, err := networkpolicy.ParsePortRange(rule.PortRange); err != nil {
			return fmt.Errorf("rules[%d]: %v", i, err)
		}
	}

	for i, route := range imp.Routes {
		if !subnetIDs[route.SubnetID] {
			return fmt.Errorf("routes[%d]: subnetId %q not found in subnets", i, route.SubnetID)
		}
		if _, _, err := net.ParseCIDR(route.DestinationCIDR); err != nil {
			return fmt.Errorf("routes[%d]: invalid destinationCidr %q", i, route.DestinationCIDR)
		}
		switch route.Target {
		case cloudtopology.TargetLocal, cloudtopology.TargetPeering, cloudtopology.TargetInternetGateway, cloudtopology.TargetNATGateway, cloudtopology.TargetTransitGateway, cloudtopology.TargetUnknown:
		default:
			return fmt.Errorf("routes[%d]: unknown target %q", i, route.Target)
		}
	}
	for i, p := range imp.Peerings {
		if !networkIDs[p.NetworkAID] {
			return fmt.Errorf("peerings[%d]: networkAId %q not found in networks", i, p.NetworkAID)
		}
		if !networkIDs[p.NetworkBID] {
			return fmt.Errorf("peerings[%d]: networkBId %q not found in networks", i, p.NetworkBID)
		}
		switch p.State {
		case cloudtopology.PeeringActive, cloudtopology.PeeringPending, cloudtopology.PeeringRejected, cloudtopology.PeeringUnknown:
		default:
			return fmt.Errorf("peerings[%d]: unknown state %q", i, p.State)
		}
	}
	return nil
}

// ListCloudTopologyImports -- GET /api/cloud-topology-imports.
func (h *Handler) ListCloudTopologyImports(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	imports, err := db.ListCloudTopologyImports(r.Context(), h.db, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if imports == nil {
		imports = []*cloudtopology.CloudTopologyImport{}
	}
	respond(w, imports)
}

// GetCloudTopologyImport -- GET /api/cloud-topology-imports/{id}.
func (h *Handler) GetCloudTopologyImport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	imp, err := db.GetCloudTopologyImport(r.Context(), h.db, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "cloud topology import not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, imp)
}
