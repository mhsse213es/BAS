package lab

// Authorization tranche (API-BAS-AUTHZ-005, 008, 009, 011). Routes live under /api/authz/ so
// the routes used by the other scenarios are unchanged. Each route has a vulnerable branch
// that carries a LAB-AUTHZ-* flaw and a fixed branch that enforces the control.

import (
	"net/http"
	"slices"
)

// customerBranch is the branch each lab customer belongs to.
var customerBranch = map[string]string{"cust-a": "BR-A", "cust-b": "BR-B"}

// customerGroups and groupScopes model entitlements. The support group carries only the
// orders:read scope.
var (
	customerGroups = map[string][]string{"cust-a": {"support"}}
	groupScopes    = map[string][]string{"support": {"orders:read"}}
	customerScopes = map[string][]string{"cust-a": {"orders:read"}, "cust-b": {"orders:read"}}
)

// hasScope reports whether the customer holds the scope directly or through a group.
func hasScope(customer, scope string) bool {
	if slices.Contains(customerScopes[customer], scope) {
		return true
	}
	for _, g := range customerGroups[customer] {
		if slices.Contains(groupScopes[g], scope) {
			return true
		}
	}
	return false
}

// inGroup reports whether the customer belongs to the named group.
func inGroup(customer, group string) bool {
	return slices.Contains(customerGroups[customer], group)
}

func (s *Server) registerAuthz(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/authz/branches/{branch}/orders", s.authzBranchOrders)
	mux.HandleFunc("GET /api/authz/orders/{id}/audit", s.authzAudit)
	mux.HandleFunc("DELETE /api/authz/orders/{id}", s.authzDelete)
	mux.HandleFunc("GET /api/authz/orders/{id}/view", s.authzView)
}

// authzBranchOrders lists the orders of one branch. The fixed build returns the branch only to
// a caller of that branch. The vulnerable build does not check the caller's branch.
func (s *Server) authzBranchOrders(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	branch := r.PathValue("branch")
	if !s.vulnerable() && customerBranch[caller] != branch {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "branch not permitted"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []map[string]any{}
	for _, o := range sortedOrders(s.orders) {
		if customerBranch[o.OwnerID] != branch {
			continue
		}
		if s.vulnerable() {
			out = append(out, orderBody(o)) // LAB-AUTHZ-BRANCH-001: other branches are returned in full
		} else {
			out = append(out, publicView(o))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"orders": out})
}

// authzAudit returns the audit view of an order, with protected values. It requires the
// audit:read scope, or the admin credential.
func (s *Server) authzAudit(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	allowed := s.adminRequest(r) || hasScope(caller, "audit:read")
	// LAB-AUTHZ-GROUP-001: the vulnerable build also honours group name "support" as if it
	// were the audit scope.
	if s.vulnerable() && inGroup(caller, "support") {
		allowed = true
	}
	if !allowed {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "audit:read scope required"})
		return
	}
	s.mu.Lock()
	o, found := s.orders[r.PathValue("id")]
	var body map[string]any
	if found {
		body = orderBody(o)
	}
	s.mu.Unlock()
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	writeJSON(w, http.StatusOK, body)
}

// authzDelete marks an order deleted. The read route checks ownership, and the fixed delete
// does too. The vulnerable delete does not.
func (s *Server) authzDelete(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	o, found := s.orders[r.PathValue("id")]
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	// LAB-AUTHZ-DELETE-001: the vulnerable build skips the ownership check on delete.
	if !s.vulnerable() && o.OwnerID != caller {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "not the owner"})
		return
	}
	o.Status = "deleted"
	writeJSON(w, http.StatusOK, map[string]string{"status": o.Status})
}

// authzView returns the owner's view of an order. The vulnerable build caches the first
// response in a cache shared by every caller, keyed by path only (LAB-AUTHZ-CACHE-001).
func (s *Server) authzView(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	key := r.URL.Path
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vulnerable() {
		if cached, hit := s.sharedCache[key]; hit {
			writeJSON(w, http.StatusOK, cached)
			return
		}
	}
	o, found := s.orders[r.PathValue("id")]
	if !found || o.OwnerID != caller {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	body := publicView(o)
	if s.vulnerable() {
		if s.sharedCache == nil {
			s.sharedCache = map[string]map[string]any{}
		}
		s.sharedCache[key] = orderBody(o)
		body = orderBody(o)
	}
	writeJSON(w, http.StatusOK, body)
}

// authzFlaws names the planted authorization flaws. Each is present only in ModeVulnerable.
func authzFlaws() []Flaw {
	return []Flaw{
		{ID: "LAB-AUTHZ-BRANCH-001", ScenarioID: "API-BAS-AUTHZ-005", Description: "GET /api/authz/branches/{branch}/orders does not check the caller's branch and returns full records.", Oracle: "protected values of another branch's order appear in the response"},
		{ID: "LAB-AUTHZ-GROUP-001", ScenarioID: "API-BAS-AUTHZ-008", Description: "GET /api/authz/orders/{id}/audit honours the support group name as if it were the audit scope.", Oracle: "protected values of an order appear to a caller without the audit:read scope"},
		{ID: "LAB-AUTHZ-DELETE-001", ScenarioID: "API-BAS-AUTHZ-009", Description: "DELETE /api/authz/orders/{id} skips the ownership check that the read route performs.", Oracle: "the order status changes to deleted for a caller who is not the owner"},
		{ID: "LAB-AUTHZ-CACHE-001", ScenarioID: "API-BAS-AUTHZ-011", Description: "GET /api/authz/orders/{id}/view caches the owner's response in a cache shared by every caller, keyed by path.", Oracle: "protected values of the owner's order appear in another customer's response"},
	}
}
