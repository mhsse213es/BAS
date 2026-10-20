// Package lab is Audspect's owned API test target for API BAS.
//
// The same HTTP contract is served in two modes:
//
//   - vulnerable: contains the planted flaws listed by Flaws. Scenarios must
//     FAIL against it.
//   - fixed:      implements the correct control for the same workflows.
//     Scenarios must PASS against it.
//
// Both modes seed from the same deterministic fixture and expose an admin
// state endpoint so the runner can verify ground truth independently of the
// HTTP response. The lab is a test target only. It is started by cmd/apibas-lab
// and is never mounted in the orchestrator server.
package lab

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/audspect/bas/internal/apibas/fixture"
)

// Mode selects which variant of the contract the lab serves.
type Mode string

const (
	ModeVulnerable Mode = "vulnerable"
	ModeFixed      Mode = "fixed"
)

// Config configures a lab instance. Tokens and AdminToken are supplied by the
// caller at start-up and are never persisted by the lab.
type Config struct {
	Mode       Mode
	Fixture    fixture.Fixture
	Tokens     map[string]string // bearer token -> customer ID
	Revoked    []string          // tokens that are in Tokens but must be refused
	AdminToken string
}

// Flaw describes one planted vulnerability and the oracle that proves it.
// Flaws are present only in ModeVulnerable.
type Flaw struct {
	ID          string
	ScenarioID  string
	Description string
	Oracle      string
}

// Flaws returns the registry of planted flaws. Each entry names the scenario
// that must detect it and the oracle that defines "detected".
func Flaws() []Flaw {
	return []Flaw{
		{
			ID:          "LAB-AUTHN-ANON-001",
			ScenarioID:  "API-BAS-AUTHN-001",
			Description: "GET /api/orders/{id} serves a request with no credential as an anonymous caller.",
			Oracle: "Vulnerable: a GET with no Authorization header returns the order and its protected values (exploited). " +
				"Fixed: the same request returns 401 and no protected values.",
		},
		{
			ID:          "LAB-AUTHN-REVOKE-001",
			ScenarioID:  "API-BAS-AUTHN-002",
			Description: "GET /api/orders/{id} accepts a revoked bearer token.",
			Oracle: "Vulnerable: a revoked token of the owner returns the owner's order and protected values (exploited). " +
				"Fixed: the same request returns 401.",
		},
		{
			ID:          "LAB-AUTHZ-BOLA-001",
			ScenarioID:  "API-BAS-AUTHZ-001",
			Description: "GET /api/orders/{id} does not check that the caller owns the order.",
			Oracle: "Vulnerable: a non-owner GET returns the owner's protected values (exploited). " +
				"Fixed: the same request returns 403 and no protected values.",
		},
		{
			ID:          "LAB-AUTHZ-BFLA-001",
			ScenarioID:  "API-BAS-AUTHZ-002",
			Description: "PATCH /api/admin/orders/{id}/status checks authentication but not the admin role.",
			Oracle: "Vulnerable: a customer token changes the order status (state change). " +
				"Fixed: the same request returns 403 and the status is unchanged.",
		},
		{
			ID:          "LAB-AUTHZ-VERSION-001",
			ScenarioID:  "API-BAS-AUTHZ-010",
			Description: "The legacy /api/v1/orders/{id} route does not check ownership; /api/orders/{id} does.",
			Oracle: "Vulnerable: a non-owner GET on the v1 route returns the owner's protected values (exploited). " +
				"Fixed: the v1 route returns 403 and no protected values.",
		},
		{
			ID:          "LAB-DATA-PROJ-001",
			ScenarioID:  "API-BAS-DATA-001",
			Description: "GET /api/orders/{id}/summary returns the full record, including protected fields, to the owner.",
			Oracle: "Vulnerable: the owner's summary contains protected values (exposed). " +
				"Fixed: the summary contains only public fields and returns 200 with no protected values.",
		},
		{
			ID:          "LAB-DISC-DEBUG-001",
			ScenarioID:  "API-BAS-DISC-003",
			Description: "A debug route is reachable by any authenticated customer and returns full records.",
			Oracle: "Vulnerable: a customer token on /debug/orders/{id} returns the owner's protected values (exposed). " +
				"Fixed: the route is not mounted and returns 404.",
		},
		{
			ID:          "LAB-AUTHN-ALG-001",
			ScenarioID:  "API-BAS-AUTHN-003",
			Description: "The token verifier accepts an unsigned JWT (alg none) and trusts its subject claim.",
			Oracle: "Vulnerable: an unsigned token whose subject is customer-b reads customer-b's order (exploited). " +
				"Fixed: the same token returns 401.",
		},
		{
			ID:          "LAB-DATA-LIST-001",
			ScenarioID:  "API-BAS-DATA-004",
			Description: "GET /api/orders returns every customer's full record, with no owner filter and no limit.",
			Oracle: "Vulnerable: a customer's list call returns another customer's protected values (exposed). " +
				"Fixed: the list returns only the caller's public projection, capped, with no protected values.",
		},
		{
			ID:          "LAB-GWAY-OVERRIDE-001",
			ScenarioID:  "API-BAS-GWAY-003",
			Description: "A POST with X-HTTP-Method-Override: PATCH reaches the PATCH admin route, bypassing the method policy.",
			Oracle: "Vulnerable: a customer's POST with the override header changes the order status (state change). " +
				"Fixed: the POST is refused with 405 and the status is unchanged.",
		},
		{
			ID:          "LAB-AUTHZ-MASS-001",
			ScenarioID:  "API-BAS-AUTHZ-003",
			Description: "PATCH /api/orders/{id} binds every submitted field, including owner_id, from the request body.",
			Oracle: "Vulnerable: an owner PATCHes owner_id on their own order and the owner changes (state change). " +
				"Fixed: the same request returns 403 and the owner is unchanged.",
		},
	}
}

// Order is a stored order. Protected values are held server-side and reach
// the caller only through the vulnerable or owner-authorised code path.
type Order struct {
	ID        string
	OwnerID   string
	Status    string
	Tag       string // run tag; empty for seed data, which cleanup never removes
	Public    map[string]string
	Protected map[string]string
}

// OrderState is the admin-visible snapshot used as ground truth. It carries no
// protected values, so the state endpoint itself does not become a leak path.
type OrderState struct {
	ID      string `json:"id"`
	OwnerID string `json:"owner_id"`
	Status  string `json:"status"`
	Tag     string `json:"tag"`
}

// AuditEntry records every admin and mutating action. Cleanup and reset never
// remove audit entries.
type AuditEntry struct {
	Seq    int    `json:"seq"`
	Action string `json:"action"`
	Tag    string `json:"tag"`
	Detail string `json:"detail"`
}

type authState int

const (
	authOK authState = iota
	authMissing
	authInvalid
	authRevoked
)

// Server is an in-memory lab instance. It is safe for concurrent use.
type Server struct {
	cfg     Config
	revoked map[string]bool
	mu      sync.Mutex
	orders  map[string]*Order
	audit   []AuditEntry
}

// New validates the configuration, seeds the store from the fixture and
// returns a ready server.
func New(cfg Config) (*Server, error) {
	if cfg.Mode != ModeVulnerable && cfg.Mode != ModeFixed {
		return nil, fmt.Errorf("lab: unknown mode %q", cfg.Mode)
	}
	if cfg.AdminToken == "" {
		return nil, errors.New("lab: admin token is required")
	}
	s := &Server{cfg: cfg, revoked: make(map[string]bool, len(cfg.Revoked))}
	for _, t := range cfg.Revoked {
		s.revoked[t] = true
	}
	s.reseed()
	s.record("seed", "", fmt.Sprintf("fixture %s, %d objects", cfg.Fixture.Name, len(cfg.Fixture.Objects)))
	return s, nil
}

// reseed restores the store to the fixture's seed state. Callers must hold
// s.mu, except during New where the server is not yet shared.
func (s *Server) reseed() {
	s.orders = make(map[string]*Order, len(s.cfg.Fixture.Objects))
	for _, o := range s.cfg.Fixture.Objects {
		s.orders[o.ID] = &Order{
			ID:        o.ID,
			OwnerID:   o.OwnerID,
			Status:    o.Status,
			Public:    copyMap(o.Public),
			Protected: copyMap(o.Protected),
		}
	}
}

// Handler returns the HTTP handler for the lab's contract and admin routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/orders/{id}", s.getOrder)
	mux.HandleFunc("PATCH /api/orders/{id}", s.patchOrder)
	mux.HandleFunc("PATCH /api/admin/orders/{id}/status", s.adminSetStatus)
	mux.HandleFunc("GET /api/v1/orders/{id}", s.getOrderV1)
	mux.HandleFunc("GET /api/orders", s.listOrders)
	mux.HandleFunc("POST /lab/token-status", s.adminOnly(s.tokenStatus))
	mux.HandleFunc("GET /api/orders/{id}/summary", s.getSummary)
	if s.cfg.Mode == ModeVulnerable {
		// The debug route exists only in the vulnerable build (LAB-DISC-DEBUG-001).
		mux.HandleFunc("GET /debug/orders/{id}", s.debugOrder)
	}
	mux.HandleFunc("GET /lab/state", s.adminOnly(s.getState))
	mux.HandleFunc("POST /lab/orders", s.adminOnly(s.createTagged))
	mux.HandleFunc("DELETE /lab/runs/{tag}", s.adminOnly(s.cleanupRun))
	mux.HandleFunc("POST /lab/reset", s.adminOnly(s.resetFixture))
	mux.HandleFunc("GET /lab/audit", s.adminOnly(s.getAudit))
	if s.cfg.Mode == ModeVulnerable {
		// LAB-GWAY-OVERRIDE-001: the vulnerable build honours a method-override header.
		return methodOverride(mux)
	}
	return mux
}

// methodOverride rewrites a POST carrying X-HTTP-Method-Override: PATCH into a
// PATCH before routing. Only the vulnerable build wraps the mux (LAB-GWAY-OVERRIDE-001),
// so the fixed build routes the POST by its real method and returns 405.
func methodOverride(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.Header.Get("X-HTTP-Method-Override") == http.MethodPatch {
			r.Method = http.MethodPatch
		}
		next.ServeHTTP(w, r)
	})
}

// identify reads the bearer credential. It returns the customer the token
// belongs to, even when the token is revoked, so the caller can decide how to
// treat a revoked token.
func (s *Server) identify(r *http.Request) (string, authState) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", authMissing
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return "", authInvalid
	}
	tok := strings.TrimPrefix(h, prefix)
	if s.cfg.Mode == ModeVulnerable {
		// LAB-AUTHN-ALG-001: the vulnerable verifier accepts an unsigned token and
		// trusts its subject claim without checking any signature.
		if sub, ok := unsignedSubject(tok); ok {
			return sub, authOK
		}
	}
	customer, ok := s.cfg.Tokens[tok]
	if !ok {
		return "", authInvalid
	}
	if s.revoked[tok] {
		return customer, authRevoked
	}
	return customer, authOK
}

func (s *Server) getOrder(w http.ResponseWriter, r *http.Request) {
	caller, st := s.identify(r)
	vulnerable := s.cfg.Mode == ModeVulnerable
	switch st {
	case authMissing:
		if !vulnerable {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
			return
		}
		caller = "" // LAB-AUTHN-ANON-001: no credential is served as anonymous
	case authRevoked:
		if !vulnerable {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "token revoked"})
			return
		}
		// LAB-AUTHN-REVOKE-001: the revoked token is still honoured.
	case authInvalid:
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return
	}

	s.mu.Lock()
	order, found := s.orders[r.PathValue("id")]
	var body map[string]any
	if found && (vulnerable || order.OwnerID == caller) {
		body = orderBody(order)
	}
	s.mu.Unlock()

	switch {
	case !found:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	case body == nil:
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
	default:
		writeJSON(w, http.StatusOK, body)
	}
}

// patchOrder updates an order. Authentication is strict in both modes; the
// planted flaw is the field binding (LAB-AUTHZ-MASS-001).
func (s *Server) patchOrder(w http.ResponseWriter, r *http.Request) {
	caller, st := s.identify(r)
	if st != authOK {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	var fields map[string]any
	if err := json.NewDecoder(r.Body).Decode(&fields); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	vulnerable := s.cfg.Mode == ModeVulnerable

	s.mu.Lock()
	defer s.mu.Unlock()
	order, found := s.orders[r.PathValue("id")]
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if !vulnerable {
		if order.OwnerID != caller {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}
		if _, ownerField := fields["owner_id"]; ownerField {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "field not permitted"})
			return
		}
		if _, statusField := fields["status"]; statusField {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "field not permitted"})
			return
		}
	}
	if v, ok := fields["owner_id"].(string); ok && vulnerable {
		order.OwnerID = v
	}
	if v, ok := fields["status"].(string); ok && vulnerable {
		order.Status = v
	}
	s.record("update", order.Tag, fmt.Sprintf("order %s patched by %s", order.ID, caller))
	writeJSON(w, http.StatusOK, orderBody(order))
}

// adminSetStatus sets an order's status through the admin route. Authentication
// is required in both modes; the role check is the planted flaw
// (LAB-AUTHZ-BFLA-001).
func (s *Server) adminSetStatus(w http.ResponseWriter, r *http.Request) {
	_, st := s.identify(r)
	if st != authOK {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	if s.cfg.Mode == ModeFixed {
		// No customer token carries the admin role, so the fixed build refuses.
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin role required"})
		return
	}
	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Status == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "status is required"})
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	order, found := s.orders[r.PathValue("id")]
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	order.Status = req.Status
	s.record("admin_status", order.Tag, fmt.Sprintf("order %s status set", order.ID))
	writeJSON(w, http.StatusOK, map[string]string{"id": order.ID, "status": order.Status})
}

func (s *Server) getState(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	states := make([]OrderState, 0, len(s.orders))
	for _, o := range s.orders {
		states = append(states, OrderState{ID: o.ID, OwnerID: o.OwnerID, Status: o.Status, Tag: o.Tag})
	}
	s.mu.Unlock()
	sort.Slice(states, func(i, j int) bool { return states[i].ID < states[j].ID })
	writeJSON(w, http.StatusOK, states)
}

type createRequest struct {
	ID      string `json:"id"`
	OwnerID string `json:"owner_id"`
	Status  string `json:"status"`
	Tag     string `json:"tag"`
}

func (s *Server) createTagged(w http.ResponseWriter, r *http.Request) {
	var req createRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" || req.Tag == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id and tag are required"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.orders[req.ID]; exists {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "id already exists"})
		return
	}
	s.orders[req.ID] = &Order{ID: req.ID, OwnerID: req.OwnerID, Status: req.Status, Tag: req.Tag,
		Public: map[string]string{}, Protected: map[string]string{}}
	s.record("create", req.Tag, req.ID)
	writeJSON(w, http.StatusCreated, map[string]string{"id": req.ID, "tag": req.Tag})
}

func (s *Server) cleanupRun(w http.ResponseWriter, r *http.Request) {
	tag := r.PathValue("tag")
	if tag == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tag is required"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for id, o := range s.orders {
		// Seed records have an empty tag and are never matched here.
		if o.Tag == tag {
			delete(s.orders, id)
			removed++
		}
	}
	s.record("cleanup", tag, fmt.Sprintf("removed %d tagged records", removed))
	writeJSON(w, http.StatusOK, map[string]int{"removed": removed})
}

// resetFixture restores the seed state. It is the sandbox cleanup for
// scenarios that change state. The audit log is kept.
func (s *Server) resetFixture(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reseed()
	s.record("reset", "", "store restored to fixture "+s.cfg.Fixture.Name)
	writeJSON(w, http.StatusOK, map[string]string{"status": "reset"})
}

func (s *Server) getAudit(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	entries := make([]AuditEntry, len(s.audit))
	copy(entries, s.audit)
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, entries)
}

// record appends to the audit log. Callers must hold s.mu, except during New
// where the server is not yet shared.
func (s *Server) record(action, tag, detail string) {
	s.audit = append(s.audit, AuditEntry{Seq: len(s.audit) + 1, Action: action, Tag: tag, Detail: detail})
}

func (s *Server) adminOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Lab-Admin") != s.cfg.AdminToken {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "admin token required"})
			return
		}
		next(w, r)
	}
}

// getOrderV1 is the legacy route. It keeps the old contract and, in the
// vulnerable build, skips the ownership check that /api/orders/{id} performs.
func (s *Server) getOrderV1(w http.ResponseWriter, r *http.Request) {
	caller, st := s.identify(r)
	if st != authOK {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	s.mu.Lock()
	order, found := s.orders[r.PathValue("id")]
	var body map[string]any
	if found && (s.cfg.Mode == ModeVulnerable || order.OwnerID == caller) {
		body = orderBody(order)
	}
	s.mu.Unlock()
	respondOrder(w, found, body)
}

// getSummary returns a projection for the owner. The fixed build returns only
// public fields; the vulnerable build returns the full record (LAB-DATA-PROJ-001).
func (s *Server) getSummary(w http.ResponseWriter, r *http.Request) {
	caller, st := s.identify(r)
	if st != authOK {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	s.mu.Lock()
	order, found := s.orders[r.PathValue("id")]
	var body map[string]any
	if found && order.OwnerID == caller {
		if s.cfg.Mode == ModeVulnerable {
			body = orderBody(order)
		} else {
			body = publicBody(order)
		}
	}
	s.mu.Unlock()
	if found && body == nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	respondOrder(w, found, body)
}

// debugOrder is a diagnostic route that returns full records. It is mounted
// only in the vulnerable build (LAB-DISC-DEBUG-001).
func (s *Server) debugOrder(w http.ResponseWriter, r *http.Request) {
	_, st := s.identify(r)
	if st != authOK {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	s.mu.Lock()
	order, found := s.orders[r.PathValue("id")]
	var body map[string]any
	if found {
		body = orderBody(order)
	}
	s.mu.Unlock()
	respondOrder(w, found, body)
}

func respondOrder(w http.ResponseWriter, found bool, body map[string]any) {
	switch {
	case !found:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	case body == nil:
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
	default:
		writeJSON(w, http.StatusOK, body)
	}
}

// publicBody is the projection a summary may return: identifiers and public
// fields only.
func publicBody(o *Order) map[string]any {
	body := map[string]any{"id": o.ID, "owner_id": o.OwnerID, "status": o.Status}
	for k, v := range o.Public {
		body[k] = v
	}
	return body
}

// listOrders is the collection endpoint. The vulnerable build returns every
// record in full with no limit; the fixed build returns the caller's own records
// as a public projection, capped (LAB-DATA-LIST-001).
func (s *Server) listOrders(w http.ResponseWriter, r *http.Request) {
	caller, st := s.identify(r)
	if st != authOK {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	const fixedCap = 50
	s.mu.Lock()
	ids := make([]string, 0, len(s.orders))
	for id := range s.orders {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rows := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		o := s.orders[id]
		if s.cfg.Mode == ModeVulnerable {
			rows = append(rows, orderBody(o))
			continue
		}
		if o.OwnerID == caller && len(rows) < fixedCap {
			rows = append(rows, publicBody(o))
		}
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, rows)
}

// tokenStatus reports to the admin caller whether the lab knows a token and
// whether it is revoked. The runner uses it as a guard before grading a
// revoked-token scenario.
func (s *Server) tokenStatus(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token is required"})
		return
	}
	_, known := s.cfg.Tokens[req.Token]
	writeJSON(w, http.StatusOK, map[string]bool{"known": known, "revoked": s.revoked[req.Token]})
}

// unsignedSubject returns the subject of an unsigned JWT (alg none, empty
// signature). It is used only by the vulnerable build.
func unsignedSubject(tok string) (string, bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || parts[2] != "" {
		return "", false
	}
	hdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	var h struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(hdr, &h) != nil || !strings.EqualFold(h.Alg, "none") {
		return "", false
	}
	pl, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var c struct {
		Sub string `json:"sub"`
	}
	if json.Unmarshal(pl, &c) != nil || c.Sub == "" {
		return "", false
	}
	return c.Sub, true
}

func orderBody(o *Order) map[string]any {
	body := map[string]any{"id": o.ID, "owner_id": o.OwnerID, "status": o.Status}
	for k, v := range o.Public {
		body[k] = v
	}
	for k, v := range o.Protected {
		body[k] = v
	}
	return body
}

func copyMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	maps.Copy(out, in)
	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
