// Package lab is Audspect's owned API test target for API BAS.
//
// The same HTTP contract is served in two modes:
//
//   - vulnerable: contains known, planted flaws (see Flaws). Scenarios must
//     FAIL against it.
//   - fixed:      implements the correct control for the same workflow.
//     Scenarios must PASS against it.
//
// Both modes seed from the same deterministic fixture and expose an admin
// state endpoint so the runner can verify ground truth independently of the
// HTTP response. The lab is a test target only. It is started by cmd/apibas-lab
// and is never mounted in the orchestrator server.
package lab

import (
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
			ID:          "LAB-AUTHZ-BOLA-001",
			ScenarioID:  "API-BAS-AUTHZ-001",
			Description: "GET /api/orders/{id} does not check that the caller owns the order.",
			Oracle: "Vulnerable: a non-owner GET returns the owner's protected values (exploited). " +
				"Fixed: the same request returns 403 and no protected values.",
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

// AuditEntry records every admin action. Cleanup never removes audit entries.
type AuditEntry struct {
	Seq    int    `json:"seq"`
	Action string `json:"action"`
	Tag    string `json:"tag"`
	Detail string `json:"detail"`
}

// Server is an in-memory lab instance. It is safe for concurrent use.
type Server struct {
	cfg    Config
	mu     sync.Mutex
	orders map[string]*Order
	audit  []AuditEntry
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
	s := &Server{cfg: cfg, orders: make(map[string]*Order)}
	for _, o := range cfg.Fixture.Objects {
		s.orders[o.ID] = &Order{
			ID:        o.ID,
			OwnerID:   o.OwnerID,
			Status:    o.Status,
			Public:    copyMap(o.Public),
			Protected: copyMap(o.Protected),
		}
	}
	s.record("seed", "", fmt.Sprintf("fixture %s, %d objects", cfg.Fixture.Name, len(cfg.Fixture.Objects)))
	return s, nil
}

// Handler returns the HTTP handler for the lab's contract and admin routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/orders/{id}", s.getOrder)
	mux.HandleFunc("GET /lab/state", s.adminOnly(s.getState))
	mux.HandleFunc("POST /lab/orders", s.adminOnly(s.createTagged))
	mux.HandleFunc("DELETE /lab/runs/{tag}", s.adminOnly(s.cleanupRun))
	mux.HandleFunc("GET /lab/audit", s.adminOnly(s.getAudit))
	return mux
}

func (s *Server) getOrder(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.authenticate(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	id := r.PathValue("id")

	s.mu.Lock()
	order, found := s.orders[id]
	var body map[string]any
	if found && (s.cfg.Mode == ModeVulnerable || order.OwnerID == caller) {
		body = orderBody(order)
	}
	s.mu.Unlock()

	switch {
	case !found:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	case body == nil:
		// Fixed mode: the caller is authenticated but not the owner.
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
	default:
		writeJSON(w, http.StatusOK, body)
	}
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

func (s *Server) authenticate(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return "", false
	}
	customer, ok := s.cfg.Tokens[strings.TrimPrefix(h, prefix)]
	return customer, ok
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
