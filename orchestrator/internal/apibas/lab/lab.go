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
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"crypto/sha256"
	"encoding/hex"
	"github.com/audspect/bas/internal/apibas/fixture"
	"math"
	"strconv"
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
	// InternalToken is the credential an internal service presents to the
	// internal route. When empty, the fixed build refuses every internal call.
	InternalToken string
	// Faults names dependency faults to hold active for the life of the lab, for example
	// "authz-store-down", "telemetry-missing" (access events are never delivered) or "telemetry-delayed"
	// (events reach the SIEM only after a three-second hold). A scenario that needs one declares it as a
	// lab_faults precondition.
	Faults []string
	// ExtractBodyIDs turns on selective extraction of known order IDs from request bodies, for detection of
	// body-carried object references (see extract.go). It is off by default: bodies are not read.
	ExtractBodyIDs bool
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
func flawsCore() []Flaw {
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
			ID:          "LAB-DISC-DEPRECATED-001",
			ScenarioID:  "API-BAS-DISC-002",
			Description: "The retired /api/v0/orders/{id} route is still served and needs no credential.",
			Oracle: "Vulnerable: an anonymous GET on the retired route returns the order and protected values (exposed). " +
				"Fixed: the route is not mounted and returns 404.",
		},
		{
			ID:          "LAB-INTEG-SSRF-001",
			ScenarioID:  "API-BAS-INTEG-003",
			Description: "POST /api/webhooks/test fetches any URL the caller supplies, including internal addresses.",
			Oracle: "Vulnerable: a customer can make the lab fetch an internal record and return its protected values (exposed). " +
				"Fixed: a loopback or private destination is refused with 403 and nothing is fetched.",
		},
		{
			ID:          "LAB-DATA-ERRLEAK-001",
			ScenarioID:  "API-BAS-DATA-003",
			Description: "A malformed PATCH body returns an error that includes the targeted order's full record.",
			Oracle: "Vulnerable: a malformed body against another customer's order returns that order's protected values (exposed). " +
				"Fixed: the error is a generic 400 with no record.",
		},
		{
			ID:          "LAB-AUTHN-SESSION-001",
			ScenarioID:  "API-BAS-AUTHN-008",
			Description: "A caller-supplied X-Customer-Id header overrides the identity the token proves.",
			Oracle: "Vulnerable: a customer token with X-Customer-Id set to another customer reads that customer's order (exploited). " +
				"Fixed: the header is ignored and the request returns 403.",
		},
		{
			ID:          "LAB-AUTHZ-BULK-001",
			ScenarioID:  "API-BAS-AUTHZ-007",
			Description: "PATCH /api/orders/bulk applies a status change to every listed order, without an ownership check.",
			Oracle: "Vulnerable: a bulk update naming another customer's order changes it (state change). " +
				"Fixed: a bulk update naming any order the caller does not own returns 403 and changes nothing.",
		},
		{
			ID:          "LAB-AUTHZ-PRIVESC-001",
			ScenarioID:  "API-BAS-AUTHZ-004",
			Description: "PATCH /api/me/role lets a customer set their own role, including admin.",
			Oracle: "Vulnerable: a customer sets their own role to admin, then uses the admin route (state change). " +
				"Fixed: the role change is refused with 403, so the admin route refuses the customer too.",
		},
		{
			ID:          "LAB-AUTHZ-PARENT-001",
			ScenarioID:  "API-BAS-AUTHZ-006",
			Description: "GET /api/orders/{id}/items/{itemId} checks the parent order but not that the item belongs to it.",
			Oracle: "Vulnerable: an item of another customer's order, requested through the caller's own parent, returns that order's protected values (exposed). " +
				"Fixed: the item is not found under the parent and the request returns 404.",
		},
		{
			ID:          "LAB-INTEG-INTERNAL-001",
			ScenarioID:  "API-BAS-INTEG-005",
			Description: "The internal route accepts any caller and does not require the internal-service credential.",
			Oracle: "Vulnerable: a customer token reads an internal record and gets its protected values (exposed). " +
				"Fixed: the request without the internal-service credential returns 401 and no record.",
		},
		{
			ID:          "LAB-AUTHZ-EXPORT-001",
			ScenarioID:  "API-BAS-AUTHZ-012",
			Description: "GET /api/exports/{id} returns an export job without checking that the caller owns its order.",
			Oracle: "Vulnerable: another customer's export returns that order's protected values (exposed). " +
				"Fixed: the export is not found for a non-owner and the request returns 404.",
		},
		{
			ID:          "LAB-BIZ-QTY-001",
			ScenarioID:  "API-BAS-BIZ-002",
			Description: "PATCH /api/orders/{id} stores any quantity, including negative values.",
			Oracle: "Vulnerable: the owner sets a negative quantity and it is stored (state change). " +
				"Fixed: a quantity that is not a whole number of at least 1 returns 400 and changes nothing.",
		},
		{
			ID:          "LAB-INTEG-WHSEC-001",
			ScenarioID:  "API-BAS-INTEG-008",
			Description: "GET /api/orders/{id}/integration returns the webhook secret to any authenticated caller.",
			Oracle: "Vulnerable: a non-owner reads the owner's webhook secret (exposed). " +
				"Fixed: a non-owner receives 403 and no secret.",
		},
		{
			ID:          "LAB-DISC-CORS-001",
			ScenarioID:  "API-BAS-DISC-005",
			Description: "GET /api/public/status reflects any request Origin in Access-Control-Allow-Origin.",
			Oracle: "Vulnerable: a request from an untrusted origin receives that origin in Access-Control-Allow-Origin (exposed). " +
				"Fixed: no CORS header is sent, so no origin is granted cross-origin reads.",
		},
		{
			ID:          "LAB-ABUSE-OTP-001",
			ScenarioID:  "API-BAS-ABUSE-001",
			Description: "POST /api/orders/{id}/verify has no limit on failed verification attempts.",
			Oracle: "Vulnerable: every wrong code is answered 401 with no limit, so repeated guesses are all accepted (exploited). " +
				"Fixed: after the attempt limit the request is answered 429 and no further attempts are processed.",
		},
		{
			ID:          "LAB-DATA-CACHE-001",
			ScenarioID:  "API-BAS-DATA-006",
			Description: "GET /api/orders/{id}/status marks an owner's public-field response as publicly cacheable.",
			Oracle: "Vulnerable: the owner's status response carries Cache-Control with public (exposed). " +
				"Fixed: the response carries private, no-store, so a shared cache does not keep it.",
		},
		{
			ID:          "LAB-ABUSE-PAGE-001",
			ScenarioID:  "API-BAS-ABUSE-003",
			Description: "GET /api/orders/page grants any requested page size.",
			Oracle: "Vulnerable: a page request for 100000 items is granted and reported as page_size 100000 (exposed). " +
				"Fixed: a page size above 100 is refused with 400.",
		},
		{
			ID:          "LAB-ABUSE-UPLOAD-001",
			ScenarioID:  "API-BAS-ABUSE-005",
			Description: "POST /api/orders/{id}/attachments reads the body without a size bound.",
			Oracle: "Vulnerable: a 2 MiB attachment is accepted and reported as accepted_bytes 2097152 (exposed). " +
				"Fixed: a body above 1 MiB is refused with 413.",
		},
		{
			ID:          "LAB-ABUSE-REPORT-001",
			ScenarioID:  "API-BAS-ABUSE-002",
			Description: "GET /api/orders/report accepts any number of periods and does the work for each.",
			Oracle: "Vulnerable: a 200-period report is computed in full and reports work_units far above the limit (exposed). " +
				"Fixed: more than 12 periods is refused with 400 before any work is done.",
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
	ID       string `json:"id"`
	OwnerID  string `json:"owner_id"`
	Status   string `json:"status"`
	Tag      string `json:"tag"`
	Quantity string `json:"quantity"`
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
	roles   map[string]string // customer -> role; absent means "customer"
	// otpFailures counts failed verification attempts per caller and order.
	otpFailures map[string]int
	// events is the access log the detection fixture reads. evMu guards it and eventSeq.
	events   []accessEvent
	eventSeq int
	evMu     sync.Mutex
	// itemParent maps an item ID to its parent order. Items are fixed by the
	// fixture, so cleanup and reset never change them.
	itemParent map[string]string
	itemSKU    map[string]string
	audit      []AuditEntry
	// gwMu guards gwCounts, the gateway rate-limit counters (see gateway.go).
	gwMu     sync.Mutex
	gwCounts map[string]int
	// rotated holds the API tokens retired by POST /api/keys/rotate in the fixed build.
	rotated map[string]bool
	// brokerCounts counts accepted publishes per publisher and topic in the fixed build (broker.go).
	brokerCounts map[string]int
	// sharedCache is the response cache of the vulnerable build (LAB-AUTHZ-CACHE-001), keyed by path.
	sharedCache map[string]map[string]any
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
	s.sharedCache = nil
	s.rotated = nil
	s.brokerCounts = nil
	s.roles = make(map[string]string)
	s.otpFailures = make(map[string]int)
	s.itemParent = make(map[string]string)
	s.itemSKU = make(map[string]string)
	s.orders = make(map[string]*Order, len(s.cfg.Fixture.Objects))
	for _, o := range s.cfg.Fixture.Objects {
		for _, it := range o.Items {
			s.itemParent[it.ID] = o.ID
			s.itemSKU[it.ID] = it.SKU
		}
	}
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
	mux.HandleFunc("PATCH /api/orders/bulk", s.bulkUpdate)
	mux.HandleFunc("PATCH /api/me/role", s.setOwnRole)
	mux.HandleFunc("PATCH /api/v2/admin/orders/{id}/status", s.adminSetStatusV2)
	mux.HandleFunc("PATCH /api/admin/orders/{id}/status", s.adminSetStatus)
	mux.HandleFunc("GET /api/v1/orders/{id}", s.getOrderV1)
	mux.HandleFunc("GET /api/orders", s.listOrders)
	mux.HandleFunc("POST /api/webhooks/test", s.testWebhook)
	mux.HandleFunc("GET /internal/orders/{id}", s.internalOrder)
	mux.HandleFunc("GET /api/orders/{id}/items/{itemId}", s.getItem)
	mux.HandleFunc("GET /api/exports/{id}", s.getExport)
	mux.HandleFunc("GET /api/public/status", s.publicStatus)
	mux.HandleFunc("POST /api/orders/{id}/verify", s.verifyCode)
	mux.HandleFunc("GET /api/orders/{id}/integration", s.getIntegration)
	if s.cfg.Mode == ModeVulnerable {
		// LAB-DISC-DEPRECATED-001: the retired v0 route is still served, without auth.
		mux.HandleFunc("GET /api/v0/orders/{id}", s.getOrderV0)
	}
	mux.HandleFunc("POST /lab/token-status", s.adminOnly(s.tokenStatus))
	mux.HandleFunc("GET /api/orders/{id}/summary", s.getSummary)
	mux.HandleFunc("GET /api/orders/{id}/status", s.getStatus)
	mux.HandleFunc("GET /api/orders/page", s.listPage)
	mux.HandleFunc("POST /api/orders/{id}/attachments", s.uploadAttachment)
	mux.HandleFunc("GET /api/orders/report", s.report)
	if s.cfg.Mode == ModeVulnerable {
		// The debug route exists only in the vulnerable build (LAB-DISC-DEBUG-001).
		mux.HandleFunc("GET /debug/orders/{id}", s.debugOrder)
	}
	mux.HandleFunc("GET /lab/state", s.adminOnly(s.getState))
	mux.HandleFunc("POST /lab/orders", s.adminOnly(s.createTagged))
	mux.HandleFunc("DELETE /lab/runs/{tag}", s.adminOnly(s.cleanupRun))
	mux.HandleFunc("POST /lab/reset", s.adminOnly(s.resetFixture))
	mux.HandleFunc("GET /lab/audit", s.adminOnly(s.getAudit))
	mux.HandleFunc("GET /lab/access-events", s.adminOnly(s.getAccessEvents))
	s.registerInjection(mux)
	s.registerGateway(mux)
	s.registerAuthz(mux)
	s.registerDiscovery(mux)
	s.registerRemaining(mux)
	s.registerGraphQL(mux)
	s.registerSOAP(mux)
	s.registerGRPC(mux)
	s.registerWebSocket(mux)
	s.registerBroker(mux)
	mux.HandleFunc("GET /lab/faults", s.adminOnly(s.listFaults))
	if s.cfg.Mode == ModeVulnerable {
		// LAB-GWAY-OVERRIDE-001: the vulnerable build honours a method-override header.
		return s.extractBodyOwner(s.logAccess(s.gateway(methodOverride(mux))))
	}
	return s.extractBodyOwner(s.logAccess(s.gateway(mux)))
}

// listFaults returns the faults the lab was started with, sorted.
func (s *Server) listFaults(w http.ResponseWriter, _ *http.Request) {
	faults := slices.Clone(s.cfg.Faults)
	slices.Sort(faults)
	writeJSON(w, http.StatusOK, faults)
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
	if s.cfg.Mode == ModeVulnerable {
		// LAB-AUTHN-SESSION-001: the vulnerable build trusts a caller-supplied
		// customer header over the identity the token proves.
		if claimed := r.Header.Get("X-Customer-Id"); claimed != "" {
			return claimed, authOK
		}
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
		if s.cfg.Mode == ModeVulnerable {
			// LAB-DATA-ERRLEAK-001: the error echoes the targeted record, with no owner check.
			s.mu.Lock()
			order, found := s.orders[r.PathValue("id")]
			var detail map[string]any
			if found {
				detail = orderBody(order)
			}
			s.mu.Unlock()
			if found {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid json", "record": detail})
				return
			}
		}
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
	if q, ok := fields["quantity"]; ok && !vulnerable {
		// LAB-BIZ-QTY-001: the fixed build accepts only a whole number of at least 1.
		n, isNum := q.(float64)
		if !isNum || n < 1 || n != math.Trunc(n) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "quantity must be a whole number of at least 1"})
			return
		}
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
	if q, ok := fields["quantity"]; ok {
		order.Public["quantity"] = fmt.Sprint(q)
	}
	if v, ok := fields["owner_id"].(string); ok && vulnerable {
		order.OwnerID = v
	}
	if v, ok := fields["status"].(string); ok && vulnerable {
		order.Status = v
	}
	s.record("update", order.Tag, fmt.Sprintf("order %s patched by %s", order.ID, caller))
	// The response carries public fields only, so an owner's own update is never
	// counted as disclosure; the state diff is what grades a write.
	writeJSON(w, http.StatusOK, publicBody(order))
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
		states = append(states, OrderState{ID: o.ID, OwnerID: o.OwnerID, Status: o.Status, Tag: o.Tag, Quantity: o.Public["quantity"]})
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
// getStatus returns the public projection of an order to its owner. It holds no
// protected values, so the caching check is not confused with a data leak. The
// vulnerable build marks the response publicly cacheable (LAB-DATA-CACHE-001); the
// fixed build marks it private, no-store.
func (s *Server) getStatus(w http.ResponseWriter, r *http.Request) {
	caller, st := s.identify(r)
	if st != authOK {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	if s.cfg.Mode == ModeVulnerable {
		w.Header().Set("Cache-Control", "public, max-age=300")
	} else {
		w.Header().Set("Cache-Control", "private, no-store")
	}
	s.mu.Lock()
	order, found := s.orders[r.PathValue("id")]
	var body map[string]any
	if found && order.OwnerID == caller {
		body = publicBody(order)
	}
	s.mu.Unlock()
	if found && body == nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	respondOrder(w, found, body)
}

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

// roleOf returns the role of a customer. Customers default to "customer".
func (s *Server) roleOf(customer string) string {
	if role, ok := s.roles[customer]; ok {
		return role
	}
	return "customer"
}

// setOwnRole is the self-service role endpoint. The vulnerable build accepts any
// role from the caller (LAB-AUTHZ-PRIVESC-001); the fixed build refuses.
func (s *Server) setOwnRole(w http.ResponseWriter, r *http.Request) {
	caller, st := s.identify(r)
	if st != authOK {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	if s.cfg.Mode == ModeFixed {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "role changes are administrative"})
		return
	}
	var req struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Role == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "role is required"})
		return
	}
	s.mu.Lock()
	s.roles[caller] = req.Role
	s.record("role_change", "", fmt.Sprintf("%s set own role to %s", caller, req.Role))
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"role": req.Role})
}

// adminSetStatusV2 is the admin status route used by the escalation chain. It
// enforces the admin role in both builds, so the only planted flaw on the chain
// is the self-service role change.
func (s *Server) adminSetStatusV2(w http.ResponseWriter, r *http.Request) {
	caller, st := s.identify(r)
	if st != authOK {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
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
	if s.roleOf(caller) != "admin" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin role required"})
		return
	}
	order, found := s.orders[r.PathValue("id")]
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	order.Status = req.Status
	s.record("admin_status", order.Tag, fmt.Sprintf("order %s status set by admin", order.ID))
	writeJSON(w, http.StatusOK, map[string]string{"id": order.ID, "status": order.Status})
}

// bulkUpdate sets one status on many orders in a single request. The vulnerable
// build checks nothing per order (LAB-AUTHZ-BULK-001). The fixed build refuses the
// whole request if any listed order is not owned by the caller.
func (s *Server) bulkUpdate(w http.ResponseWriter, r *http.Request) {
	caller, st := s.identify(r)
	if st != authOK {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	var req struct {
		IDs    []string `json:"ids"`
		Status string   `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.IDs) == 0 || req.Status == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ids and status are required"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.Mode == ModeFixed {
		for _, id := range req.IDs {
			order, found := s.orders[id]
			if !found {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
				return
			}
			if order.OwnerID != caller {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
				return
			}
		}
	}
	updated := []string{}
	for _, id := range req.IDs {
		if order, found := s.orders[id]; found {
			order.Status = req.Status
			updated = append(updated, id)
		}
	}
	s.record("bulk_update", "", fmt.Sprintf("%d orders set by %s", len(updated), caller))
	writeJSON(w, http.StatusOK, map[string]any{"updated": updated})
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

// getItem returns one item under a parent order. The caller must own the parent.
// The vulnerable build does not check that the item belongs to the parent
// (LAB-AUTHZ-PARENT-001); the fixed build does.
func (s *Server) getItem(w http.ResponseWriter, r *http.Request) {
	caller, st := s.identify(r)
	if st != authOK {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	parent, found := s.orders[r.PathValue("id")]
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if parent.OwnerID != caller {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	itemID := r.PathValue("itemId")
	itemParent, found := s.itemParent[itemID]
	if !found || (s.cfg.Mode == ModeFixed && itemParent != parent.ID) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	// The item body carries its real parent's payer account, which is protected.
	owner := s.orders[itemParent]
	writeJSON(w, http.StatusOK, map[string]any{
		"id":            itemID,
		"order_id":      itemParent,
		"sku":           s.itemSKU[itemID],
		"payer_account": owner.Protected["account_ref"],
	})
}

// getExport returns an export job. Each export is for one order and carries that
// order's protected values. The vulnerable build does not check ownership
// (LAB-AUTHZ-EXPORT-001); the fixed build answers 404 to anyone but the owner.
func (s *Server) getExport(w http.ResponseWriter, r *http.Request) {
	caller, st := s.identify(r)
	if st != authOK {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	exportID := r.PathValue("id")
	s.mu.Lock()
	defer s.mu.Unlock()
	order, found := s.orders["ORD-"+strings.TrimPrefix(exportID, "EXP-")]
	if !strings.HasPrefix(exportID, "EXP-") || !found || (s.cfg.Mode == ModeFixed && order.OwnerID != caller) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":       exportID,
		"order_id": order.ID,
		"status":   "ready",
		"order":    orderBody(order),
	})
}

// getIntegration returns the webhook secret of an order. The secret is protected
// and belongs to the owner. The vulnerable build returns it to any caller
// (LAB-INTEG-WHSEC-001); the fixed build answers 403 to anyone but the owner.
func (s *Server) getIntegration(w http.ResponseWriter, r *http.Request) {
	caller, st := s.identify(r)
	if st != authOK {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	order, found := s.orders[r.PathValue("id")]
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if s.cfg.Mode == ModeFixed && order.OwnerID != caller {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"order_id":       order.ID,
		"webhook_secret": order.Protected["webhook_secret"],
	})
}

// publicStatus is an unauthenticated status route. The vulnerable build reflects
// any request's Origin in Access-Control-Allow-Origin (LAB-DISC-CORS-001), which
// lets a page on any site read the response. The fixed build refuses untrusted origins.
func (s *Server) publicStatus(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if s.cfg.Mode == ModeVulnerable {
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
	} else if origin != "" {
		// The fixed build refuses cross-origin requests from any origin it does not
		// trust. This lab has no trusted origins, so every Origin header is refused.
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "origin not permitted"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// otpAttemptLimit is how many failed verification attempts the fixed build accepts
// per caller and order before it answers 429.
const otpAttemptLimit = 3

// verifyCode checks a one-time code for an order. Every code the lab is sent is
// wrong, so each call is a failed attempt. The vulnerable build sets no limit
// (LAB-ABUSE-OTP-001); the fixed build answers 429 after otpAttemptLimit failures.
func (s *Server) verifyCode(w http.ResponseWriter, r *http.Request) {
	caller, st := s.identify(r)
	if st != authOK {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	order, found := s.orders[r.PathValue("id")]
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if s.cfg.Mode == ModeFixed && order.OwnerID != caller {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	key := caller + "|" + order.ID
	if s.cfg.Mode == ModeFixed && s.otpFailures[key] >= otpAttemptLimit {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many attempts"})
		return
	}
	s.otpFailures[key]++
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid code"})
}

// listPage returns the caller's own orders, up to a page size the caller requests.
// The vulnerable build grants any requested size (LAB-ABUSE-PAGE-001); the fixed
// build refuses sizes above 100. The granted size is reported as page_size, so the
// grader compares what the server allowed with the scenario's declared maximum.
func (s *Server) listPage(w http.ResponseWriter, r *http.Request) {
	caller, st := s.identify(r)
	if st != authOK {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	limit := 20
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be a positive integer"})
			return
		}
		limit = n
	}
	if s.cfg.Mode == ModeFixed && limit > 100 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be 100 or less"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.orders))
	for id := range s.orders {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	items := []map[string]any{}
	for _, id := range ids {
		if len(items) == limit {
			break
		}
		if o := s.orders[id]; o.OwnerID == caller {
			items = append(items, publicBody(o))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"page_size": limit, "items": items})
}

// maxAttachmentBytes is the largest attachment the fixed build accepts.
const maxAttachmentBytes = 1 << 20

// uploadAttachment accepts an attachment for an order the caller owns and reports
// how many bytes it accepted. The vulnerable build reads the body without a bound
// (LAB-ABUSE-UPLOAD-001); the fixed build refuses bodies above 1 MiB with 413. The
// lab keeps no attachment: the accepted size is reported, not stored.
func (s *Server) uploadAttachment(w http.ResponseWriter, r *http.Request) {
	caller, st := s.identify(r)
	if st != authOK {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	s.mu.Lock()
	order, found := s.orders[r.PathValue("id")]
	owned := found && order.OwnerID == caller
	s.mu.Unlock()
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if !owned {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	var body io.Reader = r.Body
	if s.cfg.Mode == ModeFixed {
		body = http.MaxBytesReader(w, r.Body, maxAttachmentBytes)
	}
	n, err := io.Copy(io.Discard, body)
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "attachment too large"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"order_id": order.ID, "accepted_bytes": n})
}

// reportPeriodLimit is the most periods the fixed build computes. reportWorkPerPeriod
// is the number of hash rounds per period; the work is real, so its cost is measured.
const (
	reportPeriodLimit   = 12
	reportWorkPerPeriod = 2000
)

// report computes a summary over a number of periods. Each period is a chain of
// SHA-256 rounds over a 1 KiB buffer, so the cost is the work actually done. The
// vulnerable build computes any number of periods (LAB-ABUSE-REPORT-001); the fixed
// build refuses more than reportPeriodLimit before doing any work.
func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	if _, st := s.identify(r); st != authOK {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	periods := 1
	if raw := r.URL.Query().Get("periods"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "periods must be a positive integer"})
			return
		}
		periods = n
	}
	if s.cfg.Mode == ModeFixed && periods > reportPeriodLimit {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "periods must be 12 or fewer"})
		return
	}
	buf := make([]byte, 1024)
	var digest [32]byte
	for i := 0; i < periods*reportWorkPerPeriod; i++ {
		digest = sha256.Sum256(buf)
		copy(buf, digest[:])
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"periods":    periods,
		"work_units": periods * reportWorkPerPeriod,
		"digest":     hex.EncodeToString(digest[:8]),
	})
}

// getOrderV0 is the retired route (LAB-DISC-DEPRECATED-001). It is mounted only in
// the vulnerable build and serves the full record with no credential.
func (s *Server) getOrderV0(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	order, found := s.orders[r.PathValue("id")]
	var body map[string]any
	if found {
		body = orderBody(order)
	}
	s.mu.Unlock()
	respondOrder(w, found, body)
}

// internalOrder is an internal-only record route. The vulnerable build serves it
// to any caller (LAB-INTEG-INTERNAL-001), which is also the target the SSRF
// scenario reaches. The fixed build requires the internal-service credential.
func (s *Server) internalOrder(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Mode == ModeFixed {
		if s.cfg.InternalToken == "" || r.Header.Get("X-Internal-Token") != s.cfg.InternalToken {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "internal credential required"})
			return
		}
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

// testWebhook checks a webhook destination by fetching it. The vulnerable build
// fetches any URL and returns the response body to the caller; the fixed build
// refuses loopback and private destinations (LAB-INTEG-SSRF-001).
func (s *Server) testWebhook(w http.ResponseWriter, r *http.Request) {
	_, st := s.identify(r)
	if st != authOK {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	var req struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.URL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "url is required"})
		return
	}
	if s.cfg.Mode == ModeFixed && internalDestination(req.URL) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "destination not allowed"})
		return
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(req.URL)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "fetch failed"})
		return
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	writeJSON(w, http.StatusOK, map[string]any{"status": resp.StatusCode, "body": string(raw)})
}

// internalDestination reports whether a URL points at a loopback or private
// address, or at localhost.
func internalDestination(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return true
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified()
}
