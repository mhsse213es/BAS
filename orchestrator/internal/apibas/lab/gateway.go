package lab

// Gateway tranche (API-BAS-GWAY-001 to 011). The gateway is a policy layer in front of the
// routes. Its rules apply only under /api/gw/, so the routes used by the other scenarios are
// unchanged.
//
// The lab is a single listener, so there is no separate gateway process. "Direct backend
// access" (GWAY-001) is modelled as a request that reaches a route with the gateway's
// identity header and skips the gateway's checks. Each rule has a vulnerable branch and a
// fixed branch. The vulnerable branch carries a LAB-GWAY-* flaw from gatewayFlaws.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
)

const (
	gwPrefix    = "/api/gw/"
	gwRateLimit = 5 // requests per run and caller on GET /api/gw/orders/{id}
)

// gwBypassKey marks a request that reached a route without the gateway's checks.
type gwBypassKey struct{}

func gwBypassed(r *http.Request) bool {
	v, _ := r.Context().Value(gwBypassKey{}).(bool)
	return v
}

func withBypass(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), gwBypassKey{}, true))
}

// faultOn reports whether the lab was started with the named fault.
func (s *Server) faultOn(name string) bool {
	return slices.Contains(s.cfg.Faults, name)
}

// adminRequest reports whether the request carries the lab admin credential. The empty
// token never matches, so an unset admin token cannot be presented as a valid one.
func (s *Server) adminRequest(r *http.Request) bool {
	return s.cfg.AdminToken != "" && r.Header.Get("X-Lab-Admin") == s.cfg.AdminToken
}

// tokenFor returns a live bearer token for the customer, or "" when none exists.
func (s *Server) tokenFor(customer string) string {
	for _, t := range slices.Sorted(maps.Keys(s.cfg.Tokens)) {
		if s.cfg.Tokens[t] == customer && !s.revoked[t] {
			return t
		}
	}
	return ""
}

// gwScope returns the path the gateway matches its rules against. The vulnerable build
// matches the path as sent (escaped). The fixed build matches the decoded, cleaned path.
// The mux routes on the decoded path in both builds, so an encoded path is a bypass only
// in the vulnerable build.
func (s *Server) gwScope(r *http.Request) string {
	if s.vulnerable() {
		return path.Clean(r.URL.EscapedPath())
	}
	return path.Clean(r.URL.Path)
}

// gateway applies the gateway rules to requests under /api/gw/ and passes everything else
// through unchanged.
func (s *Server) gateway(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scope := s.gwScope(r)
		if !strings.HasPrefix(scope, gwPrefix) {
			next.ServeHTTP(w, r)
			return
		}
		vuln := s.vulnerable()
		bypass := false

		// Identity. The vulnerable gateway trusts an identity header from any client, and
		// lets a legacy-region node serve reads without a credential.
		if vuln {
			if id := r.Header.Get("X-Gateway-Identity"); id != "" {
				// LAB-GWAY-IDTRUST-001: the identity header replaces the caller's credential,
				// whichever credential the client sent.
				if tok := s.tokenFor(id); tok != "" {
					r.Header.Set("Authorization", "Bearer "+tok)
					bypass = true
				}
			} else if r.Header.Get("Authorization") == "" && r.Header.Get("X-Gateway-Region") == "legacy" {
				// LAB-GWAY-REGION-001: the legacy region serves reads with no credential.
				bypass = true
			}
		}

		// Rate limit: keyed by run and caller in the fixed build, and by a client-supplied
		// source address in the vulnerable build.
		if strings.HasPrefix(scope, "/api/gw/orders/") && r.Method == http.MethodGet {
			if s.gwOverLimit(s.gwRateKey(r)) {
				writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
				return
			}
		}

		// Ops routes need the admin credential. The vulnerable build also accepts a forwarded
		// host of ops.internal, which LAB-GWAY-HOSTTRUST-001 treats as an internal caller.
		if strings.HasPrefix(scope, "/api/gw/ops/") && !s.adminRequest(r) {
			trustedHost := vuln && r.Header.Get("X-Forwarded-Host") == "ops.internal"
			if !trustedHost {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin credential required"})
				return
			}
		}

		// WAF rule on the search route. The vulnerable rule matches the raw query.
		if scope == "/api/gw/search" && s.wafBlocks(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "blocked by WAF rule"})
			return
		}

		// Request schema on the quantity route. The vulnerable build applies no schema.
		if !vuln && r.Method == http.MethodPost && isQuantityPath(scope) {
			if msg := quantityViolation(r); msg != "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
				return
			}
		}

		// Ownership. The gateway decides ownership for order reads. The authorization store
		// is consulted, and when it is down the fixed build fails closed.
		if isOrderRead(scope, r.Method) && !bypass {
			if s.faultOn("authz-store-down") {
				if !vuln {
					writeJSON(w, http.StatusForbidden, map[string]string{"error": "authorization decision unavailable; denied"})
					return
				}
				// LAB-GWAY-FAILOPEN-001: the vulnerable gateway allows the request when the
				// authorization store is down.
				bypass = true
			} else if status := s.gwAuthorizeRead(r, scope); status != 0 {
				writeJSON(w, status, map[string]string{"error": http.StatusText(status)})
				return
			}
		}

		if bypass {
			r = withBypass(r)
		}
		next.ServeHTTP(w, r)
	})
}

// isOrderRead matches GET /api/gw/orders/{id} with exactly one path segment after orders.
func isOrderRead(scope, method string) bool {
	rest, ok := strings.CutPrefix(scope, "/api/gw/orders/")
	return ok && method == http.MethodGet && rest != "" && !strings.Contains(rest, "/")
}

// isQuantityPath matches /api/gw/orders/{id}/quantity.
func isQuantityPath(scope string) bool {
	rest, ok := strings.CutPrefix(scope, "/api/gw/orders/")
	return ok && strings.HasSuffix(rest, "/quantity")
}

// gwAuthorizeRead returns 0 when the caller is the order's owner, and otherwise the status
// to answer with. The gateway runs before the mux, so the order ID is read from the path.
func (s *Server) gwAuthorizeRead(r *http.Request, scope string) int {
	caller, st := s.identify(r)
	if st != authOK {
		return http.StatusUnauthorized
	}
	id, _ := strings.CutPrefix(scope, "/api/gw/orders/")
	s.mu.Lock()
	o, found := s.orders[id]
	owned := found && o.OwnerID == caller
	s.mu.Unlock()
	if !owned {
		return http.StatusNotFound
	}
	return 0
}

// gwRateKey is the counter key for the rate limit.
func (s *Server) gwRateKey(r *http.Request) string {
	run := r.Header.Get("X-BAS-Run")
	if s.vulnerable() {
		// LAB-GWAY-RATE-001: the counter trusts a client-supplied source address.
		return run + "|xff|" + r.Header.Get("X-Forwarded-For")
	}
	caller, _ := s.identify(r)
	return run + "|id|" + caller
}

// gwOverLimit counts one request under key and reports whether the key is over the limit.
func (s *Server) gwOverLimit(key string) bool {
	s.gwMu.Lock()
	defer s.gwMu.Unlock()
	if s.gwCounts == nil {
		s.gwCounts = map[string]int{}
	}
	s.gwCounts[key]++
	return s.gwCounts[key] > gwRateLimit
}

// wafBlocks reports whether the WAF rule blocks the search request.
func (s *Server) wafBlocks(r *http.Request) bool {
	if s.vulnerable() {
		// LAB-GWAY-WAF-001: the rule matches the raw query, so an encoded space evades it.
		raw := strings.ToUpper(r.URL.RawQuery)
		return strings.Contains(raw, " OR ") || strings.Contains(raw, "+OR+")
	}
	q := " " + strings.ToUpper(r.URL.Query().Get("q")) + " "
	return strings.Contains(q, " OR ")
}

// quantityViolation returns why a fixed-build quantity update is refused, or "" when it is
// allowed. The rule is one Content-Type header, a JSON object, and only the quantity field.
// The body is read and restored, so the handler still receives it.
func quantityViolation(r *http.Request) string {
	if len(r.Header.Values("Content-Type")) != 1 {
		return "exactly one Content-Type header is required"
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		return "unreadable body"
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return "body must be a JSON object"
	}
	for k := range fields {
		if k != "quantity" {
			return "unknown field: " + k
		}
	}
	var q string
	if raw, ok := fields["quantity"]; !ok || json.Unmarshal(raw, &q) != nil {
		return "quantity must be a string"
	}
	return ""
}

// registerGateway adds the gateway-fronted routes to the mux.
func (s *Server) registerGateway(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/gw/orders/{id}", s.gwGetOrder)
	mux.HandleFunc("POST /api/gw/orders/{id}/quantity", s.gwQuantity)
	mux.HandleFunc("POST /api/gw/ops/orders/{id}/cancel", s.gwCancel)
	mux.HandleFunc("GET /api/gw/search", s.injSearchOrders)
	if s.vulnerable() {
		// LAB-GWAY-SHADOW-001: an undocumented route the gateway does not publish, served
		// with no gateway policy.
		mux.HandleFunc("GET /api/gw/orders/{id}/legacy", s.gwLegacy)
	}
}

// gwGetOrder returns the order. The owner sees the public view. A request that reached it
// without the gateway's checks (bypass) gets the full record.
func (s *Server) gwGetOrder(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	o, found := s.orders[r.PathValue("id")]
	var body map[string]any
	if found {
		if gwBypassed(r) {
			body = orderBody(o)
		} else {
			body = publicView(o)
		}
	}
	s.mu.Unlock()
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	writeJSON(w, http.StatusOK, body)
}

// gwLegacy is the undocumented read route, served in the vulnerable build only.
func (s *Server) gwLegacy(w http.ResponseWriter, r *http.Request) {
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

// gwQuantity updates an order's quantity. The owner may update it. The vulnerable build
// also applies a status field, and reads a form-encoded body when that is the last
// Content-Type header (LAB-GWAY-DUPHDR-001). It also accepts unknown fields (LAB-GWAY-SCHEMA-001).
func (s *Server) gwQuantity(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	fields := map[string]string{}
	ct := r.Header.Values("Content-Type")
	last := ""
	if len(ct) > 0 {
		last = ct[len(ct)-1]
	}
	if s.vulnerable() && strings.HasPrefix(last, "application/x-www-form-urlencoded") {
		vals, err := parseFormBody(body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid form"})
			return
		}
		maps.Copy(fields, vals)
	} else {
		var m map[string]any
		if json.Unmarshal(body, &m) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
			return
		}
		for k, v := range m {
			if str, isString := v.(string); isString {
				fields[k] = str
			}
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	o, found := s.orders[r.PathValue("id")]
	if !found || o.OwnerID != caller {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	if q, has := fields["quantity"]; has {
		if o.Public == nil {
			o.Public = map[string]string{}
		}
		o.Public["quantity"] = q
	}
	if st, has := fields["status"]; has && s.vulnerable() {
		o.Status = st
	}
	writeJSON(w, http.StatusOK, map[string]bool{"saved": true})
}

// parseFormBody parses a form-encoded body into its first value per key.
func parseFormBody(body []byte) (map[string]string, error) {
	vals, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(vals))
	for k := range vals {
		out[k] = vals.Get(k)
	}
	return out, nil
}

// gwCancel cancels an order. Only the admin credential may call it in the fixed build. The
// vulnerable build relies on the gateway for that, and the gateway can be bypassed.
func (s *Server) gwCancel(w http.ResponseWriter, r *http.Request) {
	if !s.vulnerable() && !s.adminRequest(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin credential required"})
		return
	}
	s.mu.Lock()
	o, found := s.orders[r.PathValue("id")]
	if found {
		o.Status = "cancelled"
	}
	s.mu.Unlock()
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelled"})
}

// gatewayFlaws names the planted gateway flaws. Each is present only in ModeVulnerable.
func gatewayFlaws() []Flaw {
	return []Flaw{
		{ID: "LAB-GWAY-IDTRUST-001", ScenarioID: "API-BAS-GWAY-001", Description: "GET /api/gw/orders/{id} trusts X-Gateway-Identity from any client and skips the gateway's checks.", Oracle: "protected values of the named customer's order appear without a credential"},
		{ID: "LAB-GWAY-SHADOW-001", ScenarioID: "API-BAS-GWAY-002", Description: "GET /api/gw/orders/{id}/legacy is served with no gateway policy and no credential.", Oracle: "protected values of an order appear without a credential"},
		{ID: "LAB-GWAY-PATHNORM-001", ScenarioID: "API-BAS-GWAY-004", Description: "The ops rule matches the escaped path, so an encoded segment reaches POST /api/gw/ops/.../cancel.", Oracle: "the order status changes through an ops route a customer may not call"},
		{ID: "LAB-GWAY-DUPHDR-001", ScenarioID: "API-BAS-GWAY-005", Description: "The gateway accepts a request with two Content-Type headers, and the handler reads the last one as a form.", Oracle: "the order status changes through a field the schema refuses"},
		{ID: "LAB-GWAY-HOSTTRUST-001", ScenarioID: "API-BAS-GWAY-006", Description: "The ops rule trusts X-Forwarded-Host: ops.internal from any client.", Oracle: "the order status changes through an ops route a customer may not call"},
		{ID: "LAB-GWAY-WAF-001", ScenarioID: "API-BAS-GWAY-007", Description: "The WAF rule matches the raw query, so an encoded space evades it and the search predicate is injected.", Oracle: "protected values of another customer's order appear in the search response"},
		{ID: "LAB-GWAY-SCHEMA-001", ScenarioID: "API-BAS-GWAY-008", Description: "POST /api/gw/orders/{id}/quantity has no request schema and applies an unexpected status field.", Oracle: "the order status changes through a field the schema refuses"},
		{ID: "LAB-GWAY-RATE-001", ScenarioID: "API-BAS-GWAY-009", Description: "The rate limit is keyed by a client-supplied X-Forwarded-For, so varying it removes the limit.", Oracle: "more than the declared number of requests are accepted for one caller"},
		{ID: "LAB-GWAY-REGION-001", ScenarioID: "API-BAS-GWAY-010", Description: "The legacy region node serves GET /api/gw/orders/{id} with no credential.", Oracle: "protected values of an order appear without a credential"},
		{ID: "LAB-GWAY-FAILOPEN-001", ScenarioID: "API-BAS-GWAY-011", Description: "When the authorization store is down, the gateway allows the order read instead of failing closed.", Oracle: "protected values of another customer's order appear while the store is down"},
	}
}
