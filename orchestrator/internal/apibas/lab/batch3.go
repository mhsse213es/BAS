package lab

// Phase 3 batch 3: INTEG-001, 002, 006, 007, 009, 011 and DISC-006, 010. In-process HTTP routes. Each has a vulnerable
// branch with a planted flaw and a fixed branch with the control. Expectations are in the catalog and the runner tests.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// b3WebhookSecret signs webhook deliveries (INTEG-002).
const b3WebhookSecret = "BAS-WEBHOOK-SIGN-SECRET"

// b3PartnerToken is the partner integration credential, sent in X-Partner-Token (INTEG-009). The fixed build allows the partner only for the
// customers in b3PartnerCustomers.
const b3PartnerToken = "BAS-PARTNER-ACME"

var b3PartnerCustomers = map[string]bool{"cust-b": true}

// b3CallbackHost is the only callback host the fixed build registers (INTEG-011).
const b3CallbackHost = "hooks.partner.example"

// b3FraudFault is the dependency fault that takes the fraud check down (INTEG-007).
const b3FraudFault = "fraud-check-down"

// b3PartnerQuote is the partner's quote for a SKU. The hostile SKU returns a quantity outside the partner contract.
func b3PartnerQuote(sku string) string {
	if sku == "SKU-PARTNER-HOSTILE" {
		return "-5"
	}
	return "1"
}

func (s *Server) registerBatch3(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/orders/{id}/quote-refresh", s.quoteRefresh)
	mux.HandleFunc("POST /api/webhooks/events", s.webhookEvent)
	mux.HandleFunc("GET /api/proxy/orders/{id}", s.proxyOrder)
	mux.HandleFunc("POST /api/orders/{id}/authorize-payment", s.authorizePayment)
	mux.HandleFunc("GET /api/partner/orders/{id}", s.partnerOrder)
	mux.HandleFunc("POST /api/integrations/callbacks", s.registerCallback)
	mux.HandleFunc("GET /api/orders/{id}/details", s.orderDetails)
	mux.HandleFunc("GET /api/regional/orders/{id}", s.regionalOrder)
}

func batch3Flaws() []Flaw {
	return []Flaw{
		{ID: "LAB-INTEG-PARTNER-001", ScenarioID: "API-BAS-INTEG-001", Description: "POST /api/orders/{id}/quote-refresh applies the partner's quantity without checking the partner contract.", Oracle: "the order quantity becomes a value outside the contract"},
		{ID: "LAB-INTEG-REPLAY-001", ScenarioID: "API-BAS-INTEG-002", Description: "POST /api/webhooks/events verifies the signature but accepts a replayed event.", Oracle: "more deliveries of one event are accepted in a run than the declared maximum"},
		{ID: "LAB-INTEG-CONFDEP-001", ScenarioID: "API-BAS-INTEG-006", Description: "GET /api/proxy/orders/{id} acts as the identity named in X-Act-As without checking the caller may do so.", Oracle: "another tenant's protected values are returned to the caller through the proxy"},
		{ID: "LAB-INTEG-FAILOPEN-001", ScenarioID: "API-BAS-INTEG-007", Description: "POST /api/orders/{id}/authorize-payment approves the payment when the fraud check is down.", Oracle: "the order is authorized while the fraud check is unavailable"},
		{ID: "LAB-INTEG-PARTNERTRUST-001", ScenarioID: "API-BAS-INTEG-009", Description: "GET /api/partner/orders/{id} trusts any customer the partner names in X-Partner-Customer.", Oracle: "another tenant's protected values are returned to a partner not authorized for that tenant"},
		{ID: "LAB-INTEG-CALLBACK-001", ScenarioID: "API-BAS-INTEG-011", Description: "POST /api/integrations/callbacks registers any callback URL, with no host allowlist.", Oracle: "more callback URLs outside the allowlist are registered in a run than the declared maximum"},
		{ID: "LAB-DISC-ENVAUTH-001", ScenarioID: "API-BAS-DISC-006", Description: "GET /api/orders/{id}/details skips authentication when X-Environment is staging.", Oracle: "protected values are returned to an anonymous caller in the staging environment"},
		{ID: "LAB-DISC-REGION-001", ScenarioID: "API-BAS-DISC-010", Description: "GET /api/regional/orders/{id} in the legacy region skips the owner check.", Oracle: "another tenant's protected values are returned from the legacy region"},
	}
}

// quoteRefresh applies a partner quote to an order. The fixed build applies only a quantity within the contract (INTEG-001).
func (s *Server) quoteRefresh(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	var req struct {
		SKU string `json:"sku"`
	}
	if err := decodeJSON(r, &req); err != nil || req.SKU == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "sku is required"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	o, found := s.orders[r.PathValue("id")]
	if !found || o.OwnerID != caller {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	q := b3PartnerQuote(req.SKU)
	if n, err := strconv.Atoi(q); !s.vulnerable() && (err != nil || n < 1 || n > 100) {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "partner quantity outside contract"})
		return
	}
	o.Public["quantity"] = q
	writeJSON(w, http.StatusOK, map[string]string{"quantity": q})
}

// webhookEvent receives a signed event. Both builds verify the signature over timestamp and body. Only the fixed build
// refuses a replayed event ID in the run (INTEG-002).
func (s *Server) webhookEvent(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	ts := r.Header.Get("X-BAS-Timestamp")
	mac := hmac.New(sha256.New, []byte(b3WebhookSecret))
	mac.Write([]byte(ts + "." + string(raw)))
	want := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(r.Header.Get("X-BAS-Signature"))) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad signature"})
		return
	}
	var ev struct {
		EventID string `json:"event_id"`
	}
	if err := json.Unmarshal(raw, &ev); err != nil || ev.EventID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "event_id is required"})
		return
	}
	if !s.vulnerable() && !s.countUnder("evt|"+r.Header.Get("X-BAS-Run")+"|"+ev.EventID, 1) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "event already delivered"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "accepted"})
}

// proxyOrder reads an order as the identity named in X-Act-As. The fixed build allows acting only as the caller
// (INTEG-006).
func (s *Server) proxyOrder(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	effective := caller
	if act := r.Header.Get("X-Act-As"); act != "" {
		if !s.vulnerable() && act != caller {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "cannot act as another identity"})
			return
		}
		effective = act
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	o, found := s.orders[r.PathValue("id")]
	if !found || o.OwnerID != effective {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": o.ID, "fields": mergeFields(o.Public, o.Protected)})
}

// authorizePayment authorizes an order's payment through the fraud check. When the check is down, the fixed build fails
// closed and the vulnerable build fails open (INTEG-007).
func (s *Server) authorizePayment(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	o, found := s.orders[r.PathValue("id")]
	if !found || o.OwnerID != caller {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	if s.faultOn(b3FraudFault) && !s.vulnerable() {
		writeJSON(w, http.StatusFailedDependency, map[string]string{"error": "fraud check unavailable"})
		return
	}
	o.Status = "authorized"
	writeJSON(w, http.StatusOK, map[string]string{"status": o.Status})
}

// partnerOrder serves an order to an integration partner on behalf of a customer the partner names. The fixed build
// serves only customers the partner is authorized for (INTEG-009).
func (s *Server) partnerOrder(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Partner-Token") != b3PartnerToken {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	customer := r.Header.Get("X-Partner-Customer")
	if customer == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "X-Partner-Customer is required"})
		return
	}
	if !s.vulnerable() && !b3PartnerCustomers[customer] {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "partner not authorized for this customer"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	o, found := s.orders[r.PathValue("id")]
	if !found || o.OwnerID != customer {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": o.ID, "fields": mergeFields(o.Public, o.Protected)})
}

// b3CallbackAllowed reports whether a callback URL is https on the allowlisted host (INTEG-011).
func b3CallbackAllowed(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host == b3CallbackHost
}

// registerCallback registers a webhook callback. The fixed build registers only allowlisted hosts (INTEG-011).
func (s *Server) registerCallback(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	var req struct {
		URL string `json:"url"`
	}
	if err := decodeJSON(r, &req); err != nil || req.URL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "url is required"})
		return
	}
	noteDestination(r, DestCallback, req.URL)
	if !s.vulnerable() && !b3CallbackAllowed(req.URL) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "callback host not allowlisted"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"owner": caller, "url": req.URL, "status": "registered"})
}

// orderDetails returns an order's details. In the staging environment the vulnerable build skips authentication
// (DISC-006). The fixed build requires authentication in every environment.
func (s *Server) orderDetails(w http.ResponseWriter, r *http.Request) {
	env := r.Header.Get("X-Environment")
	if env == "staging" && s.vulnerable() {
		s.mu.Lock()
		defer s.mu.Unlock()
		o, found := s.orders[r.PathValue("id")]
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": o.ID, "env": env, "fields": mergeFields(o.Public, o.Protected)})
		return
	}
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	o, found := s.orders[r.PathValue("id")]
	if !found || o.OwnerID != caller {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": o.ID, "env": "production", "fields": o.Public})
}

// regionalOrder returns an order from a region. The legacy region's gateway skips the owner check in the vulnerable
// build (DISC-010). The fixed build applies the owner check in every region.
func (s *Server) regionalOrder(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	legacy := r.Header.Get("X-Region") == "legacy-eu" && s.vulnerable()
	s.mu.Lock()
	defer s.mu.Unlock()
	o, found := s.orders[r.PathValue("id")]
	if !found || (!legacy && o.OwnerID != caller) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	fields := o.Public
	if legacy {
		fields = mergeFields(o.Public, o.Protected)
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": o.ID, "region": r.Header.Get("X-Region"), "fields": fields})
}
