package lab

// The last six Phase 2 scenarios: DATA-002, DATA-008, ABUSE-008, ABUSE-009, AUTHN-006 and
// INTEG-004. Routes live under their own prefixes so the routes of other scenarios are unchanged.
// Each route carries a vulnerable branch with a LAB-* flaw and a fixed branch with the control.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func (s *Server) registerRemaining(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/data/orders/{id}/statement", s.dataStatement)
	mux.HandleFunc("GET /api/data/orders/{id}/card", s.dataCard)
	mux.HandleFunc("POST /api/abuse/signup", s.abuseSignup)
	mux.HandleFunc("GET /api/abuse/quote", s.abuseQuote)
	mux.HandleFunc("POST /api/keys/rotate", s.keysRotate)
	mux.HandleFunc("PATCH /api/keys/orders/{id}/status", s.keysStatus)
	mux.HandleFunc("GET /api/integrations/return", s.integReturn)
}

// decodeJSON reads a bounded JSON body into v.
func decodeJSON(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(v)
}

// bearerToken returns the bearer credential, or "" when none is presented.
func bearerToken(r *http.Request) string {
	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return tok
}

// dataStatement returns an order statement. The fixed build returns the public view to the
// owner. The vulnerable build returns the full record, with its financial and account
// fields, to any authenticated caller (LAB-DATA-PII-001).
func (s *Server) dataStatement(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	o, found := s.orders[r.PathValue("id")]
	if !found || (!s.vulnerable() && o.OwnerID != caller) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	if s.vulnerable() {
		writeJSON(w, http.StatusOK, orderBody(o))
		return
	}
	writeJSON(w, http.StatusOK, publicView(o))
}

// maskAllButLast4 hides every character except the last four.
func maskAllButLast4(v string) string {
	if len(v) <= 4 {
		return strings.Repeat("*", len(v))
	}
	return strings.Repeat("*", len(v)-4) + v[len(v)-4:]
}

// dataCard returns the masked card for the owner. The vulnerable build also returns the same
// value unmasked in card_display, so the masking is bypassed (LAB-DATA-MASK-001).
func (s *Server) dataCard(w http.ResponseWriter, r *http.Request) {
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
	body := map[string]any{"card_masked": maskAllButLast4(o.Protected["card_last4"])}
	if s.vulnerable() {
		body["card_display"] = o.Protected["card_last4"]
	}
	writeJSON(w, http.StatusOK, body)
}

// abuseSignup creates an account for an email address. The fixed build allows five per run
// and refuses the rest with 429. The vulnerable build has no limit (LAB-ABUSE-SIGNUP-001).
func (s *Server) abuseSignup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Email == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email is required"})
		return
	}
	if !s.vulnerable() && s.gwOverLimit("signup|"+r.Header.Get("X-BAS-Run")) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many sign-ups"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "created"})
}

// abuseQuote returns a price. The fixed build limits requests per caller and run. The
// vulnerable build limits them per client-supplied session, so new sessions reset the limit
// (LAB-ABUSE-SESSION-001).
func (s *Server) abuseQuote(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	run := r.Header.Get("X-BAS-Run")
	key := "quote|" + run + "|principal|" + caller
	if s.vulnerable() {
		key = "quote|" + run + "|session|" + r.Header.Get("X-Session-Id")
	}
	if s.gwOverLimit(key) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"price": "42.00"})
}

// keysRotate retires the caller's current API token. The fixed build refuses the retired token
// from then on. The vulnerable build keeps accepting it (LAB-AUTHN-ROTATE-001).
func (s *Server) keysRotate(w http.ResponseWriter, r *http.Request) {
	tok := bearerToken(r)
	if _, ok := s.cfg.Tokens[tok]; !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return
	}
	if !s.vulnerable() {
		s.mu.Lock()
		if s.rotated == nil {
			s.rotated = map[string]bool{}
		}
		s.rotated[tok] = true
		s.mu.Unlock()
	}
	writeJSON(w, http.StatusOK, map[string]bool{"rotated": true})
}

// keysStatus changes an owner's order status with the caller's API token. The fixed build
// refuses a token that was rotated out.
func (s *Server) keysStatus(w http.ResponseWriter, r *http.Request) {
	tok := bearerToken(r)
	customer, ok := s.cfg.Tokens[tok]
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return
	}
	var req struct {
		Status string `json:"status"`
	}
	if err := decodeJSON(r, &req); err != nil || !validStatuses[req.Status] {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid status"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.vulnerable() && s.rotated[tok] {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "token rotated"})
		return
	}
	o, found := s.orders[r.PathValue("id")]
	if !found || o.OwnerID != customer {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	o.Status = req.Status
	writeJSON(w, http.StatusOK, map[string]string{"status": o.Status})
}

// integReturn answers with a 200 page that sends the browser on to next. The fixed build
// accepts only a relative path. The vulnerable build accepts any target
// (LAB-INTEG-REDIRECT-001). The target travels in a Refresh header, not a 3xx status, so a
// client that follows redirects does not leave the lab.
func (s *Server) integReturn(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireCaller(w, r); !ok {
		return
	}
	next := r.URL.Query().Get("next")
	noteDestination(r, DestRedirect, next)
	if !s.vulnerable() && !isRelativePath(next) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "next must be a relative path"})
		return
	}
	if next != "" {
		w.Header().Set("Refresh", "0; url="+next)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "<!doctype html><title>Return</title><p>Returning you to the application.</p>")
}

// isRelativePath accepts a path on this host only. It refuses scheme-relative and absolute
// URLs, and backslashes that browsers treat as separators.
func isRelativePath(p string) bool {
	return strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") && !strings.ContainsRune(p, '\\')
}

// remainingFlaws names the planted flaws of the last six scenarios.
func remainingFlaws() []Flaw {
	return []Flaw{
		{ID: "LAB-DATA-PII-001", ScenarioID: "API-BAS-DATA-002", Description: "GET /api/data/orders/{id}/statement returns the full record, financial and account fields included, to any authenticated caller.", Oracle: "protected values of another customer's order appear in the response"},
		{ID: "LAB-DATA-MASK-001", ScenarioID: "API-BAS-DATA-008", Description: "GET /api/data/orders/{id}/card masks the card, but also returns the same value unmasked in card_display.", Oracle: "the unmasked card value appears in the response"},
		{ID: "LAB-ABUSE-SIGNUP-001", ScenarioID: "API-BAS-ABUSE-008", Description: "POST /api/abuse/signup has no limit on account creation.", Oracle: "more than the declared number of accounts are created for one run"},
		{ID: "LAB-ABUSE-SESSION-001", ScenarioID: "API-BAS-ABUSE-009", Description: "GET /api/abuse/quote limits requests per client-supplied session, so a new session resets the limit.", Oracle: "more than the declared number of requests are accepted for one caller"},
		{ID: "LAB-AUTHN-ROTATE-001", ScenarioID: "API-BAS-AUTHN-006", Description: "After POST /api/keys/rotate, the retired API token still changes orders.", Oracle: "the order status changes with a token that was rotated out"},
		{ID: "LAB-ABUSE-VALIDATE-001", ScenarioID: "API-BAS-ABUSE-006", Description: "POST /api/validate/order-lines calls the downstream validator for every request, with no limit per run.", Oracle: "more downstream-triggering requests are accepted for one caller in a run than the declared maximum"},
		{ID: "LAB-ABUSE-OTP-001", ScenarioID: "API-BAS-ABUSE-007", Description: "POST /api/auth/otp/send consumes a paid SMS unit for every request, with no limit per run.", Oracle: "more paid sends are accepted for one caller in a run than the declared maximum"},
		{ID: "LAB-INTEG-REDIRECT-001", ScenarioID: "API-BAS-INTEG-004", Description: "GET /api/integrations/return sends the browser to any target named in next.", Oracle: "the Refresh header names an external host"},
	}
}
