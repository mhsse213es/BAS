package lab

// Phase 3 batch 2: AUTHN-004 (redirect URI), AUTHN-005 (PKCE and code reuse), AUTHN-009 (workload client secret),
// DATA-005 (filter on a protected field), DATA-009 (staging copy with protected values), DATA-010 (signed file URL
// not bound to its key). In-process HTTP routes. Expectations are in the catalog and runner tests.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
)

// b2RegisteredRedirect is the one redirect URI the fixed build accepts for the client (AUTHN-004).
const b2RegisteredRedirect = "https://app.example/callback"

// b2ServiceSecret is the workload client secret the fixed build requires (AUTHN-009).
const b2ServiceSecret = "BAS-SVC-SECRET"

// b2Verifier is the PKCE verifier the client holds; the authorize request carries its S256 challenge.
const b2Verifier = "BAS-VERIFIER-1"

// b2Challenge is the S256 challenge of b2Verifier, base64url without padding.
func b2Challenge() string {
	sum := sha256.Sum256([]byte(b2Verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// fileSign is the signature for one file key (DATA-010). The fixed build requires it for the exact key.
func fileSign(key string) string {
	sum := sha256.Sum256([]byte("BAS-FILE-SIGN|" + key))
	return hex.EncodeToString(sum[:])[:16]
}

func (s *Server) registerBatch2(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/oauth/authorize", s.oauthAuthorize)
	mux.HandleFunc("POST /api/oauth/token", s.oauthToken)
	mux.HandleFunc("POST /api/service/token", s.serviceToken)
	mux.HandleFunc("GET /api/search/orders/filter", s.filterOrders)
	mux.HandleFunc("GET /api/env/staging/orders/{id}", s.stagingOrder)
	mux.HandleFunc("GET /api/files/{key}", s.getFile)
}

func batch2Flaws() []Flaw {
	return []Flaw{
		{ID: "LAB-AUTHN-REDIRECT-001", ScenarioID: "API-BAS-AUTHN-004", Description: "GET /api/oauth/authorize redirects to any redirect_uri, so an authorization code can be sent to an attacker host.", Oracle: "the Location header points at a host outside the registered redirect"},
		{ID: "LAB-AUTHN-PKCE-001", ScenarioID: "API-BAS-AUTHN-005", Description: "POST /api/oauth/token exchanges a code without a PKCE verifier, and accepts a code that was already used.", Oracle: "a code is exchanged more than once, or without its verifier, in one run"},
		{ID: "LAB-AUTHN-SVC-001", ScenarioID: "API-BAS-AUTHN-009", Description: "POST /api/service/token issues a workload token without the client secret.", Oracle: "a workload token is issued without the client secret more than the declared maximum in one run"},
		{ID: "LAB-DATA-FILTER-001", ScenarioID: "API-BAS-DATA-005", Description: "GET /api/search/orders/filter filters on protected fields across all tenants and returns the matching protected values.", Oracle: "a protected value of another tenant appears in the filter response"},
		{ID: "LAB-DATA-STAGING-001", ScenarioID: "API-BAS-DATA-009", Description: "GET /api/env/staging/orders/{id} serves an unmasked staging copy of protected fields to customers.", Oracle: "a protected value appears in the staging response"},
		{ID: "LAB-DATA-SIGNEDURL-001", ScenarioID: "API-BAS-DATA-010", Description: "GET /api/files/{key} accepts a signature for the caller's own file on any key.", Oracle: "another tenant's file content is served with a signature for a different key"},
	}
}

// oauthAuthorize issues an authorization code. The fixed build requires the registered redirect URI and a PKCE
// challenge (AUTHN-004, AUTHN-005).
func (s *Server) oauthAuthorize(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	redirect := q.Get("redirect_uri")
	if !s.vulnerable() && (redirect != b2RegisteredRedirect || q.Get("code_challenge") == "") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid redirect_uri or missing PKCE challenge"})
		return
	}
	code := "authcode-" + caller
	s.gwMu.Lock()
	if s.b2Codes == nil {
		s.b2Codes = map[string]bool{}
	}
	s.b2Codes[r.Header.Get("X-BAS-Run")+"|"+code] = true
	s.gwMu.Unlock()
	loc := redirect + "?code=" + code
	w.Header().Set("Location", loc)
	writeJSON(w, http.StatusOK, map[string]string{"location": loc})
}

// oauthToken exchanges a code for a token. The fixed build requires the PKCE verifier and consumes the code.
func (s *Server) oauthToken(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	var req struct {
		Code     string `json:"code"`
		Verifier string `json:"code_verifier"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "code is required"})
		return
	}
	key := r.Header.Get("X-BAS-Run") + "|" + req.Code
	s.gwMu.Lock()
	defer s.gwMu.Unlock()
	if !s.b2Codes[key] {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown code"})
		return
	}
	if !s.vulnerable() {
		if req.Verifier != b2Verifier {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "PKCE verifier mismatch"})
			return
		}
		delete(s.b2Codes, key)
	}
	writeJSON(w, http.StatusOK, map[string]string{"access_token": "tok-" + caller})
}

// serviceToken issues a workload token. The fixed build requires the client secret (AUTHN-009).
func (s *Server) serviceToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientID string `json:"client_id"`
		Secret   string `json:"client_secret"`
	}
	if err := decodeJSON(r, &req); err != nil || req.ClientID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "client_id is required"})
		return
	}
	if !s.vulnerable() && req.Secret != b2ServiceSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid client credentials"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"access_token": "svc-" + req.ClientID})
}

// filterOrders filters orders on a field. The fixed build filters public fields over the caller's own orders
// only (DATA-005).
func (s *Server) filterOrders(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	field, value := r.URL.Query().Get("field"), r.URL.Query().Get("value")
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.vulnerable() && field != "sku" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "filter only on public fields"})
		return
	}
	var out []map[string]any
	for _, o := range sortedOrders(s.orders) {
		if !s.vulnerable() && o.OwnerID != caller {
			continue
		}
		src := o.Public
		if s.vulnerable() {
			src = mergeFields(o.Public, o.Protected)
		}
		if src[field] == value {
			out = append(out, map[string]any{"id": o.ID, "owner_id": o.OwnerID, "fields": src})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": out})
}

// stagingOrder serves an order from the staging environment. The fixed build does not expose staging to customers
// (DATA-009).
func (s *Server) stagingOrder(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireCaller(w, r); !ok {
		return
	}
	if !s.vulnerable() {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	o, found := s.orders[r.PathValue("id")]
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": o.ID, "env": "staging", "protected": o.Protected})
}

// getFile serves a file by key with a signature. The vulnerable build accepts a signature for any file the caller
// owns, whatever key it is presented with. The fixed build requires the signature for this key and the owner of
// its order (DATA-010).
func (s *Server) getFile(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	key := r.PathValue("key")
	sig := r.URL.Query().Get("sig")
	orderID := strings.TrimSuffix(key, "-statement")
	s.mu.Lock()
	defer s.mu.Unlock()
	o, found := s.orders[orderID]
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if s.vulnerable() {
		owned := false
		for _, other := range s.orders {
			if other.OwnerID == caller && sig == fileSign(other.ID+"-statement") {
				owned = true
			}
		}
		if !owned {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "bad signature"})
			return
		}
	} else if sig != fileSign(key) || o.OwnerID != caller {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "bad signature"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"key": key, "order": o.ID, "protected": o.Protected})
}

// mergeFields returns the union of two field maps, for the vulnerable filter response.
func mergeFields(a, b map[string]string) map[string]string {
	out := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}
