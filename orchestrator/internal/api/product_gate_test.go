package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/license"
)

// A Core licence is refused every Advanced or Enterprise product API, reads as well as writes, and
// is still served the Core and common routes.
func TestProductGate_CoreRefusesHigherProducts(t *testing.T) {
	core, err := license.TierProducts(license.TierCore)
	if err != nil {
		t.Fatal(err)
	}
	reached := 0
	h := ProductGate(func(p license.ProductLine) bool { return core[p] })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached++; w.WriteHeader(http.StatusOK) }))

	refused := []string{
		"/api/dlp/runs", "/api/dlp_sink/x", "/api/phishing-runs",
		"/api/killchain/list", "/api/cloud-runs/9", "/api/webgw/x", "/api/apibas/runs",
		"/api/scenarios/api-bas",
	}
	for _, path := range refused {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer test-token")
		h.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("GET %s: status %d, want 403", path, w.Code)
		}
	}
	if reached != 0 {
		t.Fatalf("refused request reached the handler %d times", reached)
	}

	allowed := []string{"/api/av/x", "/api/waf/x", "/api/emailgw-campaigns", "/api/emailgw-runs/1", "/api/network-paths/1", "/api/scenarios", "/api/agents", "/api/dlpx"}
	for _, path := range allowed {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Header.Set("Authorization", "Bearer test-token")
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("POST %s: status %d, want 200", path, w.Code)
		}
	}
}

// A product prefix is matched on whole path segments. /api/dlpx is not the DLP product.
func TestProductForPath_WholeSegmentOnly(t *testing.T) {
	if _, ok := productForPath("/api/dlpx/y"); ok {
		t.Fatal("/api/dlpx matched the DLP product")
	}
	if p, ok := productForPath("/api/scenarios/api-bas"); !ok || p != license.ProductAPIBAS {
		t.Fatalf("/api/scenarios/api-bas -> %v %v, want APIBAS", p, ok)
	}
	if _, ok := productForPath("/api/scenarios/apt29-kill-chain"); ok {
		t.Fatal("a general scenario path was classified as a product")
	}
}

// An anonymous request is not refused by product here. It reaches authentication, which answers 401,
// so an unauthenticated caller learns nothing about which products exist.
func TestProductGate_AnonymousPassesToAuth(t *testing.T) {
	reached := 0
	h := ProductGate(func(p license.ProductLine) bool { return false })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached++; w.WriteHeader(http.StatusUnauthorized) }))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/dlp/runs", nil))
	if reached != 1 || w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous request: reached=%d status=%d, want the auth layer's 401", reached, w.Code)
	}
}
