package api

import (
	"net/http"
	"strings"

	"github.com/audspect/bas/internal/license"
)

// LicenseGate blocks all requests once the license is StateLocked, except
// the small allowlist needed to serve the lockout UI itself: the health
// check, the public license-status endpoint the frontend polls before
// login, and the static SPA shell (so the browser can load the JS that
// calls license-status and renders the lockout screen). See
// docs/superpowers/specs/2026-08-14-license-grace-period-design.md.
func LicenseGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if license.Current().State != license.StateLocked {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/health" || r.URL.Path == "/api/license/status" {
			next.ServeHTTP(w, r)
			return
		}
		gatedPrefixes := []string{"/api/", "/ws/", "/scim/", "/x/", "/login/"}
		for _, p := range gatedPrefixes {
			if strings.HasPrefix(r.URL.Path, p) {
				jsonError(w, "license_locked", http.StatusPaymentRequired)
				return
			}
		}
		next.ServeHTTP(w, r) // anything else is the static SPA shell
	})
}
