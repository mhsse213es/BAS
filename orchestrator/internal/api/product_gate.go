package api

import (
	"net/http"
	"strings"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/license"
)

// productPrefixes maps the product-specific API paths to the product line that licenses them. A
// request whose path falls under one of these is refused unless the licence permits that product.
// Matching is on whole path segments, and the longest prefix wins. Paths not listed here are
// platform routes (auth, users, agents, scenarios and so on): the scenario engine gates the scenarios
// those routes can run, so they are not refused by product here.
//
// Prefixes whose product is not yet decided are deliberately absent, and they stay open at this
// layer. They are listed in docs/licence-tier-open-items.md for a decision.
var productPrefixes = map[string]license.ProductLine{
	"/api/scenarios/api-bas":                license.ProductAPIBAS,
	"/api/apibas":                           license.ProductAPIBAS,
	"/api/aleef":                            license.ProductAleef,
	"/api/waf":                              license.ProductWAF,
	"/api/av":                               license.ProductAV,
	"/api/dlp":                              license.ProductDLP,
	"/api/dlp_sink":                         license.ProductDLP,
	"/api/phishing":                         license.ProductPhishing,
	"/api/phishing-runs":                    license.ProductPhishing,
	"/api/emailgw":                          license.ProductEmail,
	"/api/emailgw-campaigns":                license.ProductEmail,
	"/api/emailgw-runs":                     license.ProductEmail,
	"/api/webgw":                            license.ProductWebGW,
	"/api/killchain":                        license.ProductKillChain,
	"/api/cloud-campaigns":                  license.ProductCloud,
	"/api/cloud-paths":                      license.ProductCloud,
	"/api/cloud-preflight":                  license.ProductCloud,
	"/api/cloud-probes":                     license.ProductCloud,
	"/api/cloud-runs":                       license.ProductCloud,
	"/api/cloud-scenario-runs":              license.ProductCloud,
	"/api/cloud-scenarios":                  license.ProductCloud,
	"/api/cloud-topology-imports":           license.ProductCloud,
	"/api/network-control-expectations":     license.ProductNetwork,
	"/api/network-control-verifications":    license.ProductNetwork,
	"/api/network-discovery-runs":           license.ProductNetwork,
	"/api/network-paths":                    license.ProductNetwork,
	"/api/network-policy-evaluations":       license.ProductNetwork,
	"/api/network-policy-imports":           license.ProductNetwork,
	"/api/network-reachability-comparisons": license.ProductNetwork,
	"/api/network-topology-imports":         license.ProductNetwork,
}

// Aleef is a separate add-on (license.ProductAleef), not a tier product: PermitsNow grants it only
// when a verified licence carries the signed "addon:aleef" token. A dev build with no licence (zero
// licence state) therefore REFUSES /api/aleef with 403, unlike the tier products, which a dev build
// permits; this is deliberate (fail closed for the product that sends traffic to targets).
//
// The prefixes are matched on the raw request path. If a path-cleaning middleware (for example chi's
// CleanPath) is ever added AFTER this gate, the router would see a different path than the gate and the
// two could diverge; add any such middleware before ProductGate in Mount, or re-check the cleaned path.

// productForPath returns the product line that licenses path, if the path is product-specific.
func productForPath(path string) (license.ProductLine, bool) {
	best := ""
	var line license.ProductLine
	for prefix, p := range productPrefixes {
		if path != prefix && !strings.HasPrefix(path, prefix+"/") {
			continue
		}
		if len(prefix) > len(best) {
			best, line = prefix, p
		}
	}
	return line, best != ""
}

// ProductGate refuses a request to a product API that the licence does not include. It applies to
// reads and writes alike: a licence that does not include a product does not get to see its data.
// The check is per request against the verified licence state, so a re-issued or downgraded licence
// takes effect on the next request.
func ProductGate(permits func(license.ProductLine) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Anonymous requests go to authentication, which answers 401, so only a credentialed request is
			// judged against the licence.
			if p, ok := productForPath(r.URL.Path); ok && auth.TokenFromRequest(r) != "" && !permits(p) {
				jsonError(w, "product_not_licensed", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
