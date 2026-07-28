package api

import (
	"net/http"

	"golang.org/x/time/rate"
)

// RateLimitMiddleware enforces a single global token-bucket limit across
// every request it wraps -- a runaway-client protection for the current
// single-tenant-per-database on-prem product, not a per-tenant commercial
// quota system (that belongs to the future Audspect Cloud offering). One
// shared *rate.Limiter across all callers, matching perMin requests/minute
// with a burst allowance of burst. Callers over the limit get 429.
func RateLimitMiddleware(perMin, burst int) func(http.Handler) http.Handler {
	limiter := rate.NewLimiter(rate.Limit(float64(perMin)/60.0), burst)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.Allow() {
				jsonError(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
