package api

import (
	"net"
	"net/http"
	"strings"
)

// trustedRealIP replaces chi/middleware.RealIP, which is deprecated and
// vulnerable to IP spoofing (GHSA-3fxj-6jh8-hvhx, GHSA-rjr7-jggh-pgcp,
// GHSA-9g5q-2w5x-hmxf): it rewrites r.RemoteAddr from X-Forwarded-For/
// X-Real-IP/True-Client-IP unconditionally, whether or not the request
// actually passed through a trusted proxy that set those headers itself.
//
// The orchestrator's default deployment (packaging/compose/docker-compose.yml)
// exposes its port directly to the network -- no bundled reverse proxy --
// so a client connecting straight to it can set any of these headers itself.
// Every downstream consumer of r.RemoteAddr (audit.go's actor-IP attribution
// is the one that matters most: forging it lets an attacker plant a false
// source IP in the platform's own audit trail) trusted that value implicitly.
//
// Fix: only honor a forwarded-for header when the DIRECT TCP peer
// (r.RemoteAddr, before any rewrite) is loopback or a private-range address
// -- i.e., an operator-added reverse proxy (nginx/Caddy, both documented as
// optional in the installation guide) running on the same host or the same
// private docker network actually sits in front of this request. A peer
// outside that range is either the real external client (direct-exposure
// deployment, the common case) or an untrusted intermediary either way --
// its claimed X-Forwarded-For is never honored.
func trustedRealIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if peerIsTrustedProxy(r.RemoteAddr) {
			if ip := firstForwardedIP(r); ip != "" {
				r.RemoteAddr = ip
			}
		}
		next.ServeHTTP(w, r)
	})
}

// peerIsTrustedProxy reports whether hostport's host is loopback or a
// private-range address (RFC 1918 IPv4, RFC 4193 IPv6 ULA, via net.IP's own
// IsLoopback/IsPrivate). A malformed or unparseable hostport is never
// trusted -- degrade safely to "treat as a direct, untrusted client"
// rather than risk misclassifying it as trusted.
func peerIsTrustedProxy(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate()
}

// firstForwardedIP returns the first (originating-client) address from
// X-Forwarded-For, or X-Real-IP if X-Forwarded-For is absent/empty, or ""
// if neither carries a usable value. X-Forwarded-For is a comma-separated
// hop chain appended-to by each proxy in the path; the first entry is the
// original client, per the header's own convention (the same convention
// chi's own deprecated RealIP used, kept here for compatibility with
// whatever an operator's nginx/Caddy config already sends).
func firstForwardedIP(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); v != "" {
		first := strings.TrimSpace(strings.SplitN(v, ",", 2)[0])
		if first != "" {
			return first
		}
	}
	return strings.TrimSpace(r.Header.Get("X-Real-IP"))
}
