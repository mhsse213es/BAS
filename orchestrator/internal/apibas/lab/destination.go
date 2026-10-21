package lab

// Destination telemetry. A handler that acts on a destination the request names records it with noteDestination. The
// access event then carries the normalised destination and its policy verdict. The destination comes from the request
// context the handler actually acts on, never from arbitrary body text, and a route with no destination policy records
// nothing, so the rule cannot grade it.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// Destination kinds. Each kind has its own policy in DestinationPolicy.
const (
	DestRedirect = "redirect" // a post-login or return redirect target
	DestCallback = "callback" // a webhook callback host the caller registers
	DestWebhook  = "webhook"  // a URL the webhook test endpoint fetches
	DestUpstream     = "upstream"      // a URL the gateway fetches, whose certificate the gateway should verify
	DestAuthRedirect = "auth_redirect" // an OAuth redirect_uri, which must exactly match the client's registered redirect
)

// RegisteredRedirect is the one redirect_uri the lab registers for its OAuth client. The expectation grades against it.
const RegisteredRedirect = b2RegisteredRedirect

// Policy verdicts recorded on the access event.
const (
	PolicyAllowed   = "allowed"
	PolicyOutside   = "outside_allowlist"
	PolicyInternal  = "internal"
	// PolicyUntrustedCert is an upstream whose certificate chain does not verify, so the content relayed from it is not
	// authenticated (GWAY-012). PolicyVerifiedCert is an upstream whose chain verifies.
	PolicyUntrustedCert = "untrusted_certificate"
	PolicyVerifiedCert  = "verified_certificate"
	policyNotEvaled = "" // the route has no destination policy, so no verdict is recorded
)

// normalizeDestination returns scheme://host:port for an absolute URL, with the scheme and host lower-cased and the
// default port filled in. A relative reference returns "" and no error. An unparseable value returns an error.
func normalizeDestination(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", nil
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		switch scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return scheme + "://" + net.JoinHostPort(host, port), nil
}

// internalDestinationHost reports whether a host is a loopback, private, link-local or unspecified address, or the name
// localhost. Those are the destinations a server-side fetch must not reach (SSRF).
func internalDestinationHost(host string) bool {
	h := strings.ToLower(host)
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified())
}

// DestinationPolicy returns the verdict for a destination of the given kind. It is the single definition the lab
// records and the detection expectations read.
func DestinationPolicy(kind, raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return PolicyOutside
	}
	switch kind {
	case DestRedirect:
		if u.Scheme == "" && u.Host == "" {
			return PolicyAllowed // a relative path stays on this origin
		}
		return PolicyOutside
	case DestCallback:
		if internalDestinationHost(u.Hostname()) {
			return PolicyInternal
		}
		if b3CallbackAllowed(raw) {
			return PolicyAllowed
		}
		return PolicyOutside
	case DestAuthRedirect:
		if raw == b2RegisteredRedirect {
			return PolicyAllowed
		}
		return PolicyOutside
	case DestWebhook:
		if internalDestinationHost(u.Hostname()) {
			return PolicyInternal
		}
		return PolicyAllowed // the webhook test has no allowlist in the lab, so a public host is not a violation
	}
	return policyNotEvaled
}

// destHolder carries a destination from the handler back to the access log, which reads it after the handler returns.
type destHolder struct {
	destination string
	policy      string
}

type destHolderKey struct{}

// withDestinationHolder attaches an empty holder to the request so a handler can record a destination on it.
func withDestinationHolder(r *http.Request) (*http.Request, *destHolder) {
	h := &destHolder{}
	return r.WithContext(context.WithValue(r.Context(), destHolderKey{}, h)), h
}

// noteDestination records a destination the handler acts on. The policy is the kind's verdict. An unparseable destination
// is recorded as outside policy: an unreadable target is not an allowed one.
func noteDestination(r *http.Request, kind, raw string) {
	h, ok := r.Context().Value(destHolderKey{}).(*destHolder)
	if !ok {
		return
	}
	policy := DestinationPolicy(kind, raw)
	if policy == policyNotEvaled {
		return
	}
	norm, err := normalizeDestination(raw)
	if err != nil {
		policy = PolicyOutside
	}
	h.destination = norm
	h.policy = policy
}

// noteUpstream records an upstream fetch: the normalised URL and whether its certificate chain verified. The verdict is
// the one fact the gateway can establish about the content it relays.
func noteUpstream(r *http.Request, raw string, verified bool) {
	h, ok := r.Context().Value(destHolderKey{}).(*destHolder)
	if !ok {
		return
	}
	norm, err := normalizeDestination(raw)
	if err != nil {
		return
	}
	h.destination = norm
	h.policy = PolicyVerifiedCert
	if !verified {
		h.policy = PolicyUntrustedCert
	}
}

// upstreamVerified reports whether the upstream's certificate chain verifies for host against the trusted roots. It is
// the gateway's own check, made whether or not the request was configured to skip verification.
func upstreamVerified(cs *tls.ConnectionState, roots *x509.CertPool, host string) bool {
	if len(cs.PeerCertificates) == 0 {
		return false
	}
	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
		DNSName: host, Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err == nil
}
