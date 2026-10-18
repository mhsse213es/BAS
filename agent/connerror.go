package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"time"
)

// ConnErrorCategory classifies a real connection-attempt failure.
// Deliberately decoupled from TestOutcome (hostcheck.go): a Troubleshoot
// check must reflect its own live result, never a cached classification
// from a different window's Settings Test call.
type ConnErrorCategory string

const (
	ConnErrorNone           ConnErrorCategory = "none"
	ConnErrorDNS            ConnErrorCategory = "dns"
	ConnErrorTCP            ConnErrorCategory = "tcp"
	ConnErrorTLS            ConnErrorCategory = "tls"
	ConnErrorProxyAuth      ConnErrorCategory = "proxy_auth"
	ConnErrorServerRejected ConnErrorCategory = "server_rejected"
	ConnErrorUnknown        ConnErrorCategory = "unknown"
)

// LastConnError records the most recent meaningful connection failure, so
// diagnostics can read a structured field instead of grepping the log file
// (docs/guides/troubleshooting.md Section 2's current manual approach).
type LastConnError struct {
	Category ConnErrorCategory
	Detail   string
	At       time.Time
}

// proxyAuthStrings are the exact log strings
// docs/guides/troubleshooting.md Section 2.5 documents for proxy
// authentication failures. Checked before the generic DNS/TCP/TLS
// errors.As fallbacks, since a proxy rejection often also wraps a
// *net.OpError and the more specific classification must win.
var proxyAuthStrings = []string{
	"SSPI unavailable",
	"no Basic credentials configured",
	"no supported mechanism",
	"proxy rejected the configured credentials",
}

// ClassifyConnError classifies a real connection-attempt error. Only label
// a failure as a proxy issue when the error text actually matches one of
// the runbook's known strings -- never as a default guess.
func ClassifyConnError(err error) LastConnError {
	if err == nil {
		return LastConnError{Category: ConnErrorNone, At: time.Now()}
	}

	msg := err.Error()
	for _, s := range proxyAuthStrings {
		if strings.Contains(msg, s) {
			return LastConnError{Category: ConnErrorProxyAuth, Detail: msg, At: time.Now()}
		}
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return LastConnError{Category: ConnErrorDNS, Detail: msg, At: time.Now()}
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return LastConnError{Category: ConnErrorTCP, Detail: msg, At: time.Now()}
	}
	var certVerifyErr *tls.CertificateVerificationError
	if errors.As(err, &certVerifyErr) {
		return LastConnError{Category: ConnErrorTLS, Detail: msg, At: time.Now()}
	}
	var unknownAuthErr x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthErr) {
		return LastConnError{Category: ConnErrorTLS, Detail: msg, At: time.Now()}
	}

	return LastConnError{Category: ConnErrorUnknown, Detail: msg, At: time.Now()}
}
