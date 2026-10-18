package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ValidateCandidateHost validates a user-entered server host before it is
// ever used in a network call. A URL with a path, query, or fragment is
// rejected rather than silently stripped to its scheme+host+port -- the
// Settings window must never test or save a different host than what it
// shows the user.
func ValidateCandidateHost(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid host: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid host: missing scheme or host")
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("invalid host: must not include a path, query, or fragment")
	}
	return raw, nil
}

// TestOutcome is the exact, user-facing classification of a connectivity
// test against a candidate (Settings) or configured (Troubleshoot) host.
type TestOutcome string

const (
	TestOutcomeConnected       TestOutcome = "connected"
	TestOutcomeServerRejected  TestOutcome = "server_rejected"
	TestOutcomeCertInvalid     TestOutcome = "cert_invalid"
	TestOutcomeHostUnreachable TestOutcome = "host_unreachable"
	TestOutcomeInvalidHost     TestOutcome = "invalid_host"
)

// ClassifyTestResult classifies a connectivity test from the error (or nil)
// of its TLS dial step and the error (or nil) of the authenticated call
// that followed. A completed TLS handshake is never, by itself, reported
// as Connected -- only tlsErr == nil && authErr == nil is.
func ClassifyTestResult(tlsErr error, authErr error) TestOutcome {
	if tlsErr != nil {
		if isCertError(tlsErr) {
			return TestOutcomeCertInvalid
		}
		return TestOutcomeHostUnreachable
	}
	if authErr != nil {
		return TestOutcomeServerRejected
	}
	return TestOutcomeConnected
}

// isCertError reports whether err represents a TLS certificate-chain
// validation failure rather than a dial/DNS/TCP failure. Prefers typed
// errors.As checks (the real path: tls.Dial returns these directly); falls
// back to matching the error text for callers that have already flattened
// the error to a string before it reaches ClassifyTestResult.
func isCertError(err error) bool {
	var certVerifyErr *tls.CertificateVerificationError
	if errors.As(err, &certVerifyErr) {
		return true
	}
	var unknownAuthErr x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthErr) {
		return true
	}
	var certInvalidErr x509.CertificateInvalidError
	if errors.As(err, &certInvalidErr) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "x509") || strings.Contains(msg, "certificate")
}
