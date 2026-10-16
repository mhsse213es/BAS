package sentinelone

import (
	"fmt"
	"net/http"
)

// ErrorKind classifies a SentinelOne API error response by HTTP status
// alone. Unlike internal/vendors/defender's errors.go, which classifies
// against Microsoft's documented {"error":{"code":"..."}} envelope,
// SentinelOne publishes no public, authoritative API reference at all
// -- its only real schema reference lives inside each customer's own
// management console (Help -> API Hub / Swagger), which this codebase
// has no access to. Every third-party source checked (2026-10-16:
// Stitchflow, Praetorian, LimaCharlie, D3 Security, ThreatQ) describes
// only generic "invalid token"/"insufficient permission" prose, with no
// documented machine-readable error-code field.
//
// The practical consequence: a missing-license/entitlement condition
// CANNOT be distinguished from an insufficient-permission condition the
// way Defender's real "DisabledFeature" error code allows (see
// defender.ErrKindFeatureDisabled vs defender.ErrKindInsufficientPermission).
// Both surface here as the single ErrKindForbidden. Any caller that
// needs that distinction for SentinelOne must get it from a different
// signal (e.g. a known SKU/entitlement check done elsewhere), not from
// this classifier.
type ErrorKind int

const (
	ErrKindUnknown      ErrorKind = iota
	ErrKindUnauthorized           // 401
	ErrKindForbidden              // 403 -- permission AND/OR licensing, not distinguishable
	ErrKindNotFound               // 404
	ErrKindRateLimited            // 429
	ErrKindTransient              // 5xx
	ErrKindBadRequest             // other 4xx
)

// ClassifiedError is a SentinelOne API error classified by ErrorKind,
// preserving the HTTP status and raw body for diagnostics.
type ClassifiedError struct {
	Kind       ErrorKind
	StatusCode int
	Body       []byte
}

func (e *ClassifiedError) Error() string {
	return fmt.Sprintf("sentinelone API error: HTTP %d: %s", e.StatusCode, string(e.Body))
}

func classifyAPIError(statusCode int, body []byte) *ClassifiedError {
	ce := &ClassifiedError{StatusCode: statusCode, Body: body}
	switch {
	case statusCode == http.StatusUnauthorized:
		ce.Kind = ErrKindUnauthorized
	case statusCode == http.StatusForbidden:
		ce.Kind = ErrKindForbidden
	case statusCode == http.StatusNotFound:
		ce.Kind = ErrKindNotFound
	case statusCode == http.StatusTooManyRequests:
		ce.Kind = ErrKindRateLimited
	case statusCode >= 500:
		ce.Kind = ErrKindTransient
	case statusCode >= 400:
		ce.Kind = ErrKindBadRequest
	default:
		ce.Kind = ErrKindUnknown
	}
	return ce
}
