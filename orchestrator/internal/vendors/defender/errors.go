package defender

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ErrorKind classifies a Defender for Endpoint API error response by the
// real, documented error-code taxonomy
// (learn.microsoft.com/defender-endpoint/api/common-errors), so a caller
// can tell "there is no license for this feature" apart from "the app
// lacks a permission" apart from "the resource genuinely doesn't exist"
// apart from "retry later" -- distinctions a bare HTTP status code
// collapses. Every Defender for Endpoint API error response shares the
// same documented body shape:
// {"error":{"code":"...","message":"...","target":"..."}}.
type ErrorKind int

const (
	ErrKindUnknown ErrorKind = iota
	// ErrKindUnauthorized: HTTP 401, Microsoft error code "Unauthorized"
	// -- the token is missing, invalid, or expired. Re-authenticating
	// (not granting a new permission) is the fix.
	ErrKindUnauthorized
	// ErrKindInsufficientPermission: HTTP 403, Microsoft error code
	// "Forbidden" -- the token is valid but the app registration was
	// never granted (or never had admin-consented) the specific
	// application permission the call requires.
	ErrKindInsufficientPermission
	// ErrKindFeatureDisabled: HTTP 403, Microsoft error code
	// "DisabledFeature" ("Tenant feature isn't enabled"). This is the
	// real, documented signal for a tenant with no active Defender for
	// Endpoint license/entitlement, as distinct from a permission
	// problem: granting the app registration more permissions can
	// never fix this.
	ErrKindFeatureDisabled
	// ErrKindNotFound: HTTP 404, Microsoft error codes "NotFound" or
	// "ResourceNotFound" -- the specific resource (a machine, an alert)
	// genuinely does not exist. A statement about one resource, not
	// about the tenant's licensing or the app's permissions.
	ErrKindNotFound
	// ErrKindRateLimited: HTTP 429, Microsoft error code
	// "TooManyRequests" -- the request was rejected before doing any
	// work; safe to retry after the Retry-After duration.
	ErrKindRateLimited
	// ErrKindTransient: HTTP 500+ (Microsoft documents
	// "InternalServerError" specifically; any 5xx is treated the same
	// way) -- a server-side failure, safe to retry.
	ErrKindTransient
	// ErrKindBadRequest: any other 400-level response (BadRequest,
	// ODataError, InvalidInput, InvalidRequestBody,
	// MissingRequiredParameter, etc.) -- the request itself was
	// malformed; retrying it unchanged will not help.
	ErrKindBadRequest
)

// apiErrorBody is the real, documented Defender for Endpoint API error
// envelope.
type apiErrorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Target  string `json:"target"`
	} `json:"error"`
}

// ClassifiedError is a Defender for Endpoint API error response
// classified by ErrorKind, preserving the vendor's own error code,
// message, and target alongside the HTTP status and raw body for
// diagnostics. Callers that need to distinguish a licensing problem
// from a permission problem from a transient failure should use
// errors.As against this type, never string-match the error text.
type ClassifiedError struct {
	Kind       ErrorKind
	StatusCode int
	// Code is the vendor's own error.code (e.g. "DisabledFeature") --
	// empty when the response body didn't parse as the documented
	// shape, in which case Kind still derives correctly from
	// StatusCode alone.
	Code    string
	Message string
	Target  string
	Body    []byte
}

func (e *ClassifiedError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("defender API error: HTTP %d %s: %s", e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("defender API error: HTTP %d: %s", e.StatusCode, string(e.Body))
}

// classifyAPIError builds a ClassifiedError from one Defender for
// Endpoint API HTTP response. It never panics or errors on a malformed
// or empty body -- Code/Message/Target stay empty and Kind is still
// assigned from statusCode alone, so a caller can always branch on Kind
// even when the body didn't match Microsoft's documented shape.
func classifyAPIError(statusCode int, body []byte) *ClassifiedError {
	ce := &ClassifiedError{StatusCode: statusCode, Body: body}
	var parsed apiErrorBody
	if len(body) > 0 && json.Unmarshal(body, &parsed) == nil {
		ce.Code = parsed.Error.Code
		ce.Message = parsed.Error.Message
		ce.Target = parsed.Error.Target
	}
	switch {
	case statusCode == http.StatusUnauthorized:
		ce.Kind = ErrKindUnauthorized
	case statusCode == http.StatusForbidden && ce.Code == "DisabledFeature":
		ce.Kind = ErrKindFeatureDisabled
	case statusCode == http.StatusForbidden:
		ce.Kind = ErrKindInsufficientPermission
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
