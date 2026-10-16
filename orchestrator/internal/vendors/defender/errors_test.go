package defender

import (
	"net/http"
	"strings"
	"testing"
)

func TestClassifyAPIError_Unauthorized(t *testing.T) {
	body := []byte(`{"error":{"code":"Unauthorized","message":"Unauthorized (invalid or expired authorization header).","target":"abc"}}`)
	ce := classifyAPIError(http.StatusUnauthorized, body)
	if ce.Kind != ErrKindUnauthorized {
		t.Errorf("Kind = %v, want ErrKindUnauthorized", ce.Kind)
	}
}

// Review Focus: Forbidden with error.code "DisabledFeature" is the real,
// documented Microsoft signal for a tenant with no active license for
// the feature -- this must resolve to its own distinct kind, never
// collapsed into ErrKindInsufficientPermission, since granting the app
// more permissions can never fix a missing license.
func TestClassifyAPIError_ForbiddenWithDisabledFeature_IsFeatureDisabled_NotPermission(t *testing.T) {
	body := []byte(`{"error":{"code":"DisabledFeature","message":"Tenant feature isn't enabled.","target":"abc"}}`)
	ce := classifyAPIError(http.StatusForbidden, body)
	if ce.Kind != ErrKindFeatureDisabled {
		t.Errorf("Kind = %v, want ErrKindFeatureDisabled", ce.Kind)
	}
	if ce.Code != "DisabledFeature" {
		t.Errorf("Code = %q, want %q", ce.Code, "DisabledFeature")
	}
}

func TestClassifyAPIError_ForbiddenWithoutDisabledFeature_IsInsufficientPermission(t *testing.T) {
	body := []byte(`{"error":{"code":"Forbidden","message":"Forbidden (valid token but insufficient permission for the action).","target":"abc"}}`)
	ce := classifyAPIError(http.StatusForbidden, body)
	if ce.Kind != ErrKindInsufficientPermission {
		t.Errorf("Kind = %v, want ErrKindInsufficientPermission", ce.Kind)
	}
}

func TestClassifyAPIError_NotFound(t *testing.T) {
	body := []byte(`{"error":{"code":"ResourceNotFound","message":"Machine 123 was not found","target":"abc"}}`)
	ce := classifyAPIError(http.StatusNotFound, body)
	if ce.Kind != ErrKindNotFound {
		t.Errorf("Kind = %v, want ErrKindNotFound", ce.Kind)
	}
}

func TestClassifyAPIError_TooManyRequests(t *testing.T) {
	body := []byte(`{"error":{"code":"TooManyRequests","message":"quota exceeded","target":"abc"}}`)
	ce := classifyAPIError(http.StatusTooManyRequests, body)
	if ce.Kind != ErrKindRateLimited {
		t.Errorf("Kind = %v, want ErrKindRateLimited", ce.Kind)
	}
}

func TestClassifyAPIError_InternalServerError_IsTransient(t *testing.T) {
	ce := classifyAPIError(http.StatusInternalServerError, nil)
	if ce.Kind != ErrKindTransient {
		t.Errorf("Kind = %v, want ErrKindTransient", ce.Kind)
	}
}

func TestClassifyAPIError_ServiceUnavailable_IsTransient(t *testing.T) {
	ce := classifyAPIError(http.StatusServiceUnavailable, nil)
	if ce.Kind != ErrKindTransient {
		t.Errorf("Kind = %v, want ErrKindTransient (any 5xx)", ce.Kind)
	}
}

func TestClassifyAPIError_BadRequest_IsBadRequest(t *testing.T) {
	body := []byte(`{"error":{"code":"InvalidInput","message":"Invalid input foo.","target":"abc"}}`)
	ce := classifyAPIError(http.StatusBadRequest, body)
	if ce.Kind != ErrKindBadRequest {
		t.Errorf("Kind = %v, want ErrKindBadRequest", ce.Kind)
	}
}

// Review Focus: a malformed/non-JSON body must never panic or silently
// swallow the HTTP status -- Kind still derives from the status code
// alone, so a caller can always branch correctly even when the body
// didn't match Microsoft's documented shape.
func TestClassifyAPIError_MalformedBody_StillClassifiesByStatus(t *testing.T) {
	ce := classifyAPIError(http.StatusForbidden, []byte(`not json at all`))
	if ce.Kind != ErrKindInsufficientPermission {
		t.Errorf("Kind = %v, want ErrKindInsufficientPermission (DisabledFeature code absent on unparseable body)", ce.Kind)
	}
	if ce.Code != "" {
		t.Errorf("Code = %q, want empty for an unparseable body", ce.Code)
	}
}

func TestClassifyAPIError_EmptyBody_StillClassifiesByStatus(t *testing.T) {
	ce := classifyAPIError(http.StatusUnauthorized, nil)
	if ce.Kind != ErrKindUnauthorized {
		t.Errorf("Kind = %v, want ErrKindUnauthorized", ce.Kind)
	}
}

func TestClassifiedError_Error_IncludesCodeAndMessage(t *testing.T) {
	ce := classifyAPIError(http.StatusForbidden, []byte(`{"error":{"code":"DisabledFeature","message":"Tenant feature isn't enabled.","target":"abc"}}`))
	msg := ce.Error()
	if msg == "" {
		t.Fatal("Error() returned empty string")
	}
	if !strings.Contains(msg, "DisabledFeature") || !strings.Contains(msg, "Tenant feature isn't enabled") {
		t.Errorf("Error() = %q, want it to include the vendor code and message", msg)
	}
}

func TestClassifiedError_Error_MalformedBody_IncludesStatusAndRawBody(t *testing.T) {
	ce := classifyAPIError(http.StatusInternalServerError, []byte(`oops`))
	msg := ce.Error()
	if !strings.Contains(msg, "500") || !strings.Contains(msg, "oops") {
		t.Errorf("Error() = %q, want it to include the status and raw body", msg)
	}
}
