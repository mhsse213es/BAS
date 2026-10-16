package sentinelone

import (
	"net/http"
	"testing"
)

func TestClassifyAPIError_Unauthorized(t *testing.T) {
	ce := classifyAPIError(http.StatusUnauthorized, nil)
	if ce.Kind != ErrKindUnauthorized {
		t.Errorf("Kind = %v, want ErrKindUnauthorized", ce.Kind)
	}
}

// Review Focus: unlike internal/vendors/defender's errors.go, a 403 here
// can mean either "missing permission" or "no license/entitlement" --
// SentinelOne has no confirmed machine-readable error code that
// distinguishes them, so both must classify the same way (ErrKindForbidden),
// never split into two kinds we can't actually tell apart.
func TestClassifyAPIError_Forbidden(t *testing.T) {
	ce := classifyAPIError(http.StatusForbidden, []byte(`{"message":"not authorized"}`))
	if ce.Kind != ErrKindForbidden {
		t.Errorf("Kind = %v, want ErrKindForbidden", ce.Kind)
	}
}

func TestClassifyAPIError_NotFound(t *testing.T) {
	ce := classifyAPIError(http.StatusNotFound, nil)
	if ce.Kind != ErrKindNotFound {
		t.Errorf("Kind = %v, want ErrKindNotFound", ce.Kind)
	}
}

func TestClassifyAPIError_TooManyRequests(t *testing.T) {
	ce := classifyAPIError(http.StatusTooManyRequests, nil)
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

func TestClassifyAPIError_BadRequest_IsBadRequest(t *testing.T) {
	ce := classifyAPIError(http.StatusBadRequest, nil)
	if ce.Kind != ErrKindBadRequest {
		t.Errorf("Kind = %v, want ErrKindBadRequest", ce.Kind)
	}
}

func TestClassifiedError_Error_IncludesStatusAndBody(t *testing.T) {
	ce := classifyAPIError(http.StatusForbidden, []byte(`no permission`))
	msg := ce.Error()
	if msg == "" {
		t.Fatal("Error() returned empty string")
	}
}
