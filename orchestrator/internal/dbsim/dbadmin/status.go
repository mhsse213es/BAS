package dbadmin

import (
	"errors"
	"net/http"

	"github.com/audspect/bas/internal/dbsim"
)

// StatusFor maps a service or store error to its HTTP status. It is pure so it is
// testable without the API test main. Unknown errors are 500 (the handler must not
// echo their text).
func StatusFor(err error) int {
	switch {
	case err == nil:
		return http.StatusInternalServerError
	case errors.Is(err, ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, dbsim.ErrTargetInvalid):
		return http.StatusBadRequest
	case errors.Is(err, dbsim.ErrTargetExists), errors.Is(err, dbsim.ErrTargetChanged), errors.Is(err, dbsim.ErrIdentityCheckSuperseded):
		return http.StatusConflict
	case errors.Is(err, dbsim.ErrTargetNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrIdentityCheckUnavailable):
		return http.StatusNotImplemented
	}
	return http.StatusInternalServerError
}
