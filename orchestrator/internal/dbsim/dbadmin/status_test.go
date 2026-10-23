package dbadmin

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/audspect/bas/internal/dbsim"
)

// StatusFor is the pure error-to-HTTP mapping behind api.dbsimFail, testable
// without the Docker-backed api test main.
func TestStatusForMapsServiceErrors(t *testing.T) {
	for _, c := range []struct {
		err  error
		want int
	}{
		{ErrForbidden, http.StatusForbidden},
		{dbsim.ErrTargetInvalid, http.StatusBadRequest},
		{dbsim.ErrTargetExists, http.StatusConflict},
		{dbsim.ErrTargetChanged, http.StatusConflict},
		{dbsim.ErrIdentityCheckSuperseded, http.StatusConflict},
		{fmt.Errorf("wrapped: %w", dbsim.ErrTargetChanged), http.StatusConflict},
		{errors.Join(errors.New("x"), dbsim.ErrIdentityCheckSuperseded), http.StatusConflict},
		{dbsim.ErrTargetNotFound, http.StatusNotFound},
		{ErrIdentityCheckUnavailable, http.StatusNotImplemented},
		{errors.New("pq: connection refused"), http.StatusInternalServerError},
		{nil, http.StatusInternalServerError},
	} {
		if got := StatusFor(c.err); got != c.want {
			t.Errorf("%v: got %d want %d", c.err, got, c.want)
		}
	}
}
