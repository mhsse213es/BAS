package lab

import (
	"context"
	"net/http"
	"slices"
)

// responseOwners lets a handler name the owners of the objects its response discloses. The access event attributes the
// request to those owners as well as the owners of the objects it names, so a list that discloses another owner's records
// is judged the way a request that names that owner's record is judged. The holder is created per request by logAccess.
type responseOwners struct {
	owners []string
	// disclosed holds the protected field names the response emitted (see disclosure.go). Names only, never values.
	disclosed []string
}

type responseOwnersKey struct{}

// withResponseOwners returns the request carrying a fresh holder, and the holder for the access log to read.
func withResponseOwners(r *http.Request) (*http.Request, *responseOwners) {
	h := &responseOwners{}
	return r.WithContext(context.WithValue(r.Context(), responseOwnersKey{}, h)), h
}

// noteResponseOwners records owners the response discloses. It does nothing when the request carries no holder.
func noteResponseOwners(r *http.Request, owners ...string) {
	h, ok := r.Context().Value(responseOwnersKey{}).(*responseOwners)
	if !ok {
		return
	}
	for _, o := range owners {
		h.owners = appendOwner(h.owners, o)
	}
}

// noteDisclosedFields records the protected field names a response emitted. It does nothing when the request carries no holder.
func noteDisclosedFields(r *http.Request, fields ...string) {
	h, ok := r.Context().Value(responseOwnersKey{}).(*responseOwners)
	if !ok {
		return
	}
	for _, f := range fields {
		if !slices.Contains(h.disclosed, f) {
			h.disclosed = append(h.disclosed, f)
		}
	}
}
