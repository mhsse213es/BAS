package lab

import (
	"context"
	"net/http"
)

// responseOwners lets a handler name the owners of the objects its response discloses. The access event attributes the
// request to those owners as well as the owners of the objects it names, so a list that discloses another owner's records
// is judged the way a request that names that owner's record is judged. The holder is created per request by logAccess.
type responseOwners struct {
	owners []string
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
