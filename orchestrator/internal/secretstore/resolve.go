package secretstore

import (
	"context"
	"errors"
)

// ErrUnavailable means a credential column holds a reference but no store is available to resolve it (for example the
// encryption key is missing). Callers must fail the operation. They must not fall back to the plaintext column.
var ErrUnavailable = errors.New("secretstore: credential reference cannot be resolved: store unavailable")

// Resolve returns the credential for one column during the dual-read phase.
//
// Policy:
//   - ref empty: the row has not been migrated, so the plaintext column is returned unchanged.
//   - ref set: the value comes from the store. A missing store, a missing value or a failed decryption is an error. The
//     plaintext column is never used as a fallback once a reference exists, because a stale plaintext could then be used
//     silently after rotation.
//
// Error text never carries the reference's value.
func Resolve(ctx context.Context, store Store, ref, plaintext string) (string, error) {
	if ref == "" {
		return plaintext, nil
	}
	if !ValidRef(ref) {
		return "", ErrBadRef
	}
	if store == nil {
		return "", ErrUnavailable
	}
	v, err := store.Get(ctx, ref)
	if err != nil {
		return "", err
	}
	return v, nil
}
