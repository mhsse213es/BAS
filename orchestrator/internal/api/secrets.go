package api

import (
	"context"

	"github.com/audspect/bas/internal/secretstore"
)

// WithSecretStore attaches the credential store used to resolve reference columns (see secretstore.Resolve). A nil store
// is allowed: references then fail their own operation, and plaintext columns keep working.
func (h *Handler) WithSecretStore(s secretstore.Store) *Handler {
	h.secrets = s
	return h
}

// resolveCredential returns the credential for one column. Callers pass the reference column and the plaintext column read
// from the same row. A reference that cannot be resolved is an error: callers must not fall back to plaintext.
func (h *Handler) resolveCredential(ctx context.Context, ref, plaintext string) (string, error) {
	return secretstore.Resolve(ctx, h.secrets, ref, plaintext)
}
