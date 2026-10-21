package lab

// Selective, redacted extraction of object identifiers from request bodies.
//
// Privacy control: request bodies are not inspected by default. Config.ExtractBodyIDs must be set
// explicitly, for example by a test or by the operator who accepts the trade-off, before any body is
// read. When it is set, the lab reads each body up to bodyExtractLimit bytes, checks it for the
// identifiers of known orders, and keeps only the owner of an identifier it found. The body is
// discarded after the check. It is never stored, logged, or put on an access event.

import (
	"bytes"
	"context"
	"io"
	"net/http"
)

const bodyExtractLimit = 64 << 10

type bodyOwnersKey struct{}

type bodySignatureKey struct{}

// bodySignatureFromContext returns the injection classes found in the request body, when extraction is on.
func bodySignatureFromContext(ctx context.Context) []string {
	v, _ := ctx.Value(bodySignatureKey{}).([]string)
	return v
}

// bodyOwnersFromContext returns the owners of every order named in the request body, in order-ID order,
// when extraction is on. Nil means extraction is off or the body named no known order.
func bodyOwnersFromContext(ctx context.Context) []string {
	v, _ := ctx.Value(bodyOwnersKey{}).([]string)
	return v
}

// bodyRest is a request body made of bytes already read followed by the original stream.
type bodyRest struct {
	io.Reader
	io.Closer
}

// extractBodyOwner is the body-extraction middleware. It must wrap the access logger, so the logger
// sees the owner that the body names.
func (s *Server) extractBodyOwner(next http.Handler) http.Handler {
	if !s.cfg.ExtractBodyIDs {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body == nil || r.Body == http.NoBody {
			next.ServeHTTP(w, r)
			return
		}
		// Only the first bodyExtractLimit bytes are inspected. The handler still receives the whole body: the prefix
		// read here, followed by the unread remainder. A truncated body would change what the handler accepts.
		orig := r.Body
		raw, _ := io.ReadAll(io.LimitReader(orig, bodyExtractLimit))
		r.Body = bodyRest{Reader: io.MultiReader(bytes.NewReader(raw), orig), Closer: orig}
		owners := s.ownersInBody(raw)
		ctx := r.Context()
		if len(owners) > 0 {
			ctx = context.WithValue(ctx, bodyOwnersKey{}, owners)
		}
		if classes := injectionClasses(string(raw)); len(classes) > 0 {
			ctx = context.WithValue(ctx, bodySignatureKey{}, classes)
		}
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

// ownersInBody returns the owner of every known order whose ID appears in the body, in order-ID order,
// without repeats. Only owners are returned; the matched text is not kept.
func (s *Server) ownersInBody(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, o := range sortedOrders(s.orders) {
		if bytes.Contains(raw, []byte(o.ID)) {
			out = appendOwner(out, o.OwnerID)
		}
	}
	return out
}
