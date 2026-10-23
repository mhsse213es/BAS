package campaign

import (
	"bytes"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// Identifier aliasing.
//
// Tests are generated once, against the generation fixture, so their steps
// name that fixture's object ids. Every verification round runs on a FRESH
// fixture whose server-assigned ids differ. The executor therefore lives in the
// generation namespace (its fixture, created objects and scenarios all use the
// generation ids) and this transport translates at the wire: generation id ->
// fresh id in requests, fresh id -> generation id in responses.
//
// Only whole identifiers are translated: a path segment, a query value, or a
// complete JSON string. Ids embedded inside longer strings are left alone, and
// numeric JSON ids are not translated (ids created by setup operations are
// strings). When the two namespaces are identical no aliasing is installed.

const maxAliasBody = 8 << 20

type aliasRT struct {
	next    http.RoundTripper
	toFresh map[string]string
	toOld   map[string]string
}

// newAlias returns nil when no translation is needed. gen and fresh are the
// created-object ids of the generation fixture and of the new fixture, in the
// same order.
func newAlias(next http.RoundTripper, gen, fresh []string) http.RoundTripper {
	if len(gen) != len(fresh) {
		return next
	}
	toFresh, toOld := map[string]string{}, map[string]string{}
	differs := false
	for i := range gen {
		g, f := gen[i], fresh[i]
		if g == "" || f == "" || g == f || strings.ContainsAny(g+f, "\"\\/?&=#") {
			continue
		}
		toFresh[g], toOld[f] = f, g
		differs = true
	}
	if !differs {
		return next
	}
	return aliasRT{next: next, toFresh: toFresh, toOld: toOld}
}

var jsonString = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)

func rewriteJSON(b []byte, m map[string]string) []byte {
	return jsonString.ReplaceAllFunc(b, func(tok []byte) []byte {
		if v, ok := m[string(tok[1:len(tok)-1])]; ok {
			return []byte(`"` + v + `"`)
		}
		return tok
	})
}

func (a aliasRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r2 := r.Clone(r.Context())
	u := *r.URL
	segs := strings.Split(u.Path, "/")
	for i, s := range segs {
		if v, ok := a.toFresh[s]; ok {
			segs[i] = v
		}
	}
	u.Path, u.RawPath = strings.Join(segs, "/"), ""
	q := u.Query()
	changed := false
	for k, vs := range q {
		for i, v := range vs {
			if nv, ok := a.toFresh[v]; ok {
				vs[i], changed = nv, true
			}
		}
		q[k] = vs
	}
	if changed {
		u.RawQuery = q.Encode()
	}
	r2.URL = &u
	if r.Body != nil && r.Body != http.NoBody {
		raw, err := io.ReadAll(io.LimitReader(r.Body, maxAliasBody))
		_ = r.Body.Close()
		if err != nil {
			return nil, err
		}
		raw = rewriteJSON(raw, a.toFresh)
		r2.Body = io.NopCloser(bytes.NewReader(raw))
		r2.ContentLength = int64(len(raw))
		r2.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil }
	}
	resp, err := a.next.RoundTrip(r2)
	if err != nil || resp == nil || resp.Body == nil {
		return resp, err
	}
	raw, rerr := io.ReadAll(io.LimitReader(resp.Body, maxAliasBody))
	_ = resp.Body.Close()
	if rerr != nil {
		return nil, rerr
	}
	raw = rewriteJSON(raw, a.toOld)
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	resp.ContentLength = int64(len(raw))
	resp.Header.Del("Content-Length")
	return resp, nil
}
