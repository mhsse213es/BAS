package campaign

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/audspect/bas/internal/aleef/model"
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
// Translation is deliberately narrow: a whole path segment, a whole query
// value, a whole JSON string, or a whole header value (never Authorization or
// Cookie). Anything else that still contains a generation id (an id embedded in
// a longer string, a numeric JSON id, a header with extra text) cannot be
// translated safely; the request is NOT sent and ErrUntranslatedID is returned,
// so the step errors and the test ends unconfirmed instead of reading a 404 or
// 403 from a dead id as "protected". The scan looks at the original request
// with the translated tokens masked, so a fresh id that happens to contain a
// generation id as a substring is not mistaken for an untranslated one.
//
// Requests ask for identity encoding, and a response with any other
// Content-Encoding is an error (a compressed body could not be translated).
// Bodies larger than maxAliasBody are errors in both directions; they are never
// truncated.
//
// Guard interaction: exec guards the client whose Transport is this one, so the
// guard classifies the PRE-translation path. That is only safe when the id
// substituted into a path segment cannot change which route matches.
// newAlias therefore refuses to alias when any generation or fresh id equals a
// literal (non-parameter) segment of a model path, compared case-insensitively,
// or is not a plain single path segment; Fresh fails with that error and the
// test ends unconfirmed.

var (
	// ErrUntranslatedID: a generation id remains in an outgoing request.
	ErrUntranslatedID = errors.New("campaign: request still carries a generation id that cannot be translated; not sent")
	// ErrAliasBodyTooLarge: a body exceeded maxAliasBody.
	ErrAliasBodyTooLarge = errors.New("campaign: body too large to translate ids; not forwarded")
	// ErrEncodedResponse: the response is content-encoded, so ids cannot be translated.
	ErrEncodedResponse = errors.New("campaign: response is content-encoded; ids cannot be translated")
)

// maxAliasBody caps request and response bodies. A var only so tests can use a
// tiny cap.
var maxAliasBody = 8 << 20

const mask = "\x00"

type aliasRT struct {
	next    http.RoundTripper
	toFresh map[string]string
	toOld   map[string]string
}

var plainID = regexp.MustCompile(`^[A-Za-z0-9._~:@!$'()*+,-]+$`)

// newAlias returns next unchanged when the namespaces are identical. gen and
// fresh are the created-object ids of the generation fixture and of the new
// fixture, in the same order. It fails when aliasing would be unsafe (see the
// guard note above).
func newAlias(next http.RoundTripper, gen, fresh []string, m model.Model) (http.RoundTripper, error) {
	if len(gen) != len(fresh) {
		return next, nil
	}
	literals := map[string]bool{}
	for _, op := range m.Operations {
		for _, s := range strings.Split(strings.Trim(op.Path, "/"), "/") {
			if s != "" && !strings.HasPrefix(s, "{") {
				literals[strings.ToLower(s)] = true
			}
		}
	}
	toFresh, toOld := map[string]string{}, map[string]string{}
	for i := range gen {
		g, f := gen[i], fresh[i]
		if g == f {
			continue
		}
		for _, id := range []string{g, f} {
			if id == "." || id == ".." || !plainID.MatchString(id) {
				return nil, errors.New("campaign: an object id is not a plain path segment; ids cannot be aliased safely")
			}
			if literals[strings.ToLower(id)] {
				return nil, errors.New("campaign: an object id equals a literal route segment; ids cannot be aliased safely")
			}
		}
		toFresh[g], toOld[f] = f, g
	}
	if len(toFresh) == 0 {
		return next, nil
	}
	return aliasRT{next: next, toFresh: toFresh, toOld: toOld}, nil
}

var jsonString = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)

// rewriteJSON replaces every JSON string token whose content is a key of m.
func rewriteJSON(b []byte, m map[string]string) []byte {
	return jsonString.ReplaceAllFunc(b, func(tok []byte) []byte {
		if v, ok := m[string(tok[1:len(tok)-1])]; ok {
			return []byte(`"` + v + `"`)
		}
		return tok
	})
}

func maskOf(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k := range m {
		out[k] = mask
	}
	return out
}

func (a aliasRT) leftover(s string) bool {
	for k := range a.toFresh {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

func readCapped(rc io.ReadCloser) ([]byte, error) {
	defer rc.Close()
	raw, err := io.ReadAll(io.LimitReader(rc, int64(maxAliasBody)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxAliasBody {
		return nil, ErrAliasBodyTooLarge
	}
	return raw, nil
}

func skipHeader(k string) bool {
	return strings.EqualFold(k, "Authorization") || strings.EqualFold(k, "Cookie")
}

func (a aliasRT) RoundTrip(r *http.Request) (*http.Response, error) {
	masked := maskOf(a.toFresh)
	r2 := r.Clone(r.Context())
	u := *r.URL

	// ---- path
	segs := strings.Split(u.Path, "/")
	msegs := append([]string(nil), segs...)
	for i, s := range segs {
		if v, ok := a.toFresh[s]; ok {
			segs[i], msegs[i] = v, mask
		}
	}
	u.Path, u.RawPath = strings.Join(segs, "/"), ""
	scan := []string{strings.Join(msegs, "/")}

	// ---- query
	q := u.Query()
	mq := url.Values{}
	changed := false
	for k, vs := range q {
		nv := make([]string, len(vs))
		mv := make([]string, len(vs))
		for i, v := range vs {
			nv[i], mv[i] = v, v
			if f, ok := a.toFresh[v]; ok {
				nv[i], mv[i], changed = f, mask, true
			}
		}
		q[k], mq[k] = nv, mv
		scan = append(scan, k)
		scan = append(scan, mv...)
	}
	if changed {
		u.RawQuery = q.Encode()
	} else {
		scan = append(scan, r.URL.RawQuery)
	}
	r2.URL = &u

	// ---- headers (whole-value matches only; credentials are never touched)
	r2.Header = r.Header.Clone()
	if r2.Header == nil {
		r2.Header = http.Header{}
	}
	for k, vs := range r2.Header {
		if skipHeader(k) {
			continue
		}
		for i, v := range vs {
			if f, ok := a.toFresh[v]; ok {
				vs[i] = f
				continue
			}
			scan = append(scan, v)
		}
		r2.Header[k] = vs
	}
	r2.Header.Del("Accept-Encoding")
	r2.Header.Set("Accept-Encoding", "identity")

	// ---- body
	if r.Body != nil && r.Body != http.NoBody {
		raw, err := readCapped(r.Body)
		if err != nil {
			return nil, err
		}
		scan = append(scan, string(rewriteJSON(raw, masked)))
		raw = rewriteJSON(raw, a.toFresh)
		r2.Body = io.NopCloser(bytes.NewReader(raw))
		r2.ContentLength = int64(len(raw))
		r2.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil }
	}

	for _, s := range scan {
		if a.leftover(s) {
			if r.Body != nil {
				_ = r.Body.Close()
			}
			return nil, ErrUntranslatedID
		}
	}

	resp, err := a.next.RoundTrip(r2)
	if err != nil || resp == nil {
		return resp, err
	}
	if ce := strings.TrimSpace(resp.Header.Get("Content-Encoding")); ce != "" && !strings.EqualFold(ce, "identity") {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		return nil, fmt.Errorf("%w (%s)", ErrEncodedResponse, ce)
	}
	if resp.Body == nil {
		return resp, nil
	}
	raw, rerr := readCapped(resp.Body)
	if rerr != nil {
		return nil, rerr
	}
	raw = rewriteJSON(raw, a.toOld)
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	resp.ContentLength = int64(len(raw))
	resp.Header.Del("Content-Length")
	return resp, nil
}
