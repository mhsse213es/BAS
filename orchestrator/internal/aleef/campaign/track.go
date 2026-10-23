package campaign

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/audspect/bas/internal/aleef/model"
)

// Compensation of objects a test creates.
//
// Tests may call creating operations (a POST on a collection). The objects they
// make would outlive the run, and a run whose cleanup cannot be proven ends
// unconfirmed. trackRT watches the executor's traffic: when a successful POST
// matches an operation that creates objects of a type the operator declared a
// compensation for (the Setup declarations name it), the id in the response is
// handed to the executor's Track so cleanup compensates it as the owning
// account. Only a top-level string "id" is recognised; nothing else is read or
// kept, and no body is ever stored.

const maxTrackBody = 1 << 20

type trackRT struct {
	next   http.RoundTripper
	m      model.Model
	prefix string
	// comp maps a created resource type to the compensating operation id.
	comp map[string]string
	// owners maps a bearer token to the customer it belongs to (memory only).
	owners map[string]string

	// learn tells the id translator about a created object's id.
	learn func(string)

	mu    sync.Mutex
	track func(model.CreatedObject)
}

func (t *trackRT) setTrack(f func(model.CreatedObject)) {
	t.mu.Lock()
	t.track = f
	t.mu.Unlock()
}

func newTrackRT(next http.RoundTripper, cfg Config, m model.Model) *trackRT {
	t := &trackRT{next: next, m: m, comp: map[string]string{}, owners: map[string]string{}}
	if u, err := url.Parse(cfg.BaseURL); err == nil {
		t.prefix = strings.TrimRight(u.Path, "/")
	}
	for _, s := range cfg.Setup {
		if s.Compensate == "" {
			continue
		}
		for _, op := range m.Operations {
			if op.ID == s.OperationID {
				if ct := op.CreatedType(); ct != "" {
					t.comp[ct] = s.Compensate
				}
			}
		}
	}
	for _, a := range cfg.Accounts {
		if tok, err := cfg.Secrets.Resolve(a.TokenRef); err == nil && tok != "" {
			t.owners[tok] = a.CustomerID
		}
	}
	return t
}

func (t *trackRT) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.next.RoundTrip(r)
	if err != nil || resp == nil || r.Method != http.MethodPost || resp.StatusCode < 200 || resp.StatusCode > 299 || len(t.comp) == 0 {
		return resp, err
	}
	path := strings.TrimPrefix(r.URL.Path, t.prefix)
	var op *model.Operation
	for _, c := range t.m.Match(r.Method, path) {
		c := c
		if ct := c.CreatedType(); ct != "" && t.comp[ct] != "" && len(c.PathParams) == 0 {
			op = &c
			break
		}
	}
	if op == nil || resp.Body == nil {
		return resp, err
	}
	raw, rerr := io.ReadAll(io.LimitReader(resp.Body, maxTrackBody+1))
	_ = resp.Body.Close()
	if rerr != nil || len(raw) > maxTrackBody {
		// The caller still gets what was read; an unreadable or oversized body is
		// not tracked and shows up as a leftover object.
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		return resp, nil
	}
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	var out struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &out) != nil || out.ID == "" {
		return resp, nil
	}
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	owner, ok := t.owners[tok]
	if !ok {
		return resp, nil
	}
	t.mu.Lock()
	f := t.track
	t.mu.Unlock()
	if t.learn != nil {
		t.learn(out.ID)
	}
	if f != nil {
		f(model.CreatedObject{Operation: op.ID, ID: out.ID, Owner: owner, Compensate: t.comp[op.CreatedType()]})
	}
	return resp, nil
}
