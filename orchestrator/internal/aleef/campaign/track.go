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

	// seen holds every id known before a request: fixture and existing
	// objects, ids returned by earlier responses and ids already tracked. An
	// object whose id was known is never compensated by this transport.
	smu  sync.Mutex
	seen map[string]bool

	mu    sync.Mutex
	track func(model.CreatedObject)
}

func (t *trackRT) setTrack(f func(model.CreatedObject)) {
	t.mu.Lock()
	t.track = f
	t.mu.Unlock()
}

func newTrackRT(next http.RoundTripper, cfg Config, m model.Model) *trackRT {
	t := &trackRT{next: next, m: m, comp: map[string]string{}, owners: map[string]string{}, seen: map[string]bool{}}
	for _, a := range cfg.Accounts {
		for _, id := range a.Existing {
			t.seen[id] = true
		}
	}
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

// markKnown records ids as known before any request (fixture objects).
func (t *trackRT) markKnown(ids ...string) {
	t.smu.Lock()
	for _, id := range ids {
		t.seen[id] = true
	}
	t.smu.Unlock()
}

// firstSight records id and reports whether it had not been seen before.
func (t *trackRT) firstSight(id string) bool {
	t.smu.Lock()
	defer t.smu.Unlock()
	if t.seen[id] {
		return false
	}
	t.seen[id] = true
	return true
}

func (t *trackRT) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.next.RoundTrip(r)
	if err != nil || resp == nil || resp.StatusCode < 200 || resp.StatusCode > 299 || len(t.comp) == 0 || resp.Body == nil {
		return resp, err
	}
	// Every successful response teaches the transport which ids exist; only a
	// creation response (exactly 201, declared for the operation) can name a
	// new object, and only if its id was not known before.
	creating := false
	var op *model.Operation
	if r.Method == http.MethodPost && resp.StatusCode == http.StatusCreated {
		path := strings.TrimPrefix(r.URL.Path, t.prefix)
		for _, c := range t.m.Match(r.Method, path) {
			c := c
			if ct := c.CreatedType(); ct != "" && t.comp[ct] != "" && len(c.PathParams) == 0 && c.Declares("201") {
				op, creating = &c, true
				break
			}
		}
	}
	raw, rerr := io.ReadAll(io.LimitReader(resp.Body, maxTrackBody+1))
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	if rerr != nil || len(raw) > maxTrackBody {
		return resp, nil
	}
	var out struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &out) != nil || out.ID == "" {
		return resp, nil
	}
	fresh := t.firstSight(out.ID)
	if !creating || !fresh {
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
