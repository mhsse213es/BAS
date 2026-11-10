package runner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"

	"github.com/audspect/bas/internal/apibas/scope"
)

// A customer API offers no administrative view of its records, so state is judged the only way the customer's own interface allows:
// each object the test may touch is read back through its normal read route as its owner. The reads are independent of the attack
// (a different request, a different identity, taken before and after), but they see only what that route returns; a change to a
// field the route does not return cannot be detected.

// maxProbeBody bounds how much of a probe response is read.
const maxProbeBody = 1 << 20

// Probe is one object the state reader watches: the owner's credential, the concrete read path, and response fields to leave out
// of the comparison (timestamps and other values that change on every read).
type Probe struct {
	Key      string
	TokenRef string
	Path     string
	Ignore   []string
}

// Restore puts one object back to the state the customer supplied, by repeating the write as its owner.
type Restore struct {
	Key      string
	TokenRef string
	Method   string
	Path     string
	Body     string
}

// noRedirect keeps a probe or restore on the host it was aimed at.
func noRedirect(c *http.Client) *http.Client {
	cp := *c
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &cp
}

func checkPaths(allowed []string, paths []string) error {
	if len(allowed) == 0 {
		return nil
	}
	for _, p := range paths {
		if !scope.Allowed(allowed, p) {
			return errors.New("a state request would leave the target's allowed paths")
		}
	}
	return nil
}

// HTTPState is a StateReader that reads each probe as its owner.
type HTTPState struct {
	base    string
	probes  []Probe
	secrets SecretResolver
	client  *http.Client
}

// NewHTTPState returns a reader for the probes. It refuses a probe outside the allowed paths.
func NewHTTPState(base string, probes []Probe, secrets SecretResolver, client *http.Client, allowed []string) (*HTTPState, error) {
	paths := make([]string, 0, len(probes))
	for _, p := range probes {
		paths = append(paths, p.Path)
	}
	if err := checkPaths(allowed, paths); err != nil {
		return nil, err
	}
	return &HTTPState{base: base, probes: probes, secrets: secrets, client: noRedirect(client)}, nil
}

// Snapshot reads every probe and returns one record per object. The record's Tag is a hash of the response with the ignored fields
// removed, so any change to what the owner can read shows as a difference. A transport failure or a server error is an error, not a
// state: the runner then reports ERROR instead of guessing.
func (h *HTTPState) Snapshot(ctx context.Context) (map[string]StateRecord, error) {
	out := make(map[string]StateRecord, len(h.probes))
	for _, p := range h.probes {
		tok, err := h.secrets.Resolve(p.TokenRef)
		if err != nil {
			return nil, errors.New("owner credential unavailable for a state read")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.base+p.Path, nil)
		if err != nil {
			return nil, errors.New("state read could not be built")
		}
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := h.client.Do(req)
		if err != nil {
			return nil, errors.New("state read failed")
		}
		raw, rerr := io.ReadAll(io.LimitReader(resp.Body, maxProbeBody+1))
		resp.Body.Close()
		if rerr != nil || len(raw) > maxProbeBody {
			return nil, errors.New("state read returned an unreadable or oversized body")
		}
		if resp.StatusCode >= 500 {
			return nil, fmt.Errorf("state read returned %d", resp.StatusCode)
		}
		out[p.Key] = StateRecord{ID: p.Key, Status: strconv.Itoa(resp.StatusCode), Tag: fingerprint(raw, p.Ignore)}
	}
	return out, nil
}

// fingerprint hashes a response body. JSON is normalised (keys sorted, ignored fields dropped at any depth); anything else is hashed
// as it is.
func fingerprint(raw []byte, ignore []string) string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		sum := sha256.Sum256(raw)
		return hex.EncodeToString(sum[:])
	}
	skip := map[string]bool{}
	for _, k := range ignore {
		skip[k] = true
	}
	norm, _ := json.Marshal(drop(v, skip))
	sum := sha256.Sum256(norm)
	return hex.EncodeToString(sum[:])
}

func drop(v any, skip map[string]bool) any {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			if !skip[k] {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		out := make(map[string]any, len(keys))
		for _, k := range keys {
			out[k] = drop(t[k], skip)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = drop(e, skip)
		}
		return out
	default:
		return v
	}
}

// HTTPRestore is a Resetter that sends each restore request as the object's owner. The runner calls it before a write scenario (so the
// run starts from the supplied state, which also proves the restore works) and after (cleanup). A restore the target refuses is an
// error: the runner then reports the target state as unknown rather than PASS.
type HTTPRestore struct {
	base     string
	restores []Restore
	secrets  SecretResolver
	client   *http.Client
}

// NewHTTPRestore returns a restorer. It refuses a restore outside the allowed paths.
func NewHTTPRestore(base string, restores []Restore, secrets SecretResolver, client *http.Client, allowed []string) (*HTTPRestore, error) {
	paths := make([]string, 0, len(restores))
	for _, r := range restores {
		paths = append(paths, r.Path)
	}
	if err := checkPaths(allowed, paths); err != nil {
		return nil, err
	}
	return &HTTPRestore{base: base, restores: restores, secrets: secrets, client: noRedirect(client)}, nil
}

// Reset repeats every restore request.
func (h *HTTPRestore) Reset(ctx context.Context) error {
	for _, r := range h.restores {
		tok, err := h.secrets.Resolve(r.TokenRef)
		if err != nil {
			return errors.New("owner credential unavailable for a restore")
		}
		req, err := http.NewRequestWithContext(ctx, r.Method, h.base+r.Path, bytes.NewReader([]byte(r.Body)))
		if err != nil {
			return errors.New("restore could not be built")
		}
		req.Header.Set("Content-Type", "application/json")
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := h.client.Do(req)
		if err != nil {
			return errors.New("restore failed")
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxProbeBody))
		resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			return fmt.Errorf("restore of %s returned %d", r.Key, resp.StatusCode)
		}
	}
	return nil
}
