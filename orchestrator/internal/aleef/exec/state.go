package exec

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
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/audspect/bas/internal/aleef/model"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/runner"
)

const maxStateResponse = 1 << 20

// tokenForOwner resolves an object owner (a customer id) to the bearer token
// of the fixture identity that owns it. The token is returned to the caller
// only and is never stored or logged.
func tokenForOwner(fx fixture.Fixture, secrets runner.SecretResolver, owner string) (string, error) {
	for _, id := range fx.Identities {
		if id.CustomerID == owner {
			tok, err := secrets.Resolve(id.TokenRef)
			if err != nil {
				return "", fmt.Errorf("credential for owner %q unavailable", owner)
			}
			return tok, nil
		}
	}
	return "", fmt.Errorf("no fixture identity owns customer %q", owner)
}

// call sends one body-less request as the given bearer token. Errors never
// contain the token or any response content.
func call(ctx context.Context, d model.Doer, method, target, token string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return 0, nil, errors.New("build request failed")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := d.Do(req)
	if err != nil {
		return 0, nil, errors.New("request failed")
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxStateResponse))
	if err != nil {
		return resp.StatusCode, nil, errors.New("read response failed")
	}
	return resp.StatusCode, data, nil
}

// objectIDParam returns the single path parameter of an operation.
func objectIDParam(op model.Operation) (model.Param, bool) {
	if len(op.PathParams) != 1 {
		return model.Param{}, false
	}
	return op.PathParams[0], true
}

// fillPath renders an operation path for one object id.
func fillPath(op model.Operation, id string) (string, bool) {
	p, ok := objectIDParam(op)
	if !ok {
		return "", false
	}
	return strings.ReplaceAll(op.Path, "{"+p.Name+"}", url.PathEscape(id)), true
}

func opByID(m model.Model, id string) (model.Operation, bool) {
	for _, o := range m.Operations {
		if o.ID == id {
			return o, true
		}
	}
	return model.Operation{}, false
}

func requiredQuery(op model.Operation) bool {
	for _, p := range op.QueryParams {
		if p.Required {
			return true
		}
	}
	return false
}

// pickReadOp chooses the operation UATState reads objects through: a GET of
// class Read with one object-id path parameter and no required query
// parameter. A named override wins. Among candidates the one whose path ends
// in the identifier is preferred, then the smallest id.
func pickReadOp(m model.Model, override string) (model.Operation, error) {
	if override != "" {
		op, ok := opByID(m, override)
		if !ok || op.Method != "GET" || op.Class != model.ClassRead || requiredQuery(op) {
			return model.Operation{}, fmt.Errorf("exec: read operation %q is not a usable Read GET", override)
		}
		if _, ok := objectIDParam(op); !ok {
			return model.Operation{}, fmt.Errorf("exec: read operation %q needs exactly one path parameter", override)
		}
		return op, nil
	}
	var cands []model.Operation
	for _, op := range m.Operations {
		if op.Method != "GET" || op.Class != model.ClassRead || requiredQuery(op) {
			continue
		}
		if p, ok := objectIDParam(op); ok && p.IsObjectID {
			cands = append(cands, op)
		}
	}
	if len(cands) == 0 {
		return model.Operation{}, errors.New("exec: model has no Read GET operation with a single object-id path parameter")
	}
	sort.Slice(cands, func(i, j int) bool {
		ei := strings.HasSuffix(cands[i].Path, "}")
		ej := strings.HasSuffix(cands[j].Path, "}")
		if ei != ej {
			return ei
		}
		return cands[i].ID < cands[j].ID
	})
	return cands[0], nil
}

// UATState implements runner.StateReader by reading each known object through
// a Read operation of the model, as the owning account.
//
// A record carries generic fields mapped by name when present (status or
// state, owner, quantity or amount, beneficiary) and, in Tag, a SHA-256 of the
// whole JSON body. StateRecord is too narrow to see arbitrary fields, so any
// change to the object, in any field, changes Tag and registers as a state
// change. Obvious volatile keys (updated_at and similar) are left out of the
// hash. An object the server no longer returns (404 or 410) is absent from the
// snapshot, which also registers as a change.
//
// UATState only sees objects it knows: the fixture objects, the Created list
// and anything passed to Track. Records the attack creates elsewhere are
// invisible to it; Config.StateExtra can supply an enumerating adapter.
type UATState struct {
	base    string
	fx      fixture.Fixture
	secrets runner.SecretResolver
	doer    model.Doer
	op      model.Operation
	extra   runner.StateReader

	mu      sync.Mutex
	objects []model.CreatedObject
}

func newUATState(cfg Config, doer model.Doer) (*UATState, error) {
	op, err := pickReadOp(cfg.Model, cfg.ReadOperation)
	if err != nil {
		return nil, err
	}
	u := &UATState{base: strings.TrimRight(cfg.BaseURL, "/"), fx: cfg.Fixture, secrets: cfg.Secrets, doer: doer, op: op, extra: cfg.StateExtra}
	for _, o := range cfg.Fixture.Objects {
		u.add(model.CreatedObject{ID: o.ID, Owner: o.OwnerID})
	}
	for _, c := range cfg.Created {
		u.add(c)
	}
	return u, nil
}

func (u *UATState) add(o model.CreatedObject) {
	for _, e := range u.objects {
		if e.ID == o.ID {
			return
		}
	}
	u.objects = append(u.objects, o)
}

// Track makes the reader aware of an object created during a run.
func (u *UATState) Track(o model.CreatedObject) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.add(o)
}

// Snapshot implements runner.StateReader.
func (u *UATState) Snapshot(ctx context.Context) (map[string]runner.StateRecord, error) {
	u.mu.Lock()
	objs := append([]model.CreatedObject(nil), u.objects...)
	u.mu.Unlock()
	out := make(map[string]runner.StateRecord, len(objs))
	for _, o := range objs {
		rec, present, err := u.read(ctx, o)
		if err != nil {
			return nil, err
		}
		if present {
			out[o.ID] = rec
		}
	}
	if u.extra != nil {
		ex, err := u.extra.Snapshot(ctx)
		if err != nil {
			return nil, err
		}
		for id, rec := range ex {
			out["x:"+id] = rec
		}
	}
	return out, nil
}

func (u *UATState) read(ctx context.Context, o model.CreatedObject) (runner.StateRecord, bool, error) {
	path, ok := fillPath(u.op, o.ID)
	if !ok {
		return runner.StateRecord{}, false, errors.New("state read: read operation has no single path parameter")
	}
	tok, err := tokenForOwner(u.fx, u.secrets, o.Owner)
	if err != nil {
		return runner.StateRecord{}, false, fmt.Errorf("state read of %q: %w", o.ID, err)
	}
	status, body, err := call(ctx, u.doer, "GET", u.base+path, tok)
	if err != nil {
		return runner.StateRecord{}, false, fmt.Errorf("state read of %q: %w", o.ID, err)
	}
	switch {
	case status == http.StatusNotFound || status == http.StatusGone:
		return runner.StateRecord{}, false, nil
	case status < 200 || status > 299:
		return runner.StateRecord{}, false, fmt.Errorf("state read of %q: unexpected status %d", o.ID, status)
	}
	return mapRecord(o.ID, body), true, nil
}

var volatileKeys = map[string]bool{
	"updated_at": true, "updatedat": true, "modified_at": true, "modifiedat": true,
	"last_modified": true, "lastmodified": true, "etag": true,
}

func mapRecord(id string, body []byte) runner.StateRecord {
	rec := runner.StateRecord{ID: id}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		sum := sha256.Sum256(body)
		rec.Tag = hex.EncodeToString(sum[:])
		return rec
	}
	if m, ok := doc.(map[string]any); ok {
		rec.OwnerID = firstField(m, "owner_id", "ownerid", "owner", "customer_id", "customerid", "customer", "user_id", "userid")
		rec.Status = firstField(m, "status", "state")
		rec.Quantity = firstField(m, "quantity", "qty", "amount")
		rec.BeneficiaryRef = firstField(m, "beneficiary_ref", "beneficiaryref", "beneficiary", "beneficiary_id")
		clean := make(map[string]any, len(m))
		for k, v := range m {
			if !volatileKeys[strings.ToLower(k)] {
				clean[k] = v
			}
		}
		doc = clean
	}
	canon, _ := json.Marshal(doc) // maps marshal with sorted keys
	sum := sha256.Sum256(canon)
	rec.Tag = hex.EncodeToString(sum[:])
	return rec
}

func firstField(m map[string]any, names ...string) string {
	lower := make(map[string]any, len(m))
	for k, v := range m {
		lower[strings.ToLower(k)] = v
	}
	for _, n := range names {
		switch v := lower[n].(type) {
		case string:
			if v != "" {
				return v
			}
		case json.Number:
			return v.String()
		case bool:
			return strconv.FormatBool(v)
		}
	}
	return ""
}

// recorder wraps a StateReader and keeps every snapshot the runner takes, so
// the executor can tell whether the attack changed state without depending on
// the runner's graded outcome. The runner compares the second-to-last and
// last snapshots, and so does diff.
type recorder struct {
	inner runner.StateReader
	snaps []map[string]runner.StateRecord
}

func (r *recorder) Snapshot(ctx context.Context) (map[string]runner.StateRecord, error) {
	s, err := r.inner.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	cp := make(map[string]runner.StateRecord, len(s))
	for k, v := range s {
		cp[k] = v
	}
	r.snaps = append(r.snaps, cp)
	return s, nil
}

// diff reports whether the last two snapshots differ. known is false when
// fewer than two snapshots were taken.
func (r *recorder) diff() (changed, known bool) {
	n := len(r.snaps)
	if n < 2 {
		return false, false
	}
	a, b := r.snaps[n-2], r.snaps[n-1]
	if len(a) != len(b) {
		return true, true
	}
	for id, rec := range a {
		if o, ok := b[id]; !ok || o != rec {
			return true, true
		}
	}
	return false, true
}
