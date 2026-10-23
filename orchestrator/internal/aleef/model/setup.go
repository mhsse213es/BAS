package model

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"

	"github.com/audspect/bas/internal/apibas/fixture"
)

// Account is a test principal the operator declares for fixture building.
type Account struct {
	Name, CustomerID, TokenRef, Role string
}

// SetupOp is an operator-declared creation step. Compensate names the
// operation that undoes it.
type SetupOp struct {
	OperationID string
	Body        map[string]any
	Compensate  string
}

// CreatedObject records one object made by BuildFixture, for later cleanup.
type CreatedObject struct {
	Operation, ID, Owner, Compensate string
}

// Doer sends an HTTP request.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// SecretResolver returns the secret behind a reference.
type SecretResolver interface {
	Resolve(ref string) (string, error)
}

// setupBase is the placeholder origin of setup requests. The Doer is expected
// to rewrite the host (for example through its transport).
const setupBase = "http://aleef.invalid"

const maxSetupResponse = 1 << 20

// BuildFixture runs each setup operation once per account, in the order
// given, and returns the resulting fixture and the created objects. Only
// operations classified ClassSetupSafe may run. Each created body carries a
// canary in its first free-text field when the schema has one.
func BuildFixture(ctx context.Context, m Model, accounts []Account, setup []SetupOp, d Doer, secrets SecretResolver, runTag string) (fixture.Fixture, []CreatedObject, error) {
	ops := make([]*Operation, len(setup))
	for i, s := range setup {
		var op *Operation
		for j := range m.Operations {
			if m.Operations[j].ID == s.OperationID {
				op = &m.Operations[j]
				break
			}
		}
		if op == nil {
			return fixture.Fixture{}, nil, fmt.Errorf("setup operation %q not in model", s.OperationID)
		}
		if op.Class != ClassSetupSafe {
			return fixture.Fixture{}, nil, fmt.Errorf("setup operation %q is not classified setup_safe", s.OperationID)
		}
		if len(op.PathParams) > 0 {
			return fixture.Fixture{}, nil, fmt.Errorf("setup operation %q has path parameters, which are not supported", s.OperationID)
		}
		ops[i] = op
	}

	var f fixture.Fixture
	f.Name = "aleef-" + runTag
	var created []CreatedObject
	for _, a := range accounts {
		f.Identities = append(f.Identities, fixture.Identity{Name: a.Name, CustomerID: a.CustomerID, TokenRef: a.TokenRef, Role: a.Role})
	}
	for _, a := range accounts {
		token, err := secrets.Resolve(a.TokenRef)
		if err != nil {
			return fixture.Fixture{}, nil, fmt.Errorf("resolve token for account %q: secret unavailable", a.Name)
		}
		for i, s := range setup {
			op := ops[i]
			canary := ""
			body := map[string]any{}
			for k, v := range s.Body {
				body[k] = v
			}
			if field := canaryField(op.Body); field != "" {
				canary = "ALEEF-CANARY-" + runTag + "-" + a.Name
				body[field] = canary
			}
			id, err := send(ctx, d, op, body, token)
			if err != nil {
				return fixture.Fixture{}, nil, fmt.Errorf("setup %q for account %q: %w", op.ID, a.Name, err)
			}
			obj := fixture.Object{ID: id, OwnerID: a.CustomerID, Public: map[string]string{}, Protected: map[string]string{"canary": canary}}
			if canary == "" {
				obj.Public["confidence"] = "structural"
			}
			f.Objects = append(f.Objects, obj)
			created = append(created, CreatedObject{Operation: op.ID, ID: id, Owner: a.CustomerID, Compensate: s.Compensate})
		}
	}
	return f, created, nil
}

// canaryField returns the first property (sorted) that can carry free text.
func canaryField(s *Schema) string {
	for _, n := range s.PropertyNames() {
		p := s.Properties[n]
		if p == nil || p.Type != "string" || len(p.Enum) > 0 || p.Format != "" || objectIDName.MatchString(n) {
			continue
		}
		return n
	}
	return ""
}

func send(ctx context.Context, d Doer, op *Operation, body map[string]any, token string) (string, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("encode body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, op.Method, setupBase+op.Path, bytes.NewReader(raw))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := d.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxSetupResponse))
		return "", fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSetupResponse))
	if err != nil {
		return "", fmt.Errorf("read response")
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("response is not a JSON object")
	}
	if v, ok := out["id"].(string); ok && v != "" {
		return v, nil
	}
	names := make([]string, 0, len(out))
	for k := range out {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if v, ok := out[k].(string); ok && v != "" && objectIDName.MatchString(k) {
			return v, nil
		}
	}
	return "", fmt.Errorf("no object id in response")
}
