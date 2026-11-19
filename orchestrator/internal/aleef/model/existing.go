package model

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Existing objects and chained setup.
//
// Account.Existing declares objects that already exist for the account and
// that the API cannot create (an account, a document handed to the tester).
// Aleef never creates, changes the ownership of, or deletes them: they are
// not recorded as created objects, so cleanup and compensation never touch
// them, and since their ids are the same in every fixture they need no id
// translation.
//
// A setup body string may reference an object the same account already has
// with {{self.<type>.id}}. <type> is a resource type (see resource.go) that
// the account declares in Existing or that an EARLIER setup operation creates
// (its CreatedType), so dependent objects can be built in declared order. The
// placeholder is replaced before the request is built and never reaches the
// wire. Any other use of "{{self." is an error (any other "{{" in a setup string). Everything is validated before
// the first request is sent.

var (
	selfRef    = regexp.MustCompile(`\{\{\s*self\.([a-z0-9_]+)\.id\s*\}\}`)
	existingID = regexp.MustCompile(`^[A-Za-z0-9._~:@!$'()*+,-]{1,128}$`)
)

// validateExisting checks every account's Existing map against the model.
func validateExisting(m Model, accounts []Account) error {
	literals := map[string]bool{}
	for _, op := range m.Operations {
		for _, s := range strings.Split(strings.Trim(op.Path, "/"), "/") {
			if s != "" && !strings.HasPrefix(s, "{") {
				literals[strings.ToLower(s)] = true
			}
		}
	}
	for _, a := range accounts {
		for _, t := range sortedKeys(a.Existing) {
			id := a.Existing[t]
			if !m.HasResourceType(t) {
				return fmt.Errorf("account %q: existing object type %q is not a resource type of the model", a.Name, t)
			}
			if id == "." || id == ".." || !existingID.MatchString(id) {
				return fmt.Errorf("account %q: existing %s id is not a plain single path segment", a.Name, t)
			}
			if literals[strings.ToLower(id)] {
				return fmt.Errorf("account %q: existing %s id equals a literal route segment", a.Name, t)
			}
		}
	}
	return nil
}

// bodyRefs returns the placeholder types in v and an error for malformed use.
func bodyRefs(v any) ([]string, error) {
	var out []string
	var walk func(any) error
	walk = func(x any) error {
		switch t := x.(type) {
		case string:
			rest := selfRef.ReplaceAllString(t, "")
			if strings.Contains(rest, "{{") {
				return fmt.Errorf("malformed placeholder (use {{self.<type>.id}})")
			}
			for _, m := range selfRef.FindAllStringSubmatch(t, -1) {
				out = append(out, m[1])
			}
		case map[string]any:
			for _, k := range sortedKeys(t) {
				if err := walk(t[k]); err != nil {
					return err
				}
			}
		case []any:
			for _, e := range t {
				if err := walk(e); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return out, walk(v)
}

// validateChains checks, for every account, that each placeholder refers to a
// type available at that point of the setup. Nothing has been sent yet.
func validateChains(m Model, accounts []Account, setup []SetupOp, ops []*Operation) error {
	for _, a := range accounts {
		have := map[string]bool{}
		for t := range a.Existing {
			have[t] = true
		}
		for i, s := range setup {
			refs, err := bodyRefs(s.Body)
			if err != nil {
				return fmt.Errorf("setup %q: %v", s.OperationID, err)
			}
			for _, t := range refs {
				if !have[t] {
					return fmt.Errorf("setup %q for account %q: placeholder self.%s.id has no earlier object of that type", s.OperationID, a.Name, t)
				}
			}
			if ct := ops[i].CreatedType(); ct != "" {
				have[ct] = true
			}
		}
	}
	return nil
}

// resolveBody returns a copy of body with every placeholder replaced.
func resolveBody(body map[string]any, self map[string]string) (map[string]any, error) {
	var sub func(any) (any, error)
	sub = func(x any) (any, error) {
		switch t := x.(type) {
		case string:
			var missing string
			out := selfRef.ReplaceAllStringFunc(t, func(tok string) string {
				typ := selfRef.FindStringSubmatch(tok)[1]
				id, ok := self[typ]
				if !ok {
					missing = typ
					return tok
				}
				return id
			})
			if missing != "" {
				return nil, fmt.Errorf("placeholder self.%s.id is unresolved", missing)
			}
			return out, nil
		case map[string]any:
			m := make(map[string]any, len(t))
			for k, v := range t {
				r, err := sub(v)
				if err != nil {
					return nil, err
				}
				m[k] = r
			}
			return m, nil
		case []any:
			s := make([]any, len(t))
			for i, v := range t {
				r, err := sub(v)
				if err != nil {
					return nil, err
				}
				s[i] = r
			}
			return s, nil
		}
		return x, nil
	}
	r, err := sub(body)
	if err != nil {
		return nil, err
	}
	out, _ := r.(map[string]any)
	if out == nil {
		out = map[string]any{}
	}
	return out, nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
