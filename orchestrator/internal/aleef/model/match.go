package model

import "strings"

// Match returns every operation whose method equals method (case-insensitive)
// and whose path template matches path. A {placeholder} segment matches any
// single non-empty segment; matching is case-sensitive, and leading and
// trailing slashes are ignored (the same semantics the generator uses). The
// caller strips any query string first. An empty result means the request is
// not an operation of the model.
func (m Model) Match(method, path string) []Operation {
	var out []Operation
	for _, op := range m.Operations {
		if strings.EqualFold(op.Method, method) && PathMatches(op.Path, path) {
			out = append(out, op)
		}
	}
	return out
}

// PathMatches reports whether concrete matches the template opPath.
func PathMatches(opPath, concrete string) bool {
	a := strings.Split(strings.Trim(opPath, "/"), "/")
	b := strings.Split(strings.Trim(concrete, "/"), "/")
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if strings.HasPrefix(a[i], "{") && strings.HasSuffix(a[i], "}") {
			if b[i] == "" {
				return false
			}
			continue
		}
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
