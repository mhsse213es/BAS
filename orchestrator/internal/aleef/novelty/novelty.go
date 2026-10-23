// Package novelty decides whether a generated scenario repeats something the
// existing catalogue already tests. Two scenarios overlap when they make the
// same kind of claim (the property class) and the attack of one has the same
// normalized (method, path shape) as any step of the other. Scenario ids and
// names play no part.
package novelty

import (
	"regexp"
	"strings"

	"github.com/audspect/bas/internal/apibas/contract"
)

var (
	numericSeg = regexp.MustCompile(`^[0-9]+$`)
	uuidSeg    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// Shape normalizes a request path: the query is dropped, the path is lower
// cased, and every placeholder ({x}), numeric or uuid-like segment becomes
// {id}.
func Shape(path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	var out []string
	for _, seg := range strings.Split(strings.ToLower(path), "/") {
		switch {
		case seg == "":
			continue
		case strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}"),
			numericSeg.MatchString(seg), uuidSeg.MatchString(seg):
			seg = "{id}"
		}
		out = append(out, seg)
	}
	return "/" + strings.Join(out, "/")
}

func key(st contract.Step) string {
	return strings.ToUpper(st.Method) + " " + Shape(st.Path)
}

// Covered reports whether the catalogue already tests what s tests: some
// catalogue scenario has the same claim (the property class) and a step with
// the same normalized method and path shape as s's attack step. A scenario
// without steps is never covered.
func Covered(s contract.Scenario, cat []contract.Scenario) bool {
	if len(s.Steps) == 0 {
		return false
	}
	want := key(s.Steps[len(s.Steps)-1])
	for _, c := range cat {
		if c.Claim != s.Claim {
			continue
		}
		for _, st := range c.Steps {
			if key(st) == want {
				return true
			}
		}
	}
	return false
}
