package openapi

import (
	"regexp"
	"sort"
	"strings"
)

// Observed is a route seen in use, from a gateway log, a route table or a lab. Path is concrete (no template).
type Observed struct {
	Method string
	Path   string
}

// Drift is the gap between a specification and the routes observed in use.
type Drift struct {
	// Undocumented are observed routes no operation in the specification matches: routes served that nobody described.
	Undocumented []Observed
	// Unserved are specified operations no observed route matches. Absence from the observed list is not proof the route is not
	// served, only that it was not seen.
	Unserved []Operation
	// DeprecatedInUse are deprecated operations that were observed.
	DeprecatedInUse []Operation
}

var templateSeg = regexp.MustCompile(`\{[^/}]+\}`)

// matcher compiles an operation path template to a whole-path matcher. A template segment matches one non-empty segment.
func matcher(path string) *regexp.Regexp {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if templateSeg.MatchString(p) && strings.HasPrefix(p, "{") && strings.HasSuffix(p, "}") {
			parts[i] = `[^/]+`
		} else {
			parts[i] = regexp.QuoteMeta(p)
		}
	}
	return regexp.MustCompile(`^` + strings.Join(parts, "/") + `/?$`)
}

// Diff compares the inventory with observed routes. Observed paths are matched on method and path; a query string is ignored.
func (inv *Inventory) Diff(observed []Observed) Drift {
	type compiled struct {
		op Operation
		re *regexp.Regexp
	}
	ops := make([]compiled, len(inv.Operations))
	for i, o := range inv.Operations {
		ops[i] = compiled{o, matcher(o.Path)}
	}
	hit := make([]bool, len(ops))
	var d Drift
	for _, ob := range observed {
		path, _, _ := strings.Cut(ob.Path, "?")
		method := strings.ToUpper(ob.Method)
		matched := false
		for i, c := range ops {
			if c.op.Method == method && c.re.MatchString(path) {
				hit[i] = true
				matched = true
			}
		}
		if !matched {
			d.Undocumented = append(d.Undocumented, Observed{Method: method, Path: path})
		}
	}
	for i, c := range ops {
		if !hit[i] {
			d.Unserved = append(d.Unserved, c.op)
		} else if c.op.Deprecated {
			d.DeprecatedInUse = append(d.DeprecatedInUse, c.op)
		}
	}
	sort.Slice(d.Undocumented, func(i, j int) bool {
		return d.Undocumented[i].Path+d.Undocumented[i].Method < d.Undocumented[j].Path+d.Undocumented[j].Method
	})
	return d
}
