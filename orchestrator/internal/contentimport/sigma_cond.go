package contentimport

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// A Sigma condition is a boolean expression over the rule's named selections. We evaluate it to find the smallest set
// of selections that makes it true, then emulate only those.

type condNode interface {
	eval(sel map[string]bool, names []string) bool
}

type condAtom string
type condNot struct{ x condNode }
type condBin struct {
	and  bool
	l, r condNode
}
type condQuant struct {
	n        int // 0 = all
	patterns []string
}

type condConst bool

func (c condConst) eval(map[string]bool, []string) bool { return bool(c) }

func (a condAtom) eval(sel map[string]bool, _ []string) bool    { return sel[string(a)] }
func (n condNot) eval(sel map[string]bool, names []string) bool { return !n.x.eval(sel, names) }
func (b condBin) eval(sel map[string]bool, names []string) bool {
	if b.and {
		return b.l.eval(sel, names) && b.r.eval(sel, names)
	}
	return b.l.eval(sel, names) || b.r.eval(sel, names)
}
func (q condQuant) eval(sel map[string]bool, names []string) bool {
	matched, hit := 0, 0
	for _, nm := range names {
		if !anyPattern(q.patterns, nm) {
			continue
		}
		matched++
		if sel[nm] {
			hit++
		}
	}
	if matched == 0 {
		return false
	}
	if q.n == 0 {
		return hit == matched
	}
	return hit >= q.n
}

func anyPattern(patterns []string, name string) bool {
	for _, p := range patterns {
		if matchPattern(p, name) {
			return true
		}
	}
	return false
}

func matchPattern(pattern, name string) bool {
	if pattern == "them" {
		return !strings.HasPrefix(name, "_")
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(name, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == name
}

func tokenizeCond(s string) []string {
	s = strings.NewReplacer("(", " ( ", ")", " ) ").Replace(s)
	return strings.Fields(s)
}

type condParser struct {
	t []string
	i int
}

func (p *condParser) peek() string {
	if p.i < len(p.t) {
		return strings.ToLower(p.t[p.i])
	}
	return ""
}

func parseCondition(s string) (condNode, error) {
	if strings.Contains(s, "|") {
		return nil, fmt.Errorf("aggregate conditions (count, near, ...) are not supported")
	}
	p := &condParser{t: tokenizeCond(s)}
	n, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.i != len(p.t) {
		return nil, fmt.Errorf("unexpected %q in condition", p.t[p.i])
	}
	return n, nil
}

func (p *condParser) or() (condNode, error) {
	l, err := p.and()
	if err != nil {
		return nil, err
	}
	for p.peek() == "or" {
		p.i++
		r, err := p.and()
		if err != nil {
			return nil, err
		}
		l = condBin{false, l, r}
	}
	return l, nil
}

func (p *condParser) and() (condNode, error) {
	l, err := p.not()
	if err != nil {
		return nil, err
	}
	for p.peek() == "and" {
		p.i++
		r, err := p.not()
		if err != nil {
			return nil, err
		}
		l = condBin{true, l, r}
	}
	return l, nil
}

func (p *condParser) not() (condNode, error) {
	if p.peek() == "not" {
		p.i++
		x, err := p.not()
		if err != nil {
			return nil, err
		}
		return condNot{x}, nil
	}
	return p.atom()
}

func (p *condParser) atom() (condNode, error) {
	if p.i >= len(p.t) {
		return nil, fmt.Errorf("condition ends unexpectedly")
	}
	tok := p.t[p.i]
	if tok == "(" {
		p.i++
		n, err := p.or()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, fmt.Errorf("missing closing parenthesis in condition")
		}
		p.i++
		return n, nil
	}
	if p.i+2 < len(p.t) && strings.EqualFold(p.t[p.i+1], "of") {
		q := condQuant{}
		consumed := 3
		if p.t[p.i+2] == "(" { // of ($a, $b*)
			j := p.i + 3
			for ; j < len(p.t) && p.t[j] != ")"; j++ {
				for _, part := range strings.Split(p.t[j], ",") {
					if part != "" {
						q.patterns = append(q.patterns, part)
					}
				}
			}
			if j >= len(p.t) {
				return nil, fmt.Errorf("missing closing parenthesis in condition")
			}
			consumed = j - p.i + 1
		} else {
			q.patterns = []string{p.t[p.i+2]}
		}
		switch low := strings.ToLower(tok); low {
		case "all":
			q.n = 0
		case "any":
			q.n = 1
		default:
			n, err := strconv.Atoi(low)
			if err != nil || n < 1 {
				return nil, fmt.Errorf("cannot read %q as a quantity", tok)
			}
			q.n = n
		}
		p.i += consumed
		return q, nil
	}
	p.i++
	if strings.EqualFold(tok, "true") {
		return condConst(true), nil
	}
	return condAtom(tok), nil
}

// satisfyingSets lists every subset of names that makes the condition true, smallest first (deterministic order).
func satisfyingSets(c condNode, names []string) ([][]string, error) {
	const maxAtoms = 14
	if len(names) > maxAtoms {
		return nil, fmt.Errorf("the rule has %d selections; at most %d are supported", len(names), maxAtoms)
	}
	sort.Strings(names)
	var out [][]string
	for mask := 0; mask < 1<<len(names); mask++ {
		sel := map[string]bool{}
		var set []string
		for i, nm := range names {
			if mask&(1<<i) != 0 {
				sel[nm] = true
				set = append(set, nm)
			}
		}
		if c.eval(sel, names) {
			out = append(out, set)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return len(out[i]) < len(out[j]) })
	return out, nil
}
