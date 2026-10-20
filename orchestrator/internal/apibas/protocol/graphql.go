package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// GraphQL is the GraphQL adapter. A GraphQL operation travels as a JSON POST whose body has a
// "query" string. The adapter checks that the body is that shape and that the query parses, so
// a malformed scenario fails before it is sent. Execution is the target's job.
type GraphQL struct{}

func init() { Register(GraphQL{}) }

// Name is the protocol name.
func (GraphQL) Name() string { return "graphql" }

// Validate checks the body: a JSON object with a "query" string that parses.
func (GraphQL) Validate(body string) error {
	var req struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		return fmt.Errorf("graphql body must be a JSON object: %w", err)
	}
	if strings.TrimSpace(req.Query) == "" {
		return errors.New("graphql body needs a non-empty query string")
	}
	_, err := ParseGraphQL(req.Query)
	return err
}

// Field is one selected field of a GraphQL selection set.
type Field struct {
	Name   string
	Args   map[string]string
	HasSub bool
	Sub    []Field
}

// Document is a parsed operation: the selections of its root selection set.
type Document struct {
	Fields []Field
}

// Depth is the number of nested selection sets along the deepest path, counting the root.
func (d Document) Depth() int {
	return 1 + maxSubDepth(d.Fields)
}

func maxSubDepth(fields []Field) int {
	best := 0
	for _, f := range fields {
		if !f.HasSub {
			continue
		}
		if d := 1 + maxSubDepth(f.Sub); d > best {
			best = d
		}
	}
	return best
}

// ParseGraphQL parses a query of the form `{ field(arg: "v") { ... } }`, optionally prefixed by
// `query` and an operation name. Aliases, fragments and variables are not supported and are
// reported as errors, so the parser never silently accepts something it does not run.
func ParseGraphQL(query string) (Document, error) {
	p := &gqlParser{toks: tokenize(query)}
	if p.peek() == "query" {
		p.next()
		if isName(p.peek()) {
			p.next()
		}
	}
	if err := p.expect("{"); err != nil {
		return Document{}, err
	}
	fields, err := p.selections()
	if err != nil {
		return Document{}, err
	}
	if p.peek() != "" {
		return Document{}, fmt.Errorf("unexpected %q after the operation", p.peek())
	}
	return Document{Fields: fields}, nil
}

type gqlParser struct {
	toks []string
	pos  int
}

func (p *gqlParser) peek() string {
	if p.pos >= len(p.toks) {
		return ""
	}
	return p.toks[p.pos]
}

func (p *gqlParser) next() string {
	t := p.peek()
	if p.pos < len(p.toks) {
		p.pos++
	}
	return t
}

func (p *gqlParser) expect(tok string) error {
	if got := p.next(); got != tok {
		return fmt.Errorf("expected %q, got %q", tok, got)
	}
	return nil
}

// selections reads fields up to and including the closing brace. The opening brace is already read.
func (p *gqlParser) selections() ([]Field, error) {
	var out []Field
	for {
		t := p.peek()
		if t == "" {
			return nil, errors.New("unexpected end of query, missing }")
		}
		if t == "}" {
			p.next()
			if len(out) == 0 {
				return nil, errors.New("empty selection set")
			}
			return out, nil
		}
		f, err := p.field()
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
}

func (p *gqlParser) field() (Field, error) {
	name := p.next()
	if !isName(name) {
		return Field{}, fmt.Errorf("expected a field name, got %q", name)
	}
	f := Field{Name: name, Args: map[string]string{}}
	if p.peek() == "(" {
		p.next()
		for p.peek() != ")" {
			if p.peek() == "" {
				return Field{}, errors.New("unexpected end of query inside arguments")
			}
			argName := p.next()
			if !isName(argName) {
				return Field{}, fmt.Errorf("expected an argument name, got %q", argName)
			}
			if err := p.expect(":"); err != nil {
				return Field{}, err
			}
			val := p.next()
			if val == "" || val == ")" || val == "{" || val == "}" {
				return Field{}, fmt.Errorf("argument %s has no value", argName)
			}
			f.Args[argName] = strings.Trim(val, `"`)
		}
		p.next() // ")"
	}
	if p.peek() == "{" {
		p.next()
		sub, err := p.selections()
		if err != nil {
			return Field{}, err
		}
		f.HasSub = true
		f.Sub = sub
	}
	return f, nil
}

// tokenize splits a query into names, punctuation and string literals. Commas are whitespace.
func tokenize(q string) []string {
	var toks []string
	r := []rune(q)
	for i := 0; i < len(r); {
		c := r[i]
		switch {
		case unicode.IsSpace(c) || c == ',':
			i++
		case strings.ContainsRune("{}():", c):
			toks = append(toks, string(c))
			i++
		case c == '"':
			j := i + 1
			for j < len(r) && r[j] != '"' {
				if r[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(r) {
				toks = append(toks, string(r[i:]))
				return toks
			}
			toks = append(toks, string(r[i:j+1]))
			i = j + 1
		default:
			j := i
			for j < len(r) && !unicode.IsSpace(r[j]) && !strings.ContainsRune("{}():,\"", r[j]) {
				j++
			}
			toks = append(toks, string(r[i:j]))
			i = j
		}
	}
	return toks
}

func isName(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		letter := c == '_' || unicode.IsLetter(c)
		if i > 0 {
			letter = letter || unicode.IsDigit(c)
		}
		if !letter {
			return false
		}
	}
	return true
}
