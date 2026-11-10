package openapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// GraphQL schema import. A GraphQL API has one HTTP endpoint, so its operations are the root fields of the Query, Mutation and
// Subscription types. Each root field becomes one inventory operation: Method is QUERY, MUTATION or SUBSCRIPTION, Path is the
// endpoint (the default is /graphql, because a schema does not say where it is served), and Field is the root field. Arguments
// are recorded by name as BodyFields, because they travel in the POST body. The importer only reads a schema document (SDL or
// an introspection result); it never contacts an API.
//
// These operations are inventoried and classified. They are not bound to test data or run: the binding step refuses a method
// it cannot restore, and says so.

// DefaultGraphQLPath is the endpoint recorded for a GraphQL schema, which does not declare where it is served.
const DefaultGraphQLPath = "/graphql"

const (
	maxGraphQLTokens = 1_000_000
	maxGraphQLTypes  = 20000
	maxGraphQLFields = 200000
)

// graphQLKinds are the root operation types in the order they are reported.
var graphQLKinds = []string{"QUERY", "MUTATION", "SUBSCRIPTION"}

var authDirective = regexp.MustCompile(`(?i)^(auth|authenticated|requiresauth|requires_auth|isauthenticated|hasrole|has_role|requirerole|requires|secured|protected|private|authorize|authorized|permission|permissions)$`)

type gArg struct {
	Name     string
	Type     string // the named type with list and non-null wrappers removed
	List     bool   // the argument takes a list
	Required bool   // the outermost type is non-null
}

type gField struct {
	Name       string
	Desc       string
	Deprecated bool
	AuthDir    bool
	Args       []gArg
	Type       string
}

type gType struct {
	Kind    string // OBJECT, INTERFACE, INPUT_OBJECT, UNION, ENUM, SCALAR
	Fields  []gField
	Inputs  []gArg   // input object fields
	Members []string // union members
}

type gSchema struct {
	Types map[string]*gType
	Roots map[string]string // QUERY/MUTATION/SUBSCRIPTION -> type name
}

// looksLikeGraphQL says whether a document is a GraphQL schema rather than an OpenAPI or Swagger document.
func looksLikeGraphQL(data []byte) bool {
	t := strings.TrimSpace(string(data))
	if strings.HasPrefix(t, "{") {
		return strings.Contains(t, `"__schema"`)
	}
	return sdlRoot.MatchString(t)
}

var sdlRoot = regexp.MustCompile(`(?m)^\s*(schema\s*(@\w+(\([^)]*\))?\s*)*\{|(extend\s+)?type\s+(Query|Mutation|Subscription)\b)`)

// importGraphQL reads a schema document (SDL or introspection JSON) into an inventory.
func importGraphQL(data []byte) (*Inventory, error) {
	var s *gSchema
	var err error
	if strings.HasPrefix(strings.TrimSpace(string(data)), "{") {
		s, err = parseIntrospection(data)
	} else {
		s, err = parseSDL(string(data))
	}
	if err != nil {
		return nil, err
	}
	inv := &Inventory{OpenAPIVersion: "graphql", Title: "GraphQL schema", Servers: nil}
	r := &gWalker{s: s}
	for _, kind := range graphQLKinds {
		tn := s.Roots[kind]
		t := s.Types[tn]
		if tn == "" || t == nil {
			continue
		}
		fields := append([]gField(nil), t.Fields...)
		sort.Slice(fields, func(i, j int) bool { return fields[i].Name < fields[j].Name })
		seen := map[string]bool{}
		for _, f := range fields {
			// A root field declared twice (a repeated extend, or a malformed schema) is one operation.
			if strings.HasPrefix(f.Name, "__") || seen[f.Name] {
				continue
			}
			seen[f.Name] = true
			if len(inv.Operations) >= MaxOperations {
				return nil, fmt.Errorf("graphql: more than %d operations; refusing to import", MaxOperations)
			}
			inv.Operations = append(inv.Operations, r.operation(kind, f))
		}
	}
	if len(inv.Operations) == 0 {
		return nil, errors.New("graphql: the schema declares no query, mutation or subscription fields")
	}
	inv.Warnings = append(inv.Warnings,
		"a GraphQL schema does not say where it is served; operations are recorded under "+DefaultGraphQLPath,
		"a GraphQL schema does not declare authentication per field; authentication is unspecified unless a field carries an auth-like directive",
		"only GraphQL queries can be bound to test data; mutations and subscriptions are inventoried and classified only")
	inv.Warnings = append(inv.Warnings, r.warnings...)
	classifyGraphQL(inv)
	return inv, nil
}

type gWalker struct {
	s        *gSchema
	nodes    int
	warnings []string
	warned   bool
}

func (w *gWalker) operation(kind string, f gField) Operation {
	o := Operation{Method: kind, Path: DefaultGraphQLPath, Field: f.Name, OperationID: f.Name, Deprecated: f.Deprecated, Auth: AuthUnspecified}
	o.Summary = truncate(strings.TrimSpace(f.Desc), 200)
	if f.AuthDir {
		o.Auth = AuthRequired
	}
	o.BodyContentTypes = []string{"application/json"}
	o.Returns = f.Type
	o.ReturnsComposite = w.composite(f.Type)
	o.ReturnsUnion = w.kindOf(f.Type) == "UNION"
	for _, a := range f.Args {
		o.Args = append(o.Args, OpArg{Name: a.Name, Type: a.Type, Kind: w.kindOf(a.Type), List: a.List, Required: a.Required})
		o.BodyFields = append(o.BodyFields, a.Name)
		// The fields of an input object argument are body fields too, so a mutable field is seen inside an input.
		o.BodyFields = append(o.BodyFields, w.inputFields(a.Type, 0)...)
	}
	o.ResponseFields = w.responseFields(f.Type, 0)
	o.BodyFields = uniqSorted(o.BodyFields)
	o.ResponseFields = uniqSorted(o.ResponseFields)
	return o
}

// kindOf is what a named type is. The built-in scalars are not declared in a schema document, so they are known by name.
func (w *gWalker) kindOf(name string) string {
	switch name {
	case "ID", "String", "Int", "Float", "Boolean":
		return "SCALAR"
	}
	if t := w.s.Types[name]; t != nil && t.Kind != "" {
		return t.Kind
	}
	return "UNKNOWN"
}

// composite says whether a type has fields to select (an object, interface or union), so a query on it needs a selection.
func (w *gWalker) composite(name string) bool {
	switch w.kindOf(name) {
	case "OBJECT", "INTERFACE", "UNION":
		return true
	}
	return false
}

func (w *gWalker) inputFields(typeName string, depth int) []string {
	t := w.s.Types[typeName]
	if t == nil || t.Kind != "INPUT_OBJECT" || depth > maxSchemaDepth || !w.count() {
		return nil
	}
	var out []string
	for _, in := range t.Inputs {
		out = append(out, in.Name)
		out = append(out, w.inputFields(in.Type, depth+1)...)
	}
	return out
}

func (w *gWalker) responseFields(typeName string, depth int) []string {
	t := w.s.Types[typeName]
	if t == nil || depth > maxSchemaDepth || !w.count() {
		return nil
	}
	var out []string
	for _, f := range t.Fields {
		out = append(out, f.Name)
		out = append(out, w.responseFields(f.Type, depth+1)...)
	}
	for _, m := range t.Members {
		out = append(out, w.responseFields(m, depth+1)...)
	}
	return out
}

func (w *gWalker) count() bool {
	w.nodes++
	if w.nodes > maxSchemaNodes {
		if !w.warned {
			w.warned = true
			w.warnings = append(w.warnings, "the schema is too large to expand fully; some field names were not read")
		}
		return false
	}
	return true
}

// classifyGraphQL assigns candidate classes. The rules are the same name heuristics as for REST, applied to arguments (which
// are the request's identifiers and body) and to the fields a response can return.
func classifyGraphQL(inv *Inventory) {
	for i := range inv.Operations {
		o := &inv.Operations[i]
		var cs []Class
		add := func(c Class) { cs = append(cs, c) }
		for _, a := range o.BodyFields {
			if idParam.MatchString(a) {
				add(ClassObjectLevel)
				break
			}
		}
		if privSegment.MatchString(o.Field) || privateName(o.Field) {
			add(ClassFunctionLevel)
		}
		if o.Method == "MUTATION" {
			for _, f := range o.BodyFields {
				if mutableField.MatchString(f) {
					add(ClassPropertyLevel)
					break
				}
			}
		}
		for _, f := range o.ResponseFields {
			if sensitive.MatchString(f) {
				add(ClassDataExposure)
				break
			}
		}
		if o.Method == "QUERY" {
			for _, a := range o.BodyFields {
				if pagingParam.MatchString(a) {
					add(ClassResource)
					break
				}
			}
		}
		if hasDestination(o) {
			add(ClassSSRF)
		}
		if o.Deprecated {
			add(ClassLifecycle)
		}
		o.Classes = dedupeClasses(cs)
	}
}

// privateName flags a camelCase or snake_case field such as adminDeleteUser or approve_loan by a privileged word.
func privateName(name string) bool {
	for _, part := range splitWords(name) {
		if privSegment.MatchString(part) {
			return true
		}
	}
	return false
}

func splitWords(name string) []string {
	var parts []string
	cur := []rune{}
	flush := func() {
		if len(cur) > 0 {
			parts = append(parts, string(cur))
			cur = cur[:0]
		}
	}
	for i, r := range name {
		switch {
		case r == '_' || r == '-':
			flush()
		case r >= 'A' && r <= 'Z' && i > 0:
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return parts
}

// ---------------------------------------------------------------- introspection

type introRef struct {
	Kind   string    `json:"kind"`
	Name   string    `json:"name"`
	OfType *introRef `json:"ofType"`
}

// info is the named type with wrappers removed, whether the argument is a list, and whether the outermost wrapper is non-null.
func (r *introRef) info() (name string, list, required bool) {
	if r != nil && r.Kind == "NON_NULL" {
		required = true
	}
	for i := 0; r != nil && i < 16; i++ {
		if r.Kind == "LIST" {
			list = true
		}
		if r.Name != "" {
			return r.Name, list, required
		}
		r = r.OfType
	}
	return "", list, required
}

func (r *introRef) base() string {
	for i := 0; r != nil && i < 16; i++ {
		if r.Name != "" {
			return r.Name
		}
		r = r.OfType
	}
	return ""
}

type introInput struct {
	Name string    `json:"name"`
	Type *introRef `json:"type"`
}

type introField struct {
	Name         string       `json:"name"`
	Description  string       `json:"description"`
	IsDeprecated bool         `json:"isDeprecated"`
	Args         []introInput `json:"args"`
	Type         *introRef    `json:"type"`
}

type introType struct {
	Kind          string       `json:"kind"`
	Name          string       `json:"name"`
	Fields        []introField `json:"fields"`
	InputFields   []introInput `json:"inputFields"`
	PossibleTypes []introRef   `json:"possibleTypes"`
}

type introSchema struct {
	QueryType        *introRef   `json:"queryType"`
	MutationType     *introRef   `json:"mutationType"`
	SubscriptionType *introRef   `json:"subscriptionType"`
	Types            []introType `json:"types"`
}

func parseIntrospection(data []byte) (*gSchema, error) {
	var doc struct {
		Schema *introSchema `json:"__schema"`
		Data   *struct {
			Schema *introSchema `json:"__schema"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("graphql: the introspection result is not valid JSON: %w", err)
	}
	is := doc.Schema
	if is == nil && doc.Data != nil {
		is = doc.Data.Schema
	}
	if is == nil || len(is.Types) == 0 {
		return nil, errors.New("graphql: the introspection result has no __schema types")
	}
	if len(is.Types) > maxGraphQLTypes {
		return nil, fmt.Errorf("graphql: more than %d types; refusing to import", maxGraphQLTypes)
	}
	s := &gSchema{Types: map[string]*gType{}, Roots: map[string]string{}}
	for kind, ref := range map[string]*introRef{"QUERY": is.QueryType, "MUTATION": is.MutationType, "SUBSCRIPTION": is.SubscriptionType} {
		if ref != nil && ref.Name != "" {
			s.Roots[kind] = ref.Name
		}
	}
	fields := 0
	for _, t := range is.Types {
		if t.Name == "" || strings.HasPrefix(t.Name, "__") {
			continue
		}
		gt := &gType{Kind: t.Kind}
		for _, f := range t.Fields {
			fields++
			if fields > maxGraphQLFields {
				return nil, fmt.Errorf("graphql: more than %d fields; refusing to import", maxGraphQLFields)
			}
			g := gField{Name: f.Name, Desc: f.Description, Deprecated: f.IsDeprecated, Type: f.Type.base()}
			for _, a := range f.Args {
				n, list, req := a.Type.info()
				g.Args = append(g.Args, gArg{Name: a.Name, Type: n, List: list, Required: req})
			}
			gt.Fields = append(gt.Fields, g)
		}
		for _, in := range t.InputFields {
			gt.Inputs = append(gt.Inputs, gArg{Name: in.Name, Type: in.Type.base()})
		}
		for _, p := range t.PossibleTypes {
			if p.Name != "" {
				gt.Members = append(gt.Members, p.Name)
			}
		}
		if t.Kind != "UNION" {
			gt.Members = nil
		}
		s.Types[t.Name] = gt
	}
	return s, nil
}

// ---------------------------------------------------------------- SDL

type tokKind int

const (
	tEOF tokKind = iota
	tName
	tPunct
	tString
	tOther
)

type token struct {
	kind tokKind
	text string
	line int
}

func lexSDL(src string) ([]token, error) {
	var toks []token
	line := 1
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == '\n':
			line++
			i++
		case c == ' ' || c == '\t' || c == '\r' || c == ',' || c == 0xEF || c == 0xBB || c == 0xBF:
			i++
		case c == '#':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '"':
			start := line
			if strings.HasPrefix(src[i:], `"""`) {
				end := -1
				for k := i + 3; k+3 <= len(src); k++ {
					if src[k] == 92 && strings.HasPrefix(src[k+1:], `"""`) { // 92 is a backslash
						k += 3
						continue
					}
					if strings.HasPrefix(src[k:], `"""`) {
						end = k - (i + 3)
						break
					}
				}
				if end < 0 {
					return nil, fmt.Errorf("graphql: line %d: a block string is not closed", start)
				}
				body := src[i+3 : i+3+end]
				line += strings.Count(body, "\n")
				toks = append(toks, token{tString, body, start})
				i += 3 + end + 3
			} else {
				j := i + 1
				for j < len(src) && src[j] != '"' {
					if src[j] == '\\' {
						j++
					}
					if j < len(src) && src[j] == '\n' {
						return nil, fmt.Errorf("graphql: line %d: a string is not closed", start)
					}
					j++
				}
				if j >= len(src) {
					return nil, fmt.Errorf("graphql: line %d: a string is not closed", start)
				}
				toks = append(toks, token{tString, src[i+1 : j], start})
				i = j + 1
			}
		case isNameStart(c):
			j := i + 1
			for j < len(src) && isNameChar(src[j]) {
				j++
			}
			toks = append(toks, token{tName, src[i:j], line})
			i = j
		case strings.IndexByte("!$&()[]{}:=@|", c) >= 0:
			toks = append(toks, token{tPunct, string(c), line})
			i++
		case strings.HasPrefix(src[i:], "..."):
			toks = append(toks, token{tPunct, "...", line})
			i += 3
		case c == '-' || (c >= '0' && c <= '9'):
			j := i + 1
			for j < len(src) && (isNameChar(src[j]) || src[j] == '.' || src[j] == '-' || src[j] == '+') {
				j++
			}
			toks = append(toks, token{tOther, src[i:j], line})
			i = j
		default:
			return nil, fmt.Errorf("graphql: line %d: unexpected character %q", line, string(rune(c)))
		}
		if len(toks) > maxGraphQLTokens {
			return nil, fmt.Errorf("graphql: more than %d tokens; refusing to import", maxGraphQLTokens)
		}
	}
	return toks, nil
}

func isNameStart(c byte) bool { return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isNameChar(c byte) bool  { return isNameStart(c) || (c >= '0' && c <= '9') }

type sdlParser struct {
	toks   []token
	pos    int
	schema *gSchema
	fields int
}

func (p *sdlParser) peek() token {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return token{kind: tEOF, line: p.lastLine()}
}

func (p *sdlParser) lastLine() int {
	if len(p.toks) == 0 {
		return 1
	}
	return p.toks[len(p.toks)-1].line
}

func (p *sdlParser) next() token { t := p.peek(); p.pos++; return t }

func (p *sdlParser) isPunct(s string) bool {
	t := p.peek()
	return t.kind == tPunct && t.text == s
}

func (p *sdlParser) isName(s string) bool {
	t := p.peek()
	return t.kind == tName && t.text == s
}

func (p *sdlParser) errf(format string, a ...any) error {
	return fmt.Errorf("graphql: line %d: %s", p.peek().line, fmt.Sprintf(format, a...))
}

func (p *sdlParser) expectPunct(s string) error {
	if !p.isPunct(s) {
		return p.errf("expected %q", s)
	}
	p.pos++
	return nil
}

func (p *sdlParser) name() (string, error) {
	t := p.peek()
	if t.kind != tName {
		return "", p.errf("expected a name")
	}
	p.pos++
	return t.text, nil
}

// skipBalanced consumes a bracketed group starting at the opening token.
func (p *sdlParser) skipBalanced(open, closeP string) error {
	if err := p.expectPunct(open); err != nil {
		return err
	}
	depth := 1
	for depth > 0 {
		t := p.next()
		switch {
		case t.kind == tEOF:
			return p.errf("a %q is not closed", open)
		case t.kind == tPunct && t.text == open:
			depth++
		case t.kind == tPunct && t.text == closeP:
			depth--
		}
	}
	return nil
}

// directives consumes any @directive(args) group and reports whether one looks like an authorization directive or @deprecated.
func (p *sdlParser) directives() (deprecated, auth bool, err error) {
	for p.isPunct("@") {
		p.pos++
		n, e := p.name()
		if e != nil {
			return false, false, e
		}
		if n == "deprecated" {
			deprecated = true
		}
		if authDirective.MatchString(n) {
			auth = true
		}
		if p.isPunct("(") {
			if e := p.skipBalanced("(", ")"); e != nil {
				return false, false, e
			}
		}
	}
	return deprecated, auth, nil
}

// typeRef consumes a type reference and returns the named type with wrappers removed.
func (p *sdlParser) typeRef() (string, error) {
	n, _, _, err := p.typeRefInfo()
	return n, err
}

// typeRefInfo consumes a type reference and returns the named type, whether it is a list, and whether the outermost type is non-null.
func (p *sdlParser) typeRefInfo() (name string, list, required bool, err error) {
	if p.isPunct("[") {
		p.pos++
		inner, _, _, ierr := p.typeRefInfo()
		if ierr != nil {
			return "", false, false, ierr
		}
		if eerr := p.expectPunct("]"); eerr != nil {
			return "", false, false, eerr
		}
		name, list = inner, true
	} else {
		n, nerr := p.name()
		if nerr != nil {
			return "", false, false, nerr
		}
		name = n
	}
	if p.isPunct("!") {
		p.pos++
		required = true
	}
	return name, list, required, nil
}

// skipValue consumes a default value: a literal, a variable, or a bracketed list or object.
func (p *sdlParser) skipValue() error {
	switch {
	case p.isPunct("["):
		return p.skipBalanced("[", "]")
	case p.isPunct("{"):
		return p.skipBalanced("{", "}")
	case p.isPunct("$"):
		p.pos++
		_, err := p.name()
		return err
	default:
		t := p.next()
		if t.kind == tEOF || t.kind == tPunct {
			return p.errf("expected a value")
		}
		return nil
	}
}

func (p *sdlParser) description() string {
	if t := p.peek(); t.kind == tString {
		p.pos++
		return strings.TrimSpace(t.text)
	}
	return ""
}

func (p *sdlParser) argsDef() ([]gArg, error) {
	if err := p.expectPunct("("); err != nil {
		return nil, err
	}
	var args []gArg
	for !p.isPunct(")") {
		if p.peek().kind == tEOF {
			return nil, p.errf("an argument list is not closed")
		}
		p.description()
		n, err := p.name()
		if err != nil {
			return nil, err
		}
		if err := p.expectPunct(":"); err != nil {
			return nil, err
		}
		t, isList, isReq, err := p.typeRefInfo()
		if err != nil {
			return nil, err
		}
		hasDefault := false
		if p.isPunct("=") {
			p.pos++
			hasDefault = true
			if err := p.skipValue(); err != nil {
				return nil, err
			}
		}
		if _, _, err := p.directives(); err != nil {
			return nil, err
		}
		// An argument with a default does not have to be given, even when its type is non-null.
		args = append(args, gArg{Name: n, Type: t, List: isList, Required: isReq && !hasDefault})
	}
	p.pos++
	return args, nil
}

func (p *sdlParser) typeOf(name, kind string) *gType {
	t := p.schema.Types[name]
	if t == nil {
		t = &gType{Kind: kind}
		p.schema.Types[name] = t
	}
	return t
}

func (p *sdlParser) fieldsDef(t *gType, input bool) error {
	if err := p.expectPunct("{"); err != nil {
		return err
	}
	for !p.isPunct("}") {
		if p.peek().kind == tEOF {
			return p.errf("a field list is not closed")
		}
		desc := p.description()
		n, err := p.name()
		if err != nil {
			return err
		}
		var args []gArg
		if !input && p.isPunct("(") {
			if args, err = p.argsDef(); err != nil {
				return err
			}
		}
		if err := p.expectPunct(":"); err != nil {
			return err
		}
		ty, err := p.typeRef()
		if err != nil {
			return err
		}
		if input && p.isPunct("=") {
			p.pos++
			if err := p.skipValue(); err != nil {
				return err
			}
		}
		dep, auth, err := p.directives()
		if err != nil {
			return err
		}
		p.fields++
		if p.fields > maxGraphQLFields {
			return fmt.Errorf("graphql: more than %d fields; refusing to import", maxGraphQLFields)
		}
		if input {
			t.Inputs = append(t.Inputs, gArg{Name: n, Type: ty})
		} else {
			t.Fields = append(t.Fields, gField{Name: n, Desc: desc, Deprecated: dep, AuthDir: auth, Args: args, Type: ty})
		}
	}
	p.pos++
	return nil
}

func (p *sdlParser) definition() error {
	p.description()
	extend := false
	if p.isName("extend") {
		extend = true
		p.pos++
	}
	kw, err := p.name()
	if err != nil {
		return err
	}
	switch kw {
	case "schema":
		if _, _, err := p.directives(); err != nil {
			return err
		}
		if !p.isPunct("{") {
			return nil
		}
		p.pos++
		for !p.isPunct("}") {
			if p.peek().kind == tEOF {
				return p.errf("the schema block is not closed")
			}
			op, err := p.name()
			if err != nil {
				return err
			}
			if err := p.expectPunct(":"); err != nil {
				return err
			}
			tn, err := p.name()
			if err != nil {
				return err
			}
			switch op {
			case "query":
				p.schema.Roots["QUERY"] = tn
			case "mutation":
				p.schema.Roots["MUTATION"] = tn
			case "subscription":
				p.schema.Roots["SUBSCRIPTION"] = tn
			}
		}
		p.pos++
	case "scalar":
		n, err := p.name()
		if err != nil {
			return err
		}
		p.typeOf(n, "SCALAR")
		_, _, err = p.directives()
		return err
	case "type", "interface", "input":
		n, err := p.name()
		if err != nil {
			return err
		}
		kind := map[string]string{"type": "OBJECT", "interface": "INTERFACE", "input": "INPUT_OBJECT"}[kw]
		if len(p.schema.Types) >= maxGraphQLTypes {
			return fmt.Errorf("graphql: more than %d types; refusing to import", maxGraphQLTypes)
		}
		t := p.typeOf(n, kind)
		if p.isName("implements") {
			p.pos++
			if p.isPunct("&") {
				p.pos++
			}
			if _, err := p.name(); err != nil {
				return err
			}
			for p.isPunct("&") {
				p.pos++
				if _, err := p.name(); err != nil {
					return err
				}
			}
		}
		if _, _, err := p.directives(); err != nil {
			return err
		}
		if p.isPunct("{") {
			return p.fieldsDef(t, kw == "input")
		}
	case "enum":
		n, err := p.name()
		if err != nil {
			return err
		}
		p.typeOf(n, "ENUM")
		if _, _, err := p.directives(); err != nil {
			return err
		}
		if p.isPunct("{") {
			return p.skipBalanced("{", "}")
		}
	case "union":
		n, err := p.name()
		if err != nil {
			return err
		}
		t := p.typeOf(n, "UNION")
		if _, _, err := p.directives(); err != nil {
			return err
		}
		if p.isPunct("=") {
			p.pos++
			if p.isPunct("|") {
				p.pos++
			}
			for {
				m, err := p.name()
				if err != nil {
					return err
				}
				t.Members = append(t.Members, m)
				if !p.isPunct("|") {
					break
				}
				p.pos++
			}
		}
	case "directive":
		if err := p.expectPunct("@"); err != nil {
			return err
		}
		if _, err := p.name(); err != nil {
			return err
		}
		if p.isPunct("(") {
			if err := p.skipBalanced("(", ")"); err != nil {
				return err
			}
		}
		if p.isName("repeatable") {
			p.pos++
		}
		if !p.isName("on") {
			return p.errf("expected \"on\" in a directive definition")
		}
		p.pos++
		if p.isPunct("|") {
			p.pos++
		}
		for {
			if _, err := p.name(); err != nil {
				return err
			}
			if !p.isPunct("|") {
				break
			}
			p.pos++
		}
	default:
		_ = extend
		return p.errf("unexpected %q; expected a type system definition", kw)
	}
	return nil
}

func parseSDL(src string) (*gSchema, error) {
	toks, err := lexSDL(src)
	if err != nil {
		return nil, err
	}
	p := &sdlParser{toks: toks, schema: &gSchema{Types: map[string]*gType{}, Roots: map[string]string{}}}
	for p.peek().kind != tEOF {
		if err := p.definition(); err != nil {
			return nil, err
		}
	}
	// Without a schema block the roots are the conventional type names.
	for kind, def := range map[string]string{"QUERY": "Query", "MUTATION": "Mutation", "SUBSCRIPTION": "Subscription"} {
		if p.schema.Roots[kind] == "" && p.schema.Types[def] != nil {
			p.schema.Roots[kind] = def
		}
	}
	return p.schema, nil
}
