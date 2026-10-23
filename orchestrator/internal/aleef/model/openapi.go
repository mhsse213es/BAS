package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// objectIDName marks parameter names that look like object identifiers.
var objectIDName = regexp.MustCompile(`(?i)(^id$|_id$|Id$|ref$|number$)`)

var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

// methodOrder fixes the order in which a path's operations are emitted.
var methodOrder = []string{"get", "put", "post", "delete", "patch", "head", "options", "trace"}

// maxRefDepth bounds chains of $ref -> $ref so hostile documents cannot loop.
const maxRefDepth = 16

type rawDoc struct {
	OpenAPI    string                     `json:"openapi"`
	Paths      map[string]json.RawMessage `json:"paths"`
	Security   json.RawMessage            `json:"security"`
	Components struct {
		Schemas       map[string]json.RawMessage `json:"schemas"`
		Parameters    map[string]json.RawMessage `json:"parameters"`
		RequestBodies map[string]json.RawMessage `json:"requestBodies"`
	} `json:"components"`
}

type rawOp struct {
	OperationID string            `json:"operationId"`
	Parameters  []json.RawMessage `json:"parameters"`
	RequestBody json.RawMessage   `json:"requestBody"`
	Security    json.RawMessage   `json:"security"`
	Callbacks   json.RawMessage   `json:"callbacks"`
}

type rawParam struct {
	Ref      string          `json:"$ref"`
	Name     string          `json:"name"`
	In       string          `json:"in"`
	Required bool            `json:"required"`
	Schema   json.RawMessage `json:"schema"`
}

type rawBody struct {
	Ref     string `json:"$ref"`
	Content map[string]struct {
		Schema json.RawMessage `json:"schema"`
	} `json:"content"`
}

type rawSchema struct {
	Ref        string                     `json:"$ref"`
	Type       json.RawMessage            `json:"type"`
	Format     string                     `json:"format"`
	Enum       []any                      `json:"enum"`
	Nullable   bool                       `json:"nullable"`
	Pattern    string                     `json:"pattern"`
	Minimum    *float64                   `json:"minimum"`
	Maximum    *float64                   `json:"maximum"`
	MinLength  *int                       `json:"minLength"`
	MaxLength  *int                       `json:"maxLength"`
	Required   []string                   `json:"required"`
	Properties map[string]json.RawMessage `json:"properties"`
	Items      json.RawMessage            `json:"items"`
	AllOf      []json.RawMessage          `json:"allOf"`
	OneOf      []json.RawMessage          `json:"oneOf"`
	AnyOf      []json.RawMessage          `json:"anyOf"`
	Not        json.RawMessage            `json:"not"`
}

type importer struct {
	doc   rawDoc
	notes []string
	seen  map[string]bool
	ctx   string // "METHOD /path" of the operation being imported, for messages
}

func (im *importer) note(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	if im.ctx != "" {
		msg = im.ctx + ": " + msg
	}
	if im.seen[msg] {
		return
	}
	im.seen[msg] = true
	im.notes = append(im.notes, msg)
}

// Import turns a JSON OpenAPI 3.x document into a Model. It is deterministic
// (same input, same IDs and order), never panics, and records anything it cannot
// represent in Model.NotModelled rather than guessing. A document that is not
// JSON or not OpenAPI 3.x is an error.
func Import(doc []byte) (m Model, err error) {
	defer func() {
		if r := recover(); r != nil {
			m, err = Model{}, fmt.Errorf("openapi import: internal error: %v", r)
		}
	}()
	im := &importer{seen: map[string]bool{}}
	if err := json.Unmarshal(doc, &im.doc); err != nil {
		return Model{}, fmt.Errorf("openapi import: %w", err)
	}
	if !strings.HasPrefix(im.doc.OpenAPI, "3.") {
		return Model{}, errors.New("openapi import: not an OpenAPI 3.x document (missing or unsupported \"openapi\" field)")
	}

	var rootSec []string
	if len(im.doc.Security) > 0 {
		rootSec = im.securityNames(im.doc.Security)
	}

	paths := make([]string, 0, len(im.doc.Paths))
	for p := range im.doc.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	used := map[string]bool{}
	var ops []Operation
	for _, p := range paths {
		if strings.HasPrefix(p, "x-") {
			continue
		}
		ops = append(ops, im.importPath(p, im.doc.Paths[p], rootSec, used)...)
	}
	im.ctx = ""
	return Model{Operations: ops, NotModelled: im.notes}, nil
}

func (im *importer) importPath(path string, raw json.RawMessage, rootSec []string, used map[string]bool) []Operation {
	im.ctx = path
	var item map[string]json.RawMessage
	if err := json.Unmarshal(raw, &item); err != nil || item == nil {
		im.note("path item is not an object; skipped")
		return nil
	}
	if _, ok := item["$ref"]; ok {
		im.note("path item $ref not modelled; skipped")
		return nil
	}
	var pathParams []json.RawMessage
	if r, ok := item["parameters"]; ok {
		if err := json.Unmarshal(r, &pathParams); err != nil {
			im.note("path-level parameters malformed; ignored")
			pathParams = nil
		}
	}

	var out []Operation
	for _, method := range methodOrder {
		opRaw, ok := item[method]
		if !ok {
			continue
		}
		im.ctx = strings.ToUpper(method) + " " + path
		var op rawOp
		if err := json.Unmarshal(opRaw, &op); err != nil {
			im.note("operation is malformed; skipped")
			continue
		}
		if len(op.Callbacks) > 0 && string(op.Callbacks) != "null" {
			im.note("callbacks not modelled")
		}
		o := Operation{Method: strings.ToUpper(method), Path: path, Class: ClassUnknown}
		o.PathParams, o.QueryParams = im.importParams(path, pathParams, op.Parameters)
		o.Body = im.importBody(op.RequestBody)
		if len(op.Security) > 0 && string(op.Security) != "null" {
			o.Security = im.securityNames(op.Security)
		} else {
			o.Security = append([]string(nil), rootSec...)
		}
		o.ID = uniqueID(im, opID(op.OperationID, method, path), used)
		out = append(out, o)
	}
	return out
}

// uniqueID makes IDs unique deterministically (x, x_2, x_3 ...).
func uniqueID(im *importer, id string, used map[string]bool) string {
	final := id
	for n := 2; used[final]; n++ {
		final = fmt.Sprintf("%s_%d", id, n)
	}
	if final != id {
		im.note("duplicate operation id %q renamed to %q", id, final)
	}
	used[final] = true
	return final
}

// opID returns operationId, else a stable id from method+path, e.g.
// GET /items/{id} -> get_items_by_id.
func opID(explicit, method, path string) string {
	if explicit != "" {
		return explicit
	}
	parts := []string{strings.ToLower(method)}
	for _, seg := range strings.Split(path, "/") {
		if seg == "" {
			continue
		}
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			parts = append(parts, "by", sanitize(seg[1:len(seg)-1]))
		} else {
			parts = append(parts, sanitize(seg))
		}
	}
	if len(parts) == 1 {
		parts = append(parts, "root")
	}
	return strings.Join(parts, "_")
}

func sanitize(s string) string {
	return strings.Trim(nonAlnum.ReplaceAllString(strings.ToLower(s), "_"), "_")
}

func (im *importer) securityNames(raw json.RawMessage) []string {
	var reqs []map[string][]string
	if err := json.Unmarshal(raw, &reqs); err != nil {
		im.note("security requirement malformed; ignored")
		return nil
	}
	// Alternatives (OR) are flattened to the set of scheme names involved.
	set := map[string]bool{}
	for _, r := range reqs {
		for name := range r {
			set[name] = true
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// lookupRef resolves a "#/components/<kind>/<name>" reference. Anything else
// (external files, other sections, empty names) is reported and not resolved.
func (im *importer) lookupRef(ref, kind string) (json.RawMessage, string, bool) {
	prefix := "#/components/" + kind + "/"
	if !strings.HasPrefix(ref, prefix) {
		im.note("$ref %q not resolvable (only %s... is supported)", ref, prefix)
		return nil, "", false
	}
	name := strings.NewReplacer("~1", "/", "~0", "~").Replace(strings.TrimPrefix(ref, prefix))
	var table map[string]json.RawMessage
	switch kind {
	case "schemas":
		table = im.doc.Components.Schemas
	case "parameters":
		table = im.doc.Components.Parameters
	case "requestBodies":
		table = im.doc.Components.RequestBodies
	}
	raw, ok := table[name]
	if name == "" || !ok {
		im.note("$ref %q not found", ref)
		return nil, "", false
	}
	return raw, name, true
}

func (im *importer) importParams(path string, pathLevel, opLevel []json.RawMessage) (pp, qp []Param) {
	type key struct{ name, in string }
	var order []key
	byKey := map[key]Param{}
	add := func(list []json.RawMessage) {
		for _, raw := range list {
			p, ok := im.resolveParam(raw)
			if !ok {
				continue
			}
			k := key{p.Name, p.In}
			if _, dup := byKey[k]; !dup {
				order = append(order, k)
			}
			byKey[k] = p // operation level overrides path level
		}
	}
	add(pathLevel)
	add(opLevel)

	segs := strings.Split(path, "/")
	for _, k := range order {
		p := byKey[k]
		switch p.In {
		case "path":
			p.Required = true
			p.Resource = precedingCollection(segs, p.Name)
			p.IsObjectID = objectIDName.MatchString(p.Name) || p.Resource != ""
			pp = append(pp, p)
		case "query":
			p.IsObjectID = objectIDName.MatchString(p.Name)
			qp = append(qp, p)
		default:
			im.note("%s parameter %q not modelled", p.In, p.Name)
		}
	}
	// Order path params by their position in the template; undeclared ones
	// stay out (never guessed), declared-but-absent ones go last.
	pos := func(p Param) int {
		i := strings.Index(path, "{"+p.Name+"}")
		if i < 0 {
			return len(path) + 1
		}
		return i
	}
	sort.SliceStable(pp, func(i, j int) bool { return pos(pp[i]) < pos(pp[j]) })
	for _, p := range pp {
		if !strings.Contains(path, "{"+p.Name+"}") {
			im.note("path parameter %q is not in the path template", p.Name)
		}
	}
	return pp, qp
}

// precedingCollection returns the literal path segment right before {name},
// i.e. the collection the identifier selects from ("" if none).
func precedingCollection(segs []string, name string) string {
	for i, s := range segs {
		if s == "{"+name+"}" && i > 0 {
			prev := segs[i-1]
			if prev != "" && !strings.HasPrefix(prev, "{") {
				return prev
			}
		}
	}
	return ""
}

func (im *importer) resolveParam(raw json.RawMessage) (Param, bool) {
	for depth := 0; depth < maxRefDepth; depth++ {
		var rp rawParam
		if err := json.Unmarshal(raw, &rp); err != nil {
			im.note("parameter malformed; skipped")
			return Param{}, false
		}
		if rp.Ref != "" {
			r, _, ok := im.lookupRef(rp.Ref, "parameters")
			if !ok {
				return Param{}, false
			}
			raw = r
			continue
		}
		if rp.Name == "" || rp.In == "" {
			im.note("parameter without name or location skipped")
			return Param{}, false
		}
		p := Param{Name: rp.Name, In: rp.In, Required: rp.Required}
		if len(rp.Schema) > 0 {
			p.Schema = im.schema(rp.Schema, nil)
		}
		return p, true
	}
	im.note("parameter $ref chain too deep; skipped")
	return Param{}, false
}

func (im *importer) importBody(raw json.RawMessage) *Schema {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	for depth := 0; depth < maxRefDepth; depth++ {
		var rb rawBody
		if err := json.Unmarshal(raw, &rb); err != nil {
			im.note("requestBody malformed; not modelled")
			return nil
		}
		if rb.Ref != "" {
			r, _, ok := im.lookupRef(rb.Ref, "requestBodies")
			if !ok {
				return nil
			}
			raw = r
			continue
		}
		types := make([]string, 0, len(rb.Content))
		for ct := range rb.Content {
			types = append(types, ct)
		}
		sort.Strings(types)
		for _, ct := range types {
			base := strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
			if base == "application/json" || strings.HasSuffix(base, "+json") {
				if len(rb.Content[ct].Schema) == 0 {
					im.note("JSON request body has no schema")
					return nil
				}
				return im.schema(rb.Content[ct].Schema, nil)
			}
		}
		if len(types) > 0 {
			im.note("request body content types not modelled: %s", strings.Join(types, ", "))
		}
		return nil
	}
	im.note("requestBody $ref chain too deep; not modelled")
	return nil
}

// schema converts a JSON Schema node. It returns nil (after recording why) when
// the node cannot be represented faithfully. stack holds the schema names being
// expanded, to cut recursive references.
func (im *importer) schema(raw json.RawMessage, stack []string) *Schema {
	var rs rawSchema
	if err := json.Unmarshal(raw, &rs); err != nil {
		im.note("schema malformed; not modelled")
		return nil
	}
	if rs.Ref != "" {
		target, name, ok := im.lookupRef(rs.Ref, "schemas")
		if !ok {
			return nil
		}
		for _, s := range stack {
			if s == name {
				im.note("recursive $ref %q cut; not modelled", rs.Ref)
				return nil
			}
		}
		return im.schema(target, append(append([]string(nil), stack...), name))
	}
	if len(rs.Not) > 0 && string(rs.Not) != "null" {
		im.note("schema keyword \"not\" not modelled")
		return nil
	}

	s := &Schema{
		Format: rs.Format, Enum: rs.Enum, Nullable: rs.Nullable, Pattern: rs.Pattern,
		Minimum: rs.Minimum, Maximum: rs.Maximum, MinLength: rs.MinLength, MaxLength: rs.MaxLength,
		Required: append([]string(nil), rs.Required...),
	}
	if !im.schemaType(rs.Type, s) {
		return nil
	}
	if len(rs.Properties) > 0 {
		s.Properties = map[string]*Schema{}
		names := make([]string, 0, len(rs.Properties))
		for n := range rs.Properties {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if ps := im.schema(rs.Properties[n], stack); ps != nil {
				s.Properties[n] = ps
			} else {
				im.note("property %q dropped from schema", n)
			}
		}
	}
	if len(rs.Items) > 0 && string(rs.Items) != "null" {
		s.Items = im.schema(rs.Items, stack)
		if s.Items == nil {
			im.note("array items not modelled")
		}
	}

	for _, part := range rs.AllOf {
		ps := im.schema(part, stack)
		if ps == nil {
			im.note("allOf member not modelled; whole schema not modelled")
			return nil
		}
		if !mergeInto(s, ps) {
			im.note("allOf members conflict (type); whole schema not modelled")
			return nil
		}
	}
	for _, alt := range []struct {
		name  string
		parts []json.RawMessage
	}{{"oneOf", rs.OneOf}, {"anyOf", rs.AnyOf}} {
		switch len(alt.parts) {
		case 0:
		case 1:
			ps := im.schema(alt.parts[0], stack)
			if ps == nil || !mergeInto(s, ps) {
				return nil
			}
		default:
			im.note("%s with %d alternatives cannot be flattened; not modelled", alt.name, len(alt.parts))
			return nil
		}
	}
	return s
}

// schemaType reads "type", which is a string in 3.0 and may be an array in 3.1.
func (im *importer) schemaType(raw json.RawMessage, s *Schema) bool {
	if len(raw) == 0 || string(raw) == "null" {
		return true
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		s.Type = one
		return true
	}
	var many []string
	if json.Unmarshal(raw, &many) != nil {
		im.note("schema type malformed; not modelled")
		return false
	}
	var concrete []string
	for _, t := range many {
		if t == "null" {
			s.Nullable = true
		} else {
			concrete = append(concrete, t)
		}
	}
	if len(concrete) > 1 {
		im.note("multi-type schema %v not modelled", many)
		return false
	}
	if len(concrete) == 1 {
		s.Type = concrete[0]
	}
	return true
}

// mergeInto folds src into dst (allOf semantics). It fails on a type conflict.
func mergeInto(dst, src *Schema) bool {
	if src.Type != "" {
		if dst.Type != "" && dst.Type != src.Type {
			return false
		}
		dst.Type = src.Type
	}
	if dst.Format == "" {
		dst.Format = src.Format
	}
	if dst.Items == nil {
		dst.Items = src.Items
	}
	if dst.Pattern == "" {
		dst.Pattern = src.Pattern
	}
	if dst.Enum == nil {
		dst.Enum = src.Enum
	}
	if dst.Minimum == nil {
		dst.Minimum = src.Minimum
	}
	if dst.Maximum == nil {
		dst.Maximum = src.Maximum
	}
	if dst.MinLength == nil {
		dst.MinLength = src.MinLength
	}
	if dst.MaxLength == nil {
		dst.MaxLength = src.MaxLength
	}
	dst.Nullable = dst.Nullable || src.Nullable
	for n, p := range src.Properties {
		if dst.Properties == nil {
			dst.Properties = map[string]*Schema{}
		}
		if _, exists := dst.Properties[n]; !exists {
			dst.Properties[n] = p
		}
	}
	have := map[string]bool{}
	for _, r := range dst.Required {
		have[r] = true
	}
	for _, r := range src.Required {
		if !have[r] {
			dst.Required = append(dst.Required, r)
		}
	}
	return true
}
