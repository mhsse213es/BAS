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
	OperationID string                     `json:"operationId"`
	Parameters  []json.RawMessage          `json:"parameters"`
	RequestBody json.RawMessage            `json:"requestBody"`
	Security    json.RawMessage            `json:"security"`
	Callbacks   json.RawMessage            `json:"callbacks"`
	Responses   map[string]json.RawMessage `json:"responses"`
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

type importer struct {
	doc   rawDoc
	notes []string
	seen  map[string]bool
	ctx   string // "METHOD /path" of the operation being imported, for messages

	// Schema conversion state: each component schema is converted once.
	comp       map[string]*compResult
	nodes      int
	budgetNote bool
	depthNote  bool
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
	im := &importer{seen: map[string]bool{}, comp: map[string]*compResult{}}
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
	// Authorisation is keyed by signature (method + normalised path), never by the operation id the
	// document chose. An odd path, or two operations with one signature, makes the document ambiguous.
	bySig := map[string]string{}
	for _, op := range ops {
		sig, serr := Signature(op.Method, op.Path)
		if serr != nil {
			return Model{}, fmt.Errorf("openapi import: operation %q: %v", op.ID, serr)
		}
		if prev, dup := bySig[sig]; dup {
			return Model{}, fmt.Errorf("openapi import: operations %q and %q have the same signature %q", prev, op.ID, sig)
		}
		bySig[sig] = op.ID
	}
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

	im.checkPathItemKeys(path, item)
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
		for code := range op.Responses {
			o.Responses = append(o.Responses, code)
		}
		sort.Strings(o.Responses)
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
			p.ResourceType = paramResourceType(p.Name, p.Resource)
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
	declared := map[string]bool{}
	for _, p := range pp {
		declared[p.Name] = true
	}
	for _, m := range templateVar.FindAllStringSubmatch(path, -1) {
		if !declared[m[1]] {
			im.note("path template parameter %q has no declaration; not modelled", m[1])
		}
	}
	return pp, qp
}

var templateVar = regexp.MustCompile(`\{([^{}]*)\}`)

// checkPathItemKeys reports path-item keys that are neither supported methods
// nor known non-method fields, so GET, connect, query ... are not lost silently.
func (im *importer) checkPathItemKeys(path string, item map[string]json.RawMessage) {
	known := map[string]bool{"summary": true, "description": true, "parameters": true, "servers": true, "$ref": true}
	for _, m := range methodOrder {
		known[m] = true
	}
	keys := make([]string, 0, len(item))
	for k := range item {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if known[k] || strings.HasPrefix(k, "x-") {
			continue
		}
		im.note("path item key %q is not a supported method; not modelled", k)
	}
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
			p.Schema = im.schemaFromRaw(rp.Schema, "parameter "+rp.Name)
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
				return im.schemaFromRaw(rb.Content[ct].Schema, "requestBody")
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
