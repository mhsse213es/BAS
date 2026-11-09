// Package openapi imports an OpenAPI 3 document into an endpoint inventory for API BAS.
//
// The importer only reads the bytes it is given. It never fetches a remote $ref or a server URL, it follows local references
// (#/...) only, and it bounds document size, reference depth and operation count, because a specification is untrusted input.
// Example and default values are never copied into the inventory: it records names, types and shapes, not data, so a
// specification that carries a real secret in an example does not leak it through the inventory.
//
// The inventory classes are candidates for testing, chosen from the shape of the specification. They are not findings, and a
// class on an operation says nothing about whether the deployed API is vulnerable.
package openapi

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Limits on untrusted input.
const (
	MaxDocumentBytes = 8 << 20
	MaxOperations    = 5000
	maxRefDepth      = 32
	maxSchemaDepth   = 6
	// maxSchemaNodes bounds the schema nodes visited in one import. Depth alone does not stop a document whose schemas fan out
	// through shared references, which grows exponentially.
	maxSchemaNodes = 50000
)

// AuthMode is how an operation is secured according to the specification.
type AuthMode string

const (
	AuthRequired    AuthMode = "required"    // at least one security requirement applies and none is empty
	AuthNone        AuthMode = "none"        // the operation declares an empty security list: it is public
	AuthOptional    AuthMode = "optional"    // one alternative is the empty requirement, so authentication may be skipped
	AuthUnspecified AuthMode = "unspecified" // neither the operation nor the document declares security
)

// Operation is one method on one path.
type Operation struct {
	Method           string
	Path             string
	OperationID      string
	Summary          string
	Tags             []string
	Deprecated       bool
	Auth             AuthMode
	SecuritySchemes  []string
	PathParams       []string
	QueryParams      []string
	HeaderParams     []string
	BodyContentTypes []string
	BodyFields       []string
	ResponseCodes    []string
	ResponseFields   []string
	Classes          []Class
}

// Key is "METHOD path", the identity of an operation.
func (o Operation) Key() string { return o.Method + " " + o.Path }

// Inventory is the result of an import.
type Inventory struct {
	Title          string
	Version        string
	OpenAPIVersion string
	// Servers are the server URLs as declared. They are recorded, never contacted.
	Servers    []string
	Operations []Operation
	Warnings   []string
}

// Import parses an OpenAPI 3.x document, JSON or YAML, into an inventory.
func Import(data []byte) (*Inventory, error) {
	if len(data) == 0 {
		return nil, errors.New("openapi: the document is empty")
	}
	if len(data) > MaxDocumentBytes {
		return nil, fmt.Errorf("openapi: the document is %d bytes, over the %d byte limit", len(data), MaxDocumentBytes)
	}
	var root map[string]any
	if err := yaml.NewDecoder(bytes.NewReader(data)).Decode(&root); err != nil {
		return nil, fmt.Errorf("openapi: the document is not valid JSON or YAML: %w", err)
	}
	if root == nil {
		return nil, errors.New("openapi: the document has no content")
	}
	ver, _ := root["openapi"].(string)
	if _, isSwagger := root["swagger"]; isSwagger && ver == "" {
		return nil, errors.New("openapi: this is a Swagger 2.0 document; only OpenAPI 3.x is supported, convert it first")
	}
	if !strings.HasPrefix(ver, "3.") {
		return nil, fmt.Errorf("openapi: unsupported or missing openapi version %q; only 3.x is supported", ver)
	}
	r := &resolver{root: root}
	inv := &Inventory{OpenAPIVersion: ver}
	if info, ok := root["info"].(map[string]any); ok {
		inv.Title, _ = info["title"].(string)
		inv.Version, _ = info["version"].(string)
	}
	for _, s := range asList(root["servers"]) {
		if m, ok := s.(map[string]any); ok {
			if u, _ := m["url"].(string); u != "" {
				inv.Servers = append(inv.Servers, u)
			}
		}
	}
	paths, _ := root["paths"].(map[string]any)
	if len(paths) == 0 {
		return nil, errors.New("openapi: the document declares no paths")
	}
	globalSec, globalSet := root["security"]
	names := make([]string, 0, len(paths))
	for p := range paths {
		names = append(names, p)
	}
	sort.Strings(names)
	for _, p := range names {
		item := r.deref(paths[p])
		itemMap, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			inv.Warnings = append(inv.Warnings, fmt.Sprintf("path %q does not start with a slash and was skipped", p))
			continue
		}
		shared := asList(itemMap["parameters"])
		for _, m := range []string{"get", "put", "post", "delete", "patch", "options", "head"} {
			opRaw, ok := itemMap[m].(map[string]any)
			if !ok {
				continue
			}
			if len(inv.Operations) >= MaxOperations {
				return nil, fmt.Errorf("openapi: more than %d operations; refusing to import", MaxOperations)
			}
			inv.Operations = append(inv.Operations, r.operation(strings.ToUpper(m), p, opRaw, shared, globalSec, globalSet))
		}
	}
	if len(inv.Operations) == 0 {
		return nil, errors.New("openapi: the document declares paths but no operations")
	}
	inv.Warnings = append(inv.Warnings, r.warnings...)
	classify(inv)
	return inv, nil
}

type resolver struct {
	root     map[string]any
	warnings []string
	warned   map[string]bool
	nodes    int
}

func (r *resolver) warn(msg string) {
	if r.warned == nil {
		r.warned = map[string]bool{}
	}
	if !r.warned[msg] {
		r.warned[msg] = true
		r.warnings = append(r.warnings, msg)
	}
}

// deref follows local $ref chains. A remote reference is not followed and is reported once.
func (r *resolver) deref(v any) any {
	for i := 0; i < maxRefDepth; i++ {
		m, ok := v.(map[string]any)
		if !ok {
			return v
		}
		ref, ok := m["$ref"].(string)
		if !ok {
			return v
		}
		if !strings.HasPrefix(ref, "#/") {
			r.warn(fmt.Sprintf("reference %q is not local and was not followed", ref))
			return nil
		}
		cur := any(r.root)
		for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
			mm, ok := cur.(map[string]any)
			if !ok {
				r.warn(fmt.Sprintf("reference %q does not resolve", ref))
				return nil
			}
			cur = mm[part]
		}
		if cur == nil {
			r.warn(fmt.Sprintf("reference %q does not resolve", ref))
			return nil
		}
		v = cur
	}
	r.warn("a reference chain was longer than the limit and was cut")
	return nil
}

func (r *resolver) operation(method, path string, op map[string]any, shared []any, globalSec any, globalSet bool) Operation {
	o := Operation{Method: method, Path: path}
	o.OperationID, _ = op["operationId"].(string)
	o.Summary, _ = op["summary"].(string)
	o.Deprecated, _ = op["deprecated"].(bool)
	for _, t := range asList(op["tags"]) {
		if s, ok := t.(string); ok {
			o.Tags = append(o.Tags, s)
		}
	}
	// Parameters: operation-level overrides path-level by (in, name).
	seen := map[string]bool{}
	for _, raw := range append(asList(op["parameters"]), shared...) {
		p, ok := r.deref(raw).(map[string]any)
		if !ok {
			continue
		}
		name, _ := p["name"].(string)
		in, _ := p["in"].(string)
		if name == "" || seen[in+"/"+name] {
			continue
		}
		seen[in+"/"+name] = true
		switch in {
		case "path":
			o.PathParams = append(o.PathParams, name)
		case "query":
			o.QueryParams = append(o.QueryParams, name)
		case "header":
			o.HeaderParams = append(o.HeaderParams, name)
		}
	}
	// A path template parameter with no declaration is still a path parameter.
	for _, name := range templateParams(path) {
		if !contains(o.PathParams, name) {
			o.PathParams = append(o.PathParams, name)
		}
	}
	if body, ok := r.deref(op["requestBody"]).(map[string]any); ok {
		if content, ok := body["content"].(map[string]any); ok {
			for ct, mt := range content {
				o.BodyContentTypes = append(o.BodyContentTypes, ct)
				if m, ok := mt.(map[string]any); ok {
					o.BodyFields = append(o.BodyFields, r.schemaFields(m["schema"], 0)...)
				}
			}
		}
	}
	if resp, ok := op["responses"].(map[string]any); ok {
		for code, rv := range resp {
			o.ResponseCodes = append(o.ResponseCodes, code)
			if !strings.HasPrefix(code, "2") {
				continue
			}
			if rm, ok := r.deref(rv).(map[string]any); ok {
				if content, ok := rm["content"].(map[string]any); ok {
					for _, mt := range content {
						if m, ok := mt.(map[string]any); ok {
							o.ResponseFields = append(o.ResponseFields, r.schemaFields(m["schema"], 0)...)
						}
					}
				}
			}
		}
	}
	o.Auth, o.SecuritySchemes = security(op, globalSec, globalSet)
	sort.Strings(o.Tags)
	for _, s := range []*[]string{&o.PathParams, &o.QueryParams, &o.HeaderParams, &o.BodyContentTypes, &o.ResponseCodes} {
		sort.Strings(*s)
	}
	o.BodyFields = uniqSorted(o.BodyFields)
	o.ResponseFields = uniqSorted(o.ResponseFields)
	return o
}

// security resolves the effective authentication of an operation. An operation-level security key replaces the document's.
func security(op map[string]any, globalSec any, globalSet bool) (AuthMode, []string) {
	raw, set := op["security"]
	if !set {
		if !globalSet {
			return AuthUnspecified, nil
		}
		raw = globalSec
	}
	reqs := asList(raw)
	if len(reqs) == 0 {
		return AuthNone, nil
	}
	var schemes []string
	optional := false
	for _, rq := range reqs {
		m, ok := rq.(map[string]any)
		if !ok || len(m) == 0 {
			optional = true
			continue
		}
		for name := range m {
			schemes = append(schemes, name)
		}
	}
	schemes = uniqSorted(schemes)
	if optional {
		return AuthOptional, schemes
	}
	return AuthRequired, schemes
}

// schemaFields returns the property names a schema declares, to a bounded depth. Array items are followed and composition
// keywords are merged. Only names are kept.
func (r *resolver) schemaFields(v any, depth int) []string {
	if depth > maxSchemaDepth {
		return nil
	}
	r.nodes++
	if r.nodes > maxSchemaNodes {
		r.warn("the schemas are too large to expand fully; some field names were not read")
		return nil
	}
	s, ok := r.deref(v).(map[string]any)
	if !ok {
		return nil
	}
	var out []string
	if props, ok := s["properties"].(map[string]any); ok {
		for name, sub := range props {
			out = append(out, name)
			out = append(out, r.schemaFields(sub, depth+1)...)
		}
	}
	out = append(out, r.schemaFields(s["items"], depth+1)...)
	for _, k := range []string{"allOf", "oneOf", "anyOf"} {
		for _, sub := range asList(s[k]) {
			out = append(out, r.schemaFields(sub, depth+1)...)
		}
	}
	return out
}

func templateParams(path string) []string {
	var out []string
	for _, seg := range strings.Split(path, "/") {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") && len(seg) > 2 {
			out = append(out, seg[1:len(seg)-1])
		}
	}
	return out
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func uniqSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	m := map[string]bool{}
	for _, s := range in {
		m[s] = true
	}
	out := make([]string, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
