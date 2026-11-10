// Package openapi imports an OpenAPI 3, Swagger 2.0 or GraphQL schema document into an endpoint inventory for API BAS.
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
	Method           string   `json:"method"`
	Path             string   `json:"path"`
	Field            string   `json:"field,omitempty"` // GraphQL: the root field; Method is QUERY, MUTATION or SUBSCRIPTION
	OperationID      string   `json:"operation_id,omitempty"`
	Summary          string   `json:"summary,omitempty"`
	Tags             []string `json:"tags,omitempty"`
	Deprecated       bool     `json:"deprecated,omitempty"`
	Auth             AuthMode `json:"auth"`
	SecuritySchemes  []string `json:"security_schemes,omitempty"`
	PathParams       []string `json:"path_params,omitempty"`
	QueryParams      []string `json:"query_params,omitempty"`
	HeaderParams     []string `json:"header_params,omitempty"`
	BodyContentTypes []string `json:"body_content_types,omitempty"`
	BodyFields       []string `json:"body_fields,omitempty"`
	ResponseCodes    []string `json:"response_codes,omitempty"`
	ResponseFields   []string `json:"response_fields,omitempty"`
	Classes          []Class  `json:"classes,omitempty"`
}

// Key is "METHOD path", the identity of an operation. A GraphQL root field adds "#field", because every field shares one path.
func (o Operation) Key() string {
	if o.Field != "" {
		return o.Method + " " + o.Path + "#" + o.Field
	}
	return o.Method + " " + o.Path
}

// Inventory is the result of an import.
type Inventory struct {
	Title          string `json:"title"`
	Version        string `json:"version"`
	OpenAPIVersion string `json:"openapi_version"`
	// Servers are the server URLs as declared. They are recorded, never contacted.
	Servers    []string    `json:"servers,omitempty"`
	Operations []Operation `json:"operations"`
	Warnings   []string    `json:"warnings,omitempty"`
}

// Import parses an OpenAPI 3.x document, JSON or YAML, into an inventory.
func Import(data []byte) (*Inventory, error) {
	if len(data) == 0 {
		return nil, errors.New("openapi: the document is empty")
	}
	if len(data) > MaxDocumentBytes {
		return nil, fmt.Errorf("openapi: the document is %d bytes, over the %d byte limit", len(data), MaxDocumentBytes)
	}
	if looksLikeGraphQL(data) {
		return importGraphQL(data)
	}
	var root map[string]any
	if err := yaml.NewDecoder(bytes.NewReader(data)).Decode(&root); err != nil {
		return nil, fmt.Errorf("openapi: the document is not valid JSON or YAML: %w", err)
	}
	if root == nil {
		return nil, errors.New("openapi: the document has no content")
	}
	ver, _ := root["openapi"].(string)
	swagger := false
	if sv, isSwagger := root["swagger"]; isSwagger && ver == "" {
		// An unquoted 2.0 is read by YAML as the number 2.
		s := strings.TrimSpace(fmt.Sprint(sv))
		if s == "2" {
			s = "2.0"
		}
		if !strings.HasPrefix(s, "2.") {
			return nil, fmt.Errorf("openapi: unsupported swagger version %q; only Swagger 2.x and OpenAPI 3.x are supported", truncate(s, 24))
		}
		ver, swagger = s, true
	} else if !strings.HasPrefix(ver, "3.") {
		return nil, fmt.Errorf("openapi: unsupported or missing openapi version %q; only Swagger 2.x and OpenAPI 3.x are supported", truncate(ver, 24))
	}
	r := &resolver{root: root, swagger: swagger}
	for _, c := range asList(root["consumes"]) {
		if cs, ok := c.(string); ok {
			r.consumes = append(r.consumes, cs)
		}
	}
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
	// Swagger 2.0 has no servers: the base URL is its schemes, host and basePath, and every path is relative to basePath. The
	// inventory keeps full request paths, so the basePath is put in front of each one.
	prefix := ""
	if swagger {
		if bp, _ := root["basePath"].(string); bp != "" {
			if strings.HasPrefix(bp, "/") {
				prefix = strings.TrimRight(bp, "/")
			} else {
				inv.Warnings = append(inv.Warnings, fmt.Sprintf("basePath %q does not start with a slash and was ignored", truncate(bp, 40)))
			}
		}
		if host, _ := root["host"].(string); host != "" {
			schemes := []string{}
			for _, sc := range asList(root["schemes"]) {
				if v, ok := sc.(string); ok && (v == "http" || v == "https") {
					schemes = append(schemes, v)
				}
			}
			if len(schemes) == 0 {
				schemes = []string{"https"}
			}
			for _, sc := range schemes {
				inv.Servers = append(inv.Servers, sc+"://"+host+prefix)
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
			inv.Operations = append(inv.Operations, r.operation(strings.ToUpper(m), prefix+p, opRaw, shared, globalSec, globalSet))
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
	swagger  bool     // the document is Swagger 2.0
	consumes []string // the document-level consumes of a Swagger 2.0 document
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
	bodyDeclared, formDeclared := false, false
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
		case "body":
			// Swagger 2.0: the request body is a parameter whose schema is the body.
			o.BodyFields = append(o.BodyFields, r.schemaFields(p["schema"], 0)...)
			bodyDeclared = true
		case "formData":
			o.BodyFields = append(o.BodyFields, name)
			formDeclared = true
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
	if r.swagger && (bodyDeclared || formDeclared) {
		// The operation's consumes replaces the document's. With neither, a body is JSON and a form is url-encoded.
		cts := r.consumes
		if own := asList(op["consumes"]); len(own) > 0 || op["consumes"] != nil {
			cts = nil
			for _, c := range own {
				if cs, ok := c.(string); ok {
					cts = append(cts, cs)
				}
			}
		}
		if len(cts) == 0 {
			if bodyDeclared {
				cts = []string{"application/json"}
			} else {
				cts = []string{"application/x-www-form-urlencoded"}
			}
		}
		o.BodyContentTypes = append(o.BodyContentTypes, cts...)
		if formDeclared && !contains(cts, "multipart/form-data") && !contains(cts, "application/x-www-form-urlencoded") {
			// A file parameter makes the request multipart whatever the declaration says.
			o.BodyContentTypes = append(o.BodyContentTypes, "multipart/form-data")
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
				if r.swagger {
					o.ResponseFields = append(o.ResponseFields, r.schemaFields(rm["schema"], 0)...)
				}
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
	o.BodyContentTypes = uniqSorted(o.BodyContentTypes)
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
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
