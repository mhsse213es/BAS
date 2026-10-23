package model

import (
	"encoding/json"
	"reflect"
	"sort"
)

// rawSchema is parsed once into a typed tree (no re-unmarshaling of nested raw
// JSON). Keywords the importer ignores are kept raw so their presence can be
// reported.
type rawSchema struct {
	Ref        string                `json:"$ref"`
	Type       json.RawMessage       `json:"type"`
	Format     string                `json:"format"`
	Enum       []any                 `json:"enum"`
	Nullable   bool                  `json:"nullable"`
	Pattern    string                `json:"pattern"`
	Minimum    *float64              `json:"minimum"`
	Maximum    *float64              `json:"maximum"`
	MinLength  *int                  `json:"minLength"`
	MaxLength  *int                  `json:"maxLength"`
	Required   []string              `json:"required"`
	Properties map[string]*rawSchema `json:"properties"`
	Items      *rawSchema            `json:"items"`
	AllOf      []*rawSchema          `json:"allOf"`
	OneOf      []*rawSchema          `json:"oneOf"`
	AnyOf      []*rawSchema          `json:"anyOf"`
	Not        json.RawMessage       `json:"not"`

	AdditionalProperties json.RawMessage `json:"additionalProperties"`
	Discriminator        json.RawMessage `json:"discriminator"`
	ReadOnly             json.RawMessage `json:"readOnly"`
	WriteOnly            json.RawMessage `json:"writeOnly"`
	Default              json.RawMessage `json:"default"`
}

type compResult struct {
	s          *Schema
	inProgress bool
}

// Limits that keep a small hostile document from costing unbounded work.
const (
	maxSchemaNodes = 20000
	maxSchemaDepth = 64
)

// schemaFromRaw parses a schema once and converts it. loc names where it sits.
func (im *importer) schemaFromRaw(raw json.RawMessage, loc string) *Schema {
	var rs rawSchema
	if err := json.Unmarshal(raw, &rs); err != nil {
		im.note("schema at %s malformed; not modelled", loc)
		return nil
	}
	return im.conv(&rs, loc, 0)
}

// component converts components/schemas/<name> once and memoizes the result, so
// a DAG of references costs linear work. A schema reached again while it is
// still being converted is a cycle and is cut. A component first reached from
// inside a cycle keeps its truncated form (deterministic, since order is fixed).
func (im *importer) component(name string, depth int) *Schema {
	if c, ok := im.comp[name]; ok {
		if c.inProgress {
			im.note("recursive $ref to schema %q cut; not modelled", name)
			return nil
		}
		return c.s
	}
	c := &compResult{inProgress: true}
	im.comp[name] = c
	saved := im.ctx
	im.ctx = ""
	loc := "components/schemas/" + name
	var rs rawSchema
	if err := json.Unmarshal(im.doc.Components.Schemas[name], &rs); err != nil {
		im.note("schema at %s malformed; not modelled", loc)
	} else {
		c.s = im.conv(&rs, loc, depth)
	}
	im.ctx = saved
	c.inProgress = false
	return c.s
}

func (im *importer) ignored(rs *rawSchema, loc string) {
	for _, k := range []struct {
		name string
		raw  json.RawMessage
	}{
		{"additionalProperties", rs.AdditionalProperties}, {"discriminator", rs.Discriminator},
		{"readOnly", rs.ReadOnly}, {"writeOnly", rs.WriteOnly}, {"default", rs.Default},
	} {
		if len(k.raw) > 0 {
			im.note("schema keyword %q ignored at %s", k.name, loc)
		}
	}
}

// conv converts a parsed schema node. It returns nil (after recording why) when
// the node cannot be represented faithfully.
func (im *importer) conv(rs *rawSchema, loc string, depth int) *Schema {
	if rs == nil {
		return nil
	}
	if depth > maxSchemaDepth {
		if !im.depthNote {
			im.depthNote = true
			im.note("schema nesting deeper than %d (at %s); truncated", maxSchemaDepth, loc)
		}
		return nil
	}
	im.nodes++
	if im.nodes > maxSchemaNodes {
		if !im.budgetNote {
			im.budgetNote = true
			im.note("schema node budget (%d) exceeded at %s; remaining schemas truncated", maxSchemaNodes, loc)
		}
		return nil
	}
	if rs.Ref != "" {
		_, name, ok := im.lookupRef(rs.Ref, "schemas")
		if !ok {
			return nil
		}
		return im.component(name, depth+1)
	}
	im.ignored(rs, loc)
	if len(rs.Not) > 0 && string(rs.Not) != "null" {
		im.note("schema keyword \"not\" not modelled at %s", loc)
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
			if ps := im.conv(rs.Properties[n], loc+".properties."+n, depth+1); ps != nil {
				s.Properties[n] = ps
			} else {
				im.note("property %q dropped from schema at %s", n, loc)
			}
		}
	}
	if rs.Items != nil {
		s.Items = im.conv(rs.Items, loc+".items", depth+1)
		if s.Items == nil {
			im.note("array items not modelled at %s", loc)
		}
	}

	for _, part := range rs.AllOf {
		ps := im.conv(part, loc+".allOf", depth+1)
		if ps == nil {
			im.note("allOf member not modelled at %s; whole schema not modelled", loc)
			return nil
		}
		if why := mergeInto(s, ps); why != "" {
			im.note("allOf conflict at %s (%s); whole schema not modelled", loc, why)
			return nil
		}
	}
	for _, alt := range []struct {
		name  string
		parts []*rawSchema
	}{{"oneOf", rs.OneOf}, {"anyOf", rs.AnyOf}} {
		switch len(alt.parts) {
		case 0:
		case 1:
			ps := im.conv(alt.parts[0], loc+"."+alt.name, depth+1)
			if ps == nil {
				return nil
			}
			if why := mergeInto(s, ps); why != "" {
				im.note("%s conflict at %s (%s); whole schema not modelled", alt.name, loc, why)
				return nil
			}
		default:
			im.note("%s with %d alternatives at %s cannot be flattened; not modelled", alt.name, len(alt.parts), loc)
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

// mergeInto folds src into dst with allOf (intersection) semantics. Where the
// two combine exactly (enum intersection, tightest bounds, union of required)
// it does so; any real conflict returns a reason and the caller drops the
// schema. Nullable is OR-ed (a member that is nullable alone is accepted).
func mergeInto(dst, src *Schema) string {
	if src.Type != "" {
		if dst.Type != "" && dst.Type != src.Type {
			return "type " + dst.Type + " vs " + src.Type
		}
		dst.Type = src.Type
	}
	if src.Format != "" {
		if dst.Format != "" && dst.Format != src.Format {
			return "format " + dst.Format + " vs " + src.Format
		}
		dst.Format = src.Format
	}
	if src.Pattern != "" {
		if dst.Pattern != "" && dst.Pattern != src.Pattern {
			return "pattern differs"
		}
		dst.Pattern = src.Pattern
	}
	if src.Items != nil {
		if dst.Items != nil && !reflect.DeepEqual(dst.Items, src.Items) {
			return "items differ"
		}
		dst.Items = src.Items
	}
	if src.Enum != nil {
		if dst.Enum == nil {
			dst.Enum = src.Enum
		} else {
			var both []any
			for _, a := range dst.Enum {
				for _, b := range src.Enum {
					if reflect.DeepEqual(a, b) {
						both = append(both, a)
						break
					}
				}
			}
			if len(both) == 0 {
				return "enums have no common value"
			}
			dst.Enum = both
		}
	}
	dst.Minimum = tighter(dst.Minimum, src.Minimum, true)
	dst.Maximum = tighter(dst.Maximum, src.Maximum, false)
	if src.MinLength != nil && (dst.MinLength == nil || *src.MinLength > *dst.MinLength) {
		dst.MinLength = src.MinLength
	}
	if src.MaxLength != nil && (dst.MaxLength == nil || *src.MaxLength < *dst.MaxLength) {
		dst.MaxLength = src.MaxLength
	}
	dst.Nullable = dst.Nullable || src.Nullable
	names := make([]string, 0, len(src.Properties))
	for n := range src.Properties {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if dst.Properties == nil {
			dst.Properties = map[string]*Schema{}
		}
		if old, exists := dst.Properties[n]; exists {
			if !reflect.DeepEqual(old, src.Properties[n]) {
				return "property " + n + " defined differently in two members"
			}
			continue
		}
		dst.Properties[n] = src.Properties[n]
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
	return ""
}

// tighter returns the more restrictive bound (larger minimum / smaller maximum).
func tighter(a, b *float64, isMin bool) *float64 {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if (isMin && *b > *a) || (!isMin && *b < *a) {
		return b
	}
	return a
}
