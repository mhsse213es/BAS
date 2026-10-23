// Package model is the generator-side application model: a neutral,
// deterministic view of an API derived from an OpenAPI description. It knows
// nothing about any particular application.
//
// Model.Match and PathMatches are case-sensitive; callers that guard requests
// must also consider that a server may route case-insensitively.
package model

import "sort"

// OpClass is a local string alias for the operation safety class. A later task
// converts it to safety.Class; it lives here to avoid an import cycle.
type OpClass string

const (
	ClassUnknown    OpClass = "unknown"
	ClassRead       OpClass = "read"
	ClassSetupSafe  OpClass = "setup_safe"
	ClassReversible OpClass = "reversible"
	ClassMoney      OpClass = "money"
	ClassNotifying  OpClass = "notifying"
)

// Param is a path or query parameter.
type Param struct {
	Name       string
	In         string // "path" or "query"
	IsObjectID bool
	Resource   string // collection the identifier refers to, when it can be derived
	Required   bool
	Schema     *Schema
}

// Schema is the subset of JSON Schema the generator reasons about.
type Schema struct {
	Type       string
	Format     string
	Enum       []any
	Nullable   bool
	Pattern    string
	Minimum    *float64
	Maximum    *float64
	MinLength  *int
	MaxLength  *int
	Required   []string
	Properties map[string]*Schema
	Items      *Schema
}

// PropertyNames returns property names in sorted order.
func (s *Schema) PropertyNames() []string {
	if s == nil {
		return nil
	}
	names := make([]string, 0, len(s.Properties))
	for n := range s.Properties {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Operation is one HTTP operation.
type Operation struct {
	ID          string
	Method      string // upper case
	Path        string
	PathParams  []Param
	QueryParams []Param
	Body        *Schema
	Security    []string // security scheme names required (sorted)
	Class       OpClass  // set by the operator later; the importer leaves ClassUnknown
}

// Model is the imported application model.
type Model struct {
	Operations  []Operation
	Roles       []string // filled by the operator, not by the importer
	NotModelled []string // human-readable notes for constructs that were skipped
}
