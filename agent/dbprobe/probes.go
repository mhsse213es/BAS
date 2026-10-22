package dbprobe

import (
	"fmt"
	"sort"
)

var bothEngines = []string{"postgresql", "mysql"}

var catalog = map[string]ProbeDef{
	"read_roles": {ID: "read_roles", Class: ClassReadOnly, Engines: bothEngines,
		ParamSchema: map[string]ParamKind{}},
	"read_grants": {ID: "read_grants", Class: ClassReadOnly, Engines: bothEngines,
		ParamSchema: map[string]ParamKind{"role": ParamString}},
	"auth_check": {ID: "auth_check", Class: ClassReadOnly, Engines: bothEngines,
		ParamSchema: map[string]ParamKind{}},
	"read_restricted_table": {ID: "read_restricted_table", Class: ClassReadOnly, Engines: bothEngines,
		ParamSchema: map[string]ParamKind{"table": ParamString}},
}

// LookupProbe returns the catalog entry for id.
func LookupProbe(id string) (ProbeDef, bool) {
	d, ok := catalog[id]
	return d, ok
}

// ProbeIDs returns all catalog probe ids, sorted.
func ProbeIDs() []string {
	ids := make([]string, 0, len(catalog))
	for id := range catalog {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// ValidateSpec checks the probe exists, supports the engine, declares every
// param, has a valid mode, and has positive limits.
func ValidateSpec(s DBProbeSpec) error {
	def, ok := LookupProbe(s.ProbeID)
	if !ok {
		return fmt.Errorf("dbprobe: unknown probe %q", s.ProbeID)
	}
	engineOK := false
	for _, e := range def.Engines {
		if e == s.Engine {
			engineOK = true
		}
	}
	if !engineOK {
		return fmt.Errorf("dbprobe: probe %q does not support engine %q", s.ProbeID, s.Engine)
	}
	if s.Mode != ModeLab && s.Mode != ModeClient {
		return fmt.Errorf("dbprobe: invalid mode %q", s.Mode)
	}
	for k := range s.Params {
		if _, ok := def.ParamSchema[k]; !ok {
			return fmt.Errorf("dbprobe: param %q not declared for probe %q", k, s.ProbeID)
		}
	}
	if s.Limits.MaxRows <= 0 || s.Limits.TimeoutSec <= 0 || s.Limits.MaxConns <= 0 {
		return fmt.Errorf("dbprobe: limits must all be > 0")
	}
	return nil
}
