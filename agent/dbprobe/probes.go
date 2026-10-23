package dbprobe

import (
	"fmt"
	"sort"
	"strings"
)

// Upper bounds on Limits so MaxRows+1 and TimeoutSec*1000 can never overflow.
const (
	MaxRowsCap       = 1_000_000
	MaxTimeoutSecCap = 3600
	MaxConnsCap      = 64
)

var bothEngines = []string{"postgresql", "mysql"}

var catalog = map[string]ProbeDef{
	"read_roles": {ID: "read_roles", Class: ClassReadOnly, Engines: bothEngines,
		ParamSchema: map[string]ParamKind{}},
	"read_grants": {ID: "read_grants", Class: ClassReadOnly, Engines: bothEngines,
		ParamSchema: map[string]ParamKind{"role": ParamString}},
	"auth_check": {ID: "auth_check", Class: ClassReadOnly, Engines: bothEngines,
		ParamSchema: map[string]ParamKind{}},
	// read_audit_config reports the audit-relevant settings through fixed
	// read-only SQL (no parameters). It observes; it never changes a setting.
	"read_audit_config": {ID: "read_audit_config", Class: ClassReadOnly, Engines: bothEngines,
		ParamSchema: map[string]ParamKind{}},
	"read_restricted_table": {ID: "read_restricted_table", Class: ClassReadOnly, Engines: bothEngines,
		ParamSchema: map[string]ParamKind{"table": ParamString}},
	// suspicious_read (DB-05): one unfiltered all-column SELECT of a seeded
	// fixture table, a read pattern a DAM/SIEM rule is expected to flag. It only
	// runs a SELECT inside a READ ONLY transaction (class read_only) and reads at
	// most SuspiciousReadMaxRows rows whatever the spec limit says. It is
	// fixture-aware, hence lab-only.
	ProbeSuspiciousRead: {ID: ProbeSuspiciousRead, Class: ClassReadOnly, Engines: bothEngines,
		ParamSchema: map[string]ParamKind{"table": ParamString}, FixtureParam: "table"},
	// bounded_synthetic_read (DB-09): the same fixed SELECT as a row-capped BULK
	// read (cap = Limits.MaxRows, plus a byte cap). Classified bounded_synthetic
	// because it runs against a per-run seeded fixture, so it needs the
	// lab-mutation allowance even though its own SQL is a SELECT in a READ ONLY
	// transaction.
	ProbeBoundedSyntheticRead: {ID: ProbeBoundedSyntheticRead, Class: ClassBoundedSynthetic, Engines: bothEngines,
		ParamSchema: map[string]ParamKind{"table": ParamString}, FixtureParam: "table"},
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
// param, has a valid mode, a connection host/port, a registered identity, and
// positive limits.
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
	if strings.TrimSpace(s.Host) == "" {
		return fmt.Errorf("dbprobe: host must not be empty")
	}
	if s.Port < 0 || s.Port > 65535 {
		return fmt.Errorf("dbprobe: port %d out of range", s.Port)
	}
	if s.ExpectedIdentity == "" {
		return fmt.Errorf("dbprobe: expectedIdentity (registered target identity) must not be empty")
	}
	for k := range s.Params {
		if _, ok := def.ParamSchema[k]; !ok {
			return fmt.Errorf("dbprobe: param %q not declared for probe %q", k, s.ProbeID)
		}
	}
	if def.FixtureParam != "" {
		if s.FixtureID == "" {
			return fmt.Errorf("dbprobe: probe %q reads a seeded fixture and requires a fixtureId", s.ProbeID)
		}
		if s.Mode != ModeLab {
			return fmt.Errorf("dbprobe: probe %q is fixture-aware and runs only in lab mode", s.ProbeID)
		}
	}
	if s.Limits.MaxRows <= 0 || s.Limits.TimeoutSec <= 0 || s.Limits.MaxConns <= 0 {
		return fmt.Errorf("dbprobe: limits must all be > 0")
	}
	if s.Limits.MaxRows > MaxRowsCap || s.Limits.TimeoutSec > MaxTimeoutSecCap || s.Limits.MaxConns > MaxConnsCap {
		return fmt.Errorf("dbprobe: limits exceed sane maximums (rows %d, timeout %ds, conns %d)",
			MaxRowsCap, MaxTimeoutSecCap, MaxConnsCap)
	}
	return nil
}
