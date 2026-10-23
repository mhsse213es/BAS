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
	// Rule (R-AI): a run that seeds a fixture mutates the lab database and is
	// gated as bounded_synthetic regardless of what the probe itself reads.
	//
	// suspicious_read (DB-05): one unfiltered all-column SELECT of a seeded
	// fixture table, a read pattern a DAM/SIEM rule is expected to flag; at most
	// SuspiciousReadMaxRows rows whatever the spec limit says. Lab-only.
	ProbeSuspiciousRead: {ID: ProbeSuspiciousRead, Class: ClassBoundedSynthetic, Engines: bothEngines,
		ParamSchema: map[string]ParamKind{"table": ParamString}, FixtureParam: "table"},
	// bounded_synthetic_read (DB-09): the same fixed SELECT as a row-capped BULK
	// read (cap = Limits.MaxRows, plus a byte cap). Lab-only.
	ProbeBoundedSyntheticRead: {ID: ProbeBoundedSyntheticRead, Class: ClassBoundedSynthetic, Engines: bothEngines,
		ParamSchema: map[string]ParamKind{"table": ParamString}, FixtureParam: "table"},
	// read_classified_fixture (DB-07): the same bounded unfiltered read, fixed to
	// the customers_pii table of the classified-pii fixture (published test card
	// numbers only). No table param exists, so nothing else can be addressed.
	ProbeReadClassifiedFixture: {ID: ProbeReadClassifiedFixture, Class: ClassBoundedSynthetic, Engines: bothEngines,
		ParamSchema: map[string]ParamKind{}, RequiredFixture: ClassifiedFixtureKind, FixedTable: ClassifiedFixtureTable},
	// auth_after_revoke (DB-06): creates a throwaway login account for this run,
	// proves it can connect, revokes its login and proves a NEW connection is then
	// refused. Class bounded_synthetic (ruling R-AO): it only creates, locks and
	// drops its own throwaway account, like the fixture lifecycle of DB-05/09. A true
	// mutation class signs as destructive, which the agent's B5 gate vetoes with no
	// approval path. Lab-only and mutation-approved via RequiredFixture (R-AI), not class.
	ProbeAuthAfterRevoke: {ID: ProbeAuthAfterRevoke, Class: ClassBoundedSynthetic, Engines: bothEngines,
		ParamSchema: map[string]ParamKind{}, RequiredFixture: RevokeFixtureKind},
	// try_disable_audit (DB-08): a throwaway NO-privilege account opens a new
	// connection and attempts ONLY a session-scoped audit change (see
	// auditTamperSQL). bounded_synthetic (user decision, option A: never
	// mutation, B5 vetoes destructive); no parameter, mode or code path performs
	// a global or persistent audit change. Lab only via its required fixture.
	ProbeTryDisableAudit: {ID: ProbeTryDisableAudit, Class: ClassBoundedSynthetic, Engines: bothEngines,
		ParamSchema: map[string]ParamKind{}, RequiredFixture: AuditTamperFixtureKind},
	// try_write_fixture (DB-10): a throwaway SELECT-only account attempts one
	// INSERT, UPDATE and DELETE against the fixture's accounts table; the table
	// state is fingerprinted before and after through the lab connection.
	ProbeTryWriteFixture: {ID: ProbeTryWriteFixture, Class: ClassBoundedSynthetic, Engines: bothEngines,
		ParamSchema: map[string]ParamKind{}, RequiredFixture: WriteFixtureKind},
	// check_export_privileges (DB-11): fixed read-only catalog queries about
	// what the CONNECTED account may do regarding export/backup. No export is
	// ever performed. Read-only by class, lab-only by LabOnly.
	ProbeCheckExportPrivileges: {ID: ProbeCheckExportPrivileges, Class: ClassReadOnly, Engines: bothEngines,
		ParamSchema: map[string]ParamKind{}, LabOnly: true},
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
	if def.RequiredFixture != "" {
		if s.FixtureID != def.RequiredFixture {
			return fmt.Errorf("dbprobe: probe %q requires fixture %q", s.ProbeID, def.RequiredFixture)
		}
		if s.Mode != ModeLab {
			return fmt.Errorf("dbprobe: probe %q needs a seeded fixture and runs only in lab mode", s.ProbeID)
		}
	}
	if def.LabOnly {
		if s.Mode != ModeLab {
			return fmt.Errorf("dbprobe: probe %q runs only in lab mode", s.ProbeID)
		}
		if s.FixtureID != "" {
			return fmt.Errorf("dbprobe: probe %q reads no fixture", s.ProbeID)
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
