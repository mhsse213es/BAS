// Package dbsim holds the orchestrator side of database security simulation.
// This file mirrors the agent wire types (agent/protocol/dbprobe.go); the
// orchestrator never imports agent code. The two are tied by an identical
// golden JSON vector in each module (testdata/dbprobe_spec.golden.json).
package dbsim

import (
	"sort"
	"time"
)

type ExecMode string

const (
	ModeLab    ExecMode = "lab"
	ModeClient ExecMode = "client"
)

type Limits struct {
	MaxRows    int `json:"maxRows"`
	TimeoutSec int `json:"timeoutSec"`
	MaxConns   int `json:"maxConns"`
}

type DBProbeSpec struct {
	Engine   string `json:"engine"`
	ProbeID  string `json:"probeId"`
	TargetID string `json:"targetId"`
	// Connection target. Host/Port/Database/TLSMode say where to connect;
	// ExpectedIdentity is the pre-registered PG system_identifier / MySQL
	// server_uuid the agent gate compares against the observed identity.
	// None of these is a secret (credentials stay a CredentialRef).
	Host             string `json:"host"`
	Port             int    `json:"port"`
	Database         string `json:"database,omitempty"`
	TLSMode          string `json:"tlsMode,omitempty"`
	ExpectedIdentity string `json:"expectedIdentity"`
	CredentialRef    string `json:"credentialRef"`
	// SeedCredentialRef: privileged credential for fixture seed/cleanup (see agent protocol).
	SeedCredentialRef string   `json:"seedCredentialRef,omitempty"`
	RunID             string   `json:"runId"`
	Marker            string   `json:"marker"`
	FixtureID         string   `json:"fixtureId,omitempty"`
	Mode              ExecMode `json:"mode"`
	// AuditBasis selects the audit evidence class: "" (marker) or AuditBasisRoleWindow.
	AuditBasis string            `json:"auditBasis,omitempty"`
	Limits     Limits            `json:"limits"`
	Params     map[string]string `json:"params,omitempty"`
}

type DBProbeResult struct {
	Denied     bool      `json:"denied"`
	RowsRead   int       `json:"rowsRead"`
	ErrorClass string    `json:"errorClass,omitempty"`
	DBTime     time.Time `json:"dbTime"`
	AgentTime  time.Time `json:"agentTime"`
	Notes      []string  `json:"notes,omitempty"`
	// AuditStatus and AuditEvents mirror the agent's audit readback
	// (agent/protocol/dbprobe.go). Empty AuditStatus means no attempt was
	// recorded; "unsupported" and "error" must never be graded as a pass.
	AuditStatus string `json:"auditStatus,omitempty"`
	// AuditBasis echoes the evidence class that produced AuditStatus.
	AuditBasis string `json:"auditBasis,omitempty"`
	// AuditPrincipal is the account the connection evidence was matched under
	// (the throwaway account for the failed-login basis).
	AuditPrincipal string              `json:"auditPrincipal,omitempty"`
	AuditEvents    []DBProbeAuditEvent `json:"auditEvents,omitempty"`
	// CleanupStatus and SafetyIncident mirror the agent's fixture teardown
	// report (agent/protocol/dbprobe.go). Empty status means an older agent or
	// no fixture. A SafetyIncident, or a residual/failed status, can never be
	// graded as a pass.
	CleanupStatus  string `json:"cleanupStatus,omitempty"`
	SafetyIncident bool   `json:"safetyIncident,omitempty"`
	// Grants mirrors agent protocol.DBProbeResult.Grants (read_grants only).
	Grants []DBProbeGrant `json:"grants,omitempty"`
	// GlobalGrants and Memberships mirror the agent result (read_global_privileges, read_memberships).
	GlobalGrants []DBProbeGlobalGrant `json:"globalGrants,omitempty"`
	Memberships  []DBProbeMembership  `json:"memberships,omitempty"`
}

// DBProbeGlobalGrant mirrors agent protocol.DBProbeGlobalGrant.
type DBProbeGlobalGrant struct {
	Role      string `json:"role"`
	Scope     string `json:"scope"`
	Privilege string `json:"privilege"`
}

// DBProbeMembership mirrors agent protocol.DBProbeMembership.
type DBProbeMembership struct {
	Role    string `json:"role"`
	Member  string `json:"member"`
	Inherit bool   `json:"inherit"`
}

// DBProbeGrant mirrors agent protocol.DBProbeGrant.
type DBProbeGrant struct {
	Role        string `json:"role"`
	Object      string `json:"object"`
	Privilege   string `json:"privilege"`
	GrantOption bool   `json:"grantOption,omitempty"`
}

// Cleanup status values (DBProbeResult.CleanupStatus); same strings as the
// agent's protocol.DBCleanup* constants, tied by the result golden vector.
const (
	CleanupNotApplicable = "not_applicable" // no fixture was used
	CleanupOK            = "ok"             // fixture removed and verified gone
	CleanupResidual      = "residual"       // verification found leftover objects
	CleanupFailed        = "failed"         // cleanup or verification itself failed
)

// Audit status values (DBProbeResult.AuditStatus); same strings as the agent's
// protocol.DBAudit* constants, tied by the result golden vector.
const (
	AuditUnsupported = "unsupported" // no queryable audit source on the target
	AuditAbsent      = "absent"      // source healthy, window covered, no marker event
	AuditFound       = "found"       // at least one marker event, evidence complete
	AuditIncomplete  = "incomplete"  // window rotated/evicted or cap hit; absence proves nothing
	AuditError       = "error"       // collection failed; never absent
)

// DBProbeAuditEvent is one marker-bearing audit record.
type DBProbeAuditEvent struct {
	Time      time.Time `json:"time"`
	Principal string    `json:"principal,omitempty"`
	Statement string    `json:"statement"`
	Source    string    `json:"source,omitempty"`
}

type ProbeClass string

const (
	ClassReadOnly         ProbeClass = "read_only"
	ClassBoundedSynthetic ProbeClass = "bounded_synthetic"
	ClassMutation         ProbeClass = "mutation"
)

// ProbeRegistryEntry is the orchestrator's data-only view of an agent probe.
type ProbeRegistryEntry struct {
	ID          string
	Class       ProbeClass
	Engines     []string
	ParamSchema map[string]string // param name -> kind ("string"|"int"|"bool")
	// FixtureParam, when set, marks a fixture-aware probe and names the param
	// that carries a fixture TABLE NAME (never a schema). Such a probe reads the
	// run's seeded fixture, so it needs a db_fixture on the step and is lab-only.
	FixtureParam string
	// RequiredFixture, when set, is the one catalog fixture a step of this probe
	// must name in db_fixture; such a probe is lab-only and takes no table param.
	RequiredFixture string
	// FixedTable, when set, is the fixture table a RequiredFixture read probe
	// reads. It is fixed in the agent, so no param can address a table.
	FixedTable string
	// LabOnly marks a probe refused for client targets and, even when it is
	// read_only, requiring a confirmed lab target and the scenario's mutation
	// approval (DB-11). It takes no fixture.
	LabOnly bool
}

var probeRegistry = map[string]ProbeRegistryEntry{
	"read_roles":             {ID: "read_roles", Class: ClassReadOnly, Engines: []string{"postgresql", "mysql"}, ParamSchema: map[string]string{}},
	"read_grants":            {ID: "read_grants", Class: ClassReadOnly, Engines: []string{"postgresql", "mysql"}, ParamSchema: map[string]string{"role": "string"}},
	"read_global_privileges": {ID: "read_global_privileges", Class: ClassReadOnly, Engines: []string{"postgresql"}, ParamSchema: map[string]string{}},
	"read_memberships":       {ID: "read_memberships", Class: ClassReadOnly, Engines: []string{"postgresql"}, ParamSchema: map[string]string{}},
	"auth_check":             {ID: "auth_check", Class: ClassReadOnly, Engines: []string{"postgresql", "mysql"}, ParamSchema: map[string]string{}},
	"read_audit_config":      {ID: "read_audit_config", Class: ClassReadOnly, Engines: []string{"postgresql", "mysql"}, ParamSchema: map[string]string{}},
	"read_restricted_table":  {ID: "read_restricted_table", Class: ClassReadOnly, Engines: []string{"postgresql", "mysql"}, ParamSchema: map[string]string{"table": "string"}},
	// Rule (R-AI): a run that seeds a fixture mutates the lab database and is gated as bounded_synthetic regardless of what the probe itself reads.
	// DB-05: one unfiltered all-column SELECT of a seeded fixture table (small hard row cap).
	"suspicious_read": {ID: "suspicious_read", Class: ClassBoundedSynthetic, Engines: []string{"postgresql", "mysql"}, ParamSchema: map[string]string{"table": "string"}, FixtureParam: "table"},
	// DB-09: the same SELECT as a row-capped bulk read (bounded_synthetic: lab only, needs mutation approval).
	"bounded_synthetic_read": {ID: "bounded_synthetic_read", Class: ClassBoundedSynthetic, Engines: []string{"postgresql", "mysql"}, ParamSchema: map[string]string{"table": "string"}, FixtureParam: "table"},
	// DB-07: the same bounded unfiltered read, fixed to the customers_pii table of the classified-pii fixture (no table param).
	"read_classified_fixture": {ID: "read_classified_fixture", Class: ClassBoundedSynthetic, Engines: []string{"postgresql", "mysql"}, ParamSchema: map[string]string{}, RequiredFixture: "classified-pii", FixedTable: "customers_pii"},
	// DB-03 (tests 04, 05): a read of one restricted table of the authz-restricted fixture under its read role, which holds no grant on it (PostgreSQL only).
	"read_customer_records": {ID: "read_customer_records", Class: ClassReadOnly, Engines: []string{"postgresql"}, ParamSchema: map[string]string{}, RequiredFixture: "authz-restricted", FixedTable: "customers"},
	// DB-03 test 11 (T1087): counts role and account names other than the probe's own and the built-in ones. Counts only.
	"read_foreign_role_names": {ID: "read_foreign_role_names", Class: ClassReadOnly, Engines: []string{"postgresql", "mysql"}, ParamSchema: map[string]string{}, LabOnly: true},
	"read_financial_records":  {ID: "read_financial_records", Class: ClassReadOnly, Engines: []string{"postgresql"}, ParamSchema: map[string]string{}, RequiredFixture: "authz-restricted", FixedTable: "transactions"},
	// DB-06: creates a throwaway login account for the run, proves it can log in, revokes its login and proves a NEW connection is refused (bounded_synthetic, ruling R-AO: only touches its own throwaway account; lab only and mutation-approved through its required fixture, R-AI).
	"auth_after_revoke": {ID: "auth_after_revoke", Class: ClassBoundedSynthetic, Engines: []string{"postgresql", "mysql"}, ParamSchema: map[string]string{}, RequiredFixture: "empty"},
	"auth_failed_login": {ID: "auth_failed_login", Class: ClassBoundedSynthetic, Engines: []string{"postgresql"}, ParamSchema: map[string]string{}, RequiredFixture: "empty"},
	// DB-08: a throwaway NO-privilege account attempts ONLY a session-scoped audit change (bounded_synthetic, user decision option A: never mutation). No parameter selects a statement; no global or persistent change exists.
	"try_disable_audit": {ID: "try_disable_audit", Class: ClassBoundedSynthetic, Engines: []string{"postgresql", "mysql"}, ParamSchema: map[string]string{}, RequiredFixture: "empty"},
	// DB-10: a throwaway SELECT-only account attempts one INSERT, UPDATE and DELETE on the accounts fixture table; the table is fingerprinted before and after.
	"try_write_fixture": {ID: "try_write_fixture", Class: ClassBoundedSynthetic, Engines: []string{"postgresql", "mysql"}, ParamSchema: map[string]string{}, RequiredFixture: "accounts"},
	"audit_reload_conf": {ID: "audit_reload_conf", Class: ClassBoundedSynthetic, Engines: []string{"postgresql"}, ParamSchema: map[string]string{}, RequiredFixture: "accounts"},
	"audit_ddl_roundtrip": {ID: "audit_ddl_roundtrip", Class: ClassBoundedSynthetic, Engines: []string{"postgresql"}, ParamSchema: map[string]string{}, RequiredFixture: "accounts"},
	"audit_role_roundtrip": {ID: "audit_role_roundtrip", Class: ClassBoundedSynthetic, Engines: []string{"postgresql"}, ParamSchema: map[string]string{}, RequiredFixture: "accounts"},
	// DB-11: fixed read-only catalog queries about the connected account's export/backup privileges. Read-only by class, lab-only by LabOnly. No export is performed.
	"check_export_privileges": {ID: "check_export_privileges", Class: ClassReadOnly, Engines: []string{"postgresql", "mysql"}, ParamSchema: map[string]string{}, LabOnly: true},
	// Task 16: fixed read-only catalog questions about the connected account (can it write, change schema, administer accounts or touch audit settings). Plain read_only and allowed in client mode: it is how a target earns the read-only identity the client-mode release gate requires.
	"check_readonly_identity": {ID: "check_readonly_identity", Class: ClassReadOnly, Engines: []string{"postgresql", "mysql"}, ParamSchema: map[string]string{}},
}

// Task 14 probe ids.
const (
	ProbeReadClassifiedFixture = "read_classified_fixture"
	ProbeReadCustomerRecords   = "read_customer_records"
	ProbeReadFinancialRecords  = "read_financial_records"
	ProbeAuthAfterRevoke       = "auth_after_revoke"
)

// Task 15 probe ids.
const (
	ProbeTryDisableAudit       = "try_disable_audit"
	ProbeTryWriteFixture       = "try_write_fixture"
	ProbeCheckExportPrivileges = "check_export_privileges"
)

// ProbeReadGrants is the grant-enumeration probe (DB-02); its result is only
// meaningful against a performed policy diff (ruling R-AK).
const ProbeReadGrants = "read_grants"

// ProbeReadGlobalPrivileges (DB-02-05) and ProbeReadMemberships (DB-02-06) are read-only
// catalog reads compared with the policy; PostgreSQL only.
const (
	ProbeReadGlobalPrivileges = "read_global_privileges"
	ProbeReadMemberships      = "read_memberships"
)

// LookupProbeEntry returns the registry entry for a probe id.
func LookupProbeEntry(id string) (ProbeRegistryEntry, bool) {
	e, ok := probeRegistry[id]
	return e, ok
}

// ProbeIDs returns every registered probe id, sorted.
func ProbeIDs() []string {
	ids := make([]string, 0, len(probeRegistry))
	for id := range probeRegistry {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
