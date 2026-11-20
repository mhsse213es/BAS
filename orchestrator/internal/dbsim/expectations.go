package dbsim

// Expectation is the per-scenario-step grading expectation of a shipped dbsim
// scenario. The values are the ones the live staging runs (PostgreSQL and
// MySQL) were graded with; they were moved here from the dbrun test helper so
// the product run path and the tests grade through the same table.
//
// The detection rule in the lab fires on every statement that begins with the
// marker comment, except the agent's own audit-lookup and meta statements
// (read_audit_config mentions audit-source words so it never alerts), and a
// failed login or catalog read carries no marker, so those steps carry no SIEM
// expectation.
type Expectation struct {
	ExpectedPrevention   string // "allow" | "deny"
	ExpectDetection      bool
	ExpectAudit          bool
	// AuditRequire lists statement texts that must each appear in a marker-tagged
	// audit event, separated by "|". Empty = any marker event. Kept a string so
	// Expectation stays comparable.
	AuditRequire string
	ExpectAuditConfig    bool
	RequireObservation   bool
	RequirePolicyDiff    bool
	ExpectClassification bool
}

var (
	expAllow = Expectation{ExpectedPrevention: "allow", ExpectDetection: true}
	expDeny  = Expectation{ExpectedPrevention: "deny", ExpectDetection: true}
	// DB-06 (the NEW login after the revoke must be refused; a failed login
	// carries no marker) and DB-11 (a catalog read).
	expDenyNoSIEM = Expectation{ExpectedPrevention: "deny"}
)

// expectations is keyed by scenario id, then probe id, pinned to the `db_probe`
// fields of the 11 shipped scenarios (scenarios/dbsim-db01..db11).
var expectations = map[string]map[string]Expectation{
	"dbsim-db01-auth-policy": {
		"auth_check": expAllow,
		"read_roles": expAllow,
	},
	"dbsim-db02-excessive-grants": {
		"read_roles": expAllow,
		"read_grants": {ExpectedPrevention: "allow", ExpectDetection: true,
			RequireObservation: true, RequirePolicyDiff: true},
	},
	"dbsim-db02-01-role-enumeration": {
		"read_roles": expAllow,
	},
	"dbsim-db02-02-app-role-grants": {
		"read_grants": {ExpectedPrevention: "allow", ExpectDetection: true,
			RequireObservation: true, RequirePolicyDiff: true},
	},
	"dbsim-db02-03-excessive-privilege": {
		"read_grants": {ExpectedPrevention: "allow", ExpectDetection: true,
			RequireObservation: true, RequirePolicyDiff: true},
	},
	"dbsim-db02-04-dba-accounts": {
		"read_roles": expAllow,
	},
	"dbsim-db02-08-public-grants": {
		"read_grants": {ExpectedPrevention: "allow", ExpectDetection: true,
			RequireObservation: true, RequirePolicyDiff: true},
	},
	"dbsim-db02-11-service-account": {
		"read_grants": {ExpectedPrevention: "allow", ExpectDetection: true,
			RequireObservation: true, RequirePolicyDiff: true},
	},
	"dbsim-db02-09-cross-schema-access": {
		"read_grants": {ExpectedPrevention: "allow", ExpectDetection: true,
			RequireObservation: true, RequirePolicyDiff: true},
	},
	"dbsim-db02-10-sensitive-table-access": {
		"read_grants": {ExpectedPrevention: "allow", ExpectDetection: true,
			RequireObservation: true, RequirePolicyDiff: true},
	},
	"dbsim-db02-07-grant-option": {
		"read_grants": {ExpectedPrevention: "allow", ExpectDetection: true,
			RequireObservation: true, RequirePolicyDiff: true},
	},
	"dbsim-db02-05-global-grants": {
		"read_global_privileges": {ExpectedPrevention: "allow", ExpectDetection: true,
			RequireObservation: true, RequirePolicyDiff: true},
	},
	"dbsim-db02-06-inheritance-chain": {
		"read_memberships": {ExpectedPrevention: "allow", ExpectDetection: true,
			RequireObservation: true, RequirePolicyDiff: true},
	},
	"dbsim-db03-unauthorized-access": {
		"read_restricted_table":   expDeny,
		"read_customer_records":   expDeny,
		"read_financial_records":  expDeny,
		// PostgreSQL grants pg_roles to every login: the read is allowed and the
		// visibility of other role names is recorded, not denied.
		"read_foreign_role_names": expAllow,
	},
	"dbsim-db04-06-role-audit": {
		"audit_role_roundtrip": {ExpectedPrevention: "allow", ExpectAudit: true, AuditRequire: "GRANT|REVOKE"},
	},
	"dbsim-db04-08-ddl-audit": {
		"audit_ddl_roundtrip": {ExpectedPrevention: "allow", ExpectAudit: true, AuditRequire: "CREATE TABLE|DROP TABLE"},
	},
	"dbsim-db04-audit-coverage": {
		"read_audit_config": {ExpectedPrevention: "allow", ExpectAuditConfig: true},
		"read_roles":        {ExpectedPrevention: "allow", ExpectDetection: true, ExpectAudit: true},
	},
	// DB-04-03: a successful login must appear in the connection log for the probe role.
	// DB-04-04: a refused wrong-password login must be recorded under the throwaway account.
	"dbsim-db04-04-failed-login-audit": {
		"auth_failed_login": {ExpectedPrevention: "deny", ExpectAudit: true},
	},
	"dbsim-db04-03-authentication-audit": {
		"auth_check": {ExpectedPrevention: "allow", ExpectAudit: true},
	},
	// DB-04-07: a denied sensitive read must still be recorded by the audit trail.
	"dbsim-db04-07-sensitive-table-access": {
		"read_restricted_table": {ExpectedPrevention: "deny", ExpectDetection: true, ExpectAudit: true},
	},
	"dbsim-db05-suspicious-read": {
		"suspicious_read": expAllow,
	},
	"dbsim-db06-account-revocation": {
		"auth_after_revoke": expDenyNoSIEM,
	},
	"dbsim-db07-sensitive-classification": {
		"read_classified_fixture": {ExpectedPrevention: "allow", ExpectDetection: true, ExpectClassification: true},
	},
	"dbsim-db08-audit-tamper-resistance": {
		"try_disable_audit": expDeny,
	},
	"dbsim-db09-bounded-bulk-read": {
		"bounded_synthetic_read": expAllow,
	},
	"dbsim-db10-write-delete-prevention": {
		"try_write_fixture": expDeny,
	},
	"dbsim-db11-backup-export-permissions": {
		"check_export_privileges": expDenyNoSIEM,
	},
}

// ExpectationFor returns the expectation of a shipped scenario step. It fails
// closed: an unknown scenario/probe pair returns false and a zero Expectation.
func ExpectationFor(scenarioID, probeID string) (Expectation, bool) {
	e, ok := expectations[scenarioID][probeID]
	return e, ok
}
