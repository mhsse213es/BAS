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
	"dbsim-db03-unauthorized-access": {
		"read_restricted_table": expDeny,
	},
	"dbsim-db04-audit-coverage": {
		"read_audit_config": {ExpectedPrevention: "allow", ExpectAuditConfig: true},
		"read_roles":        {ExpectedPrevention: "allow", ExpectDetection: true, ExpectAudit: true},
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
