package dbprobe

import "strings"

// ProbeCheckReadOnlyIdentity is the read-only identity check behind the client
// mode release gate (spec R4/R8, Task 16). It is a fixed set of read-only
// catalog questions about the CONNECTED account: can it write data, change the
// schema, administer accounts or touch audit settings? It takes no parameter,
// uses no fixture and is allowed in client mode (it is the probe that decides
// whether a target may ever be used in client mode).
const ProbeCheckReadOnlyIdentity = "check_readonly_identity"

// Values of the identity_checks note
// "identity_checks=can_write=<v>,can_ddl=<v>,can_admin=<v>,can_audit=<v>".
const (
	IdentityChecksKey = "identity_checks"

	IdentityYes     = "yes"     // the account holds the capability (or a superset of it)
	IdentityNo      = "no"      // positively observed not to hold it
	IdentityUnknown = "unknown" // could not be observed; never read as "no"
)

// IdentityChecksNote renders the check_readonly_identity typed note.
func IdentityChecksNote(canWrite, canDDL, canAdmin, canAudit string) string {
	return IdentityChecksKey + "=can_write=" + canWrite + ",can_ddl=" + canDDL +
		",can_admin=" + canAdmin + ",can_audit=" + canAudit
}

// IdentityVerdict returns the result ErrorClass for the four answers: empty when
// the observation is usable (a definite "yes" is a finding even if another
// answer is unobservable) and "identity_check_incomplete" when nothing is held
// but at least one answer is unobserved. The probe never sets Denied: the
// orchestrator decides pass/fail from the typed note.
func IdentityVerdict(canWrite, canDDL, canAdmin, canAudit string) string {
	vs := []string{canWrite, canDDL, canAdmin, canAudit}
	incomplete := false
	for _, v := range vs {
		if v == IdentityYes {
			return ""
		}
		if v != IdentityNo {
			incomplete = true
		}
	}
	if incomplete {
		return "identity_check_incomplete"
	}
	return ""
}

// PrivRow is one privilege row of the connected MySQL account as read from
// information_schema. Scope is "G" (USER_PRIVILEGES, global), "S"
// (SCHEMA_PRIVILEGES), "T" (TABLE_PRIVILEGES) or "C" (COLUMN_PRIVILEGES);
// Schema is empty for global rows.
type PrivRow struct {
	Scope     string
	Schema    string
	Privilege string
	// Grantable is the row's IS_GRANTABLE value. "YES" on ANY row means the
	// account holds GRANT OPTION (information_schema has no GRANT OPTION
	// PRIVILEGE_TYPE row). Empty is treated as not grantable.
	Grantable string
}

var (
	mysqlWritePrivs = setOf("INSERT", "UPDATE", "DELETE")
	mysqlDDLPrivs   = setOf("CREATE", "DROP", "ALTER", "INDEX", "CREATE VIEW", "CREATE ROUTINE",
		"ALTER ROUTINE", "TRIGGER", "EVENT", "CREATE TABLESPACE")
	mysqlAdminPrivs = setOf("SUPER", "CREATE USER", "GRANT OPTION", "RELOAD", "SHUTDOWN", "REPLICATION SLAVE",
		"FILE", "CREATE ROLE", "DROP ROLE")
	mysqlAuditPrivs  = setOf("SUPER", "SYSTEM_VARIABLES_ADMIN", "AUDIT_ADMIN")
	mysqlBenignPrivs = setOf("SELECT", "USAGE", "SHOW VIEW", "SHOW DATABASES", "PROCESS",
		"REFERENCES", "REPLICATION CLIENT", "LOCK TABLES", "CREATE TEMPORARY TABLES", "SHOW_ROUTINE")
)

func setOf(v ...string) map[string]bool {
	m := make(map[string]bool, len(v))
	for _, s := range v {
		m[s] = true
	}
	return m
}

// ClassifyMySQLPrivileges turns the connected MySQL account's privilege rows
// into the four identity answers. It is deliberately conservative:
//
//   - No rows at all means the grantee match failed (a real account always has at
//     least a USAGE row): every answer is unknown, never "holds nothing".
//   - A privilege this function does not recognise (not read-only, not in a known
//     write/DDL/admin/audit set, not a *_ADMIN dynamic privilege) could be any
//     capability, so every answer that is not already "yes" becomes unknown.
//   - Audit control is SUPER, SYSTEM_VARIABLES_ADMIN or AUDIT_ADMIN, or any
//     write/DDL privilege that reaches the mysql or sys schemas (global scope, a
//     wildcard schema, or a schema/table row for those schemas), because the
//     general log and audit tables live there.
//
// What it does NOT see: privileges that arrive through an active or merely
// granted role (the caller reports unknown), column-level SELECT detail, PROXY
// grants (mysql.proxies_priv) and the PROCESS privilege's reach. Never run
// against a real server: UNVERIFIED until the staging integration tests run.
func ClassifyMySQLPrivileges(rows []PrivRow) (canWrite, canDDL, canAdmin, canAudit string) {
	if len(rows) == 0 {
		return IdentityUnknown, IdentityUnknown, IdentityUnknown, IdentityUnknown
	}
	var w, d, a, au, unknown, execute bool
	for _, r := range rows {
		scope := strings.ToUpper(strings.TrimSpace(r.Scope))
		p := strings.ToUpper(strings.TrimSpace(r.Privilege))
		schema := strings.ToLower(strings.TrimSpace(r.Schema))
		if scope != "G" && scope != "S" && scope != "T" && scope != "C" {
			unknown = true
			continue
		}
		// GRANT OPTION appears only as IS_GRANTABLE=YES on another row.
		if strings.EqualFold(strings.TrimSpace(r.Grantable), "YES") {
			a = true
		}
		reachesAudit := scope == "G" || schema == "mysql" || schema == "sys" || strings.ContainsAny(schema, "%_*")
		switch {
		case p == "ALL PRIVILEGES" || p == "ALL" || p == "SUPER":
			w, d, a, au = true, true, true, true
		case mysqlWritePrivs[p]:
			w = true
			au = au || reachesAudit
		case mysqlDDLPrivs[p]:
			d = true
			au = au || reachesAudit
		case mysqlAdminPrivs[p]:
			a = true
		case strings.HasSuffix(p, "_ADMIN"):
			a = true
			au = au || mysqlAuditPrivs[p]
		case p == "EXECUTE":
			// A SECURITY DEFINER routine can write on the caller's behalf, and
			// routine bodies are not inspected: write is unknown unless a write
			// privilege shows yes. Not a DDL/admin/audit signal.
			execute = true
		case mysqlBenignPrivs[p]:
		default:
			unknown = true
		}
		if mysqlAuditPrivs[p] {
			au = true
		}
	}
	pick := func(yes bool) string {
		switch {
		case yes:
			return IdentityYes
		case unknown:
			return IdentityUnknown
		}
		return IdentityNo
	}
	cw := pick(w)
	if cw == IdentityNo && execute {
		cw = IdentityUnknown
	}
	return cw, pick(d), pick(a), pick(au)
}
