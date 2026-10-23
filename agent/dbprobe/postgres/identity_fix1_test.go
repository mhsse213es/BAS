package postgres

import (
	"strings"
	"testing"
)

// Fix round 1, I2. The queries are never run against a server here, so these
// tests pin the structure of the fixed SQL that closes each false-PASS path. The
// semantics are UNVERIFIED until the dbsim_integration tests run on staging.

func norm(s string) string { return strings.Join(strings.Fields(s), " ") }

// (a) views and foreign tables are write paths.
func TestIdentityWriteQueryCoversViewsAndForeignTables(t *testing.T) {
	q := norm(sqlIdWrite)
	if !strings.Contains(q, "'r','p','v','f'") {
		t.Fatalf("relkind list must include views and foreign tables: %s", q)
	}
	for _, kind := range []string{"'m'"} { // materialized views cannot be written
		if strings.Contains(q, kind) {
			t.Errorf("unexpected relkind %s", kind)
		}
	}
}

// (b) NOINHERIT memberships can still SET ROLE: privileges are evaluated for
// every role the account is a MEMBER of, not just for current_user's inherited set.
func TestIdentityQueriesEvaluateEveryMemberRole(t *testing.T) {
	member := "pg_has_role(current_user, x.oid, 'MEMBER')"
	for name, q := range map[string]string{"write": sqlIdWrite, "ddl": sqlIdDDL, "admin": sqlIdAdmin, "super": sqlIdSuper, "param": sqlIdParam} {
		if !strings.Contains(norm(q), member) {
			t.Errorf("%s query does not iterate the roles the account is a MEMBER of", name)
		}
	}
	w := norm(sqlIdWrite)
	for _, priv := range []string{"INSERT", "UPDATE", "DELETE", "TRUNCATE"} {
		if !strings.Contains(w, "has_table_privilege(x.oid, c.oid, '"+priv+"')") {
			t.Errorf("write: role-qualified has_table_privilege for %s missing", priv)
		}
	}
	for _, priv := range []string{"INSERT", "UPDATE"} {
		if !strings.Contains(w, "has_any_column_privilege(x.oid, c.oid, '"+priv+"')") {
			t.Errorf("write: role-qualified column privilege for %s missing", priv)
		}
	}
	if strings.Contains(w, "has_table_privilege(c.oid") {
		t.Error("write: the inherited-only form has_table_privilege(c.oid, ...) is still used")
	}
	d := norm(sqlIdDDL)
	for _, want := range []string{"has_database_privilege(x.oid, current_database(), 'CREATE')", "has_schema_privilege(x.oid, n.oid, 'CREATE')", "pg_has_role(current_user, c.relowner, 'MEMBER')"} {
		if !strings.Contains(d, want) {
			t.Errorf("ddl: %q missing", want)
		}
	}
	if strings.Contains(d, "'USAGE'") {
		t.Error("ddl: ownership is tested with USAGE (inherited only); it must use MEMBER")
	}
	if strings.Contains(norm(sqlIdParam), "has_parameter_privilege(current_user") {
		t.Error("param: must be evaluated per member role")
	}
}

// (c) predefined roles outside an explicit allow-list count as administration, so
// roles added by future PostgreSQL versions fail closed.
func TestIdentityAdminCoversPredefinedRolesOutsideTheAllowList(t *testing.T) {
	a := norm(sqlIdAdmin)
	if !strings.Contains(a, "x.rolname LIKE 'pg\\_%'") || !strings.Contains(a, "x.rolname NOT IN (") {
		t.Fatalf("admin query must treat unlisted pg_* roles as admin: %s", a)
	}
	for _, ok := range []string{"pg_read_all_data", "pg_read_all_settings", "pg_read_all_stats", "pg_stat_scan_tables", "pg_monitor", "pg_database_owner"} {
		if !strings.Contains(a, "'"+ok+"'") {
			t.Errorf("allow-list lacks %s", ok)
		}
	}
	for _, bad := range []string{"pg_write_server_files", "pg_execute_server_program", "pg_read_server_files", "pg_signal_backend", "pg_maintain", "pg_write_all_data"} {
		if strings.Contains(a, "'"+bad+"'") {
			t.Errorf("%s must not be allow-listed", bad)
		}
	}
}

// Every query stays fixed, parameterless and free of write/export primitives.
func TestIdentityQueriesStayFixedAndReadOnly(t *testing.T) {
	for name, q := range map[string]string{"write": sqlIdWrite, "ddl": sqlIdDDL, "admin": sqlIdAdmin, "super": sqlIdSuper, "ver": sqlIdVer, "param": sqlIdParam} {
		if strings.Contains(q, "$1") || strings.Contains(q, "%s") {
			t.Errorf("%s: parameterised or formatted SQL", name)
		}
		up := strings.ToUpper(q)
		for _, bad := range []string{"INSERT INTO", "UPDATE ", "DELETE FROM", "CREATE ", "DROP ", "ALTER ", "GRANT ", "SET ROLE", "COPY ", "PG_READ_FILE"} {
			if strings.Contains(up, bad) {
				t.Errorf("%s: contains %q", name, bad)
			}
		}
	}
}
