package postgres

import (
	"context"
	"errors"
	"strconv"
	"time"

	"audspect/agent/dbprobe"
)

// Fixed read-only catalog queries of check_readonly_identity (Task 16, client
// mode release gate). Each answers one question about the CONNECTED account
// (current_user). All are parameter-free and run in their own READ ONLY
// transaction. They are deliberately conservative: a privilege the account holds
// anywhere (any non-system schema or table, through any membership) counts, and
// anything that cannot be observed is reported unknown, never "no".
//
// NEVER RUN against a real server (fake-session and structure tests only); the
// semantics are UNVERIFIED until the dbsim_integration tests run on staging.
//
// Roles. Every question is asked for each role the account is a MEMBER of
// (pg_has_role(current_user, x.oid, 'MEMBER'), which includes the account itself),
// using the role-qualified forms such as has_table_privilege(x.oid, c.oid, ...).
// A NOINHERIT membership does not confer privileges automatically but the account
// can SET ROLE into it, so inherited-only checks (has_table_privilege(c.oid, ...),
// pg_has_role(..., 'USAGE')) would miss it.
//
//   - can_write: a member role that is a superuser or pg_write_all_data, or holds
//     INSERT, UPDATE, DELETE or TRUNCATE (table level) or INSERT/UPDATE (column
//     level) on any non-system table, partitioned table, VIEW or FOREIGN table
//     (views and foreign tables are write paths).
//   - can_ddl: a member role that is a superuser, has CREATE on the current
//     database or on any non-system schema, or the account owns (by MEMBER) any
//     non-system relation (an owner can ALTER and DROP it).
//   - can_admin: a member role that is a superuser or has CREATEROLE, CREATEDB,
//     BYPASSRLS or REPLICATION, or any predefined pg_* role OUTSIDE an explicit
//     allow-list of read-only ones (pg_read_all_data, pg_read_all_settings,
//     pg_read_all_stats, pg_stat_scan_tables, pg_monitor, pg_database_owner).
//     pg_write_server_files, pg_execute_server_program, pg_signal_backend,
//     pg_maintain and any role added by a future version therefore count: fail
//     closed.
//   - can_audit: a member role that is a superuser, or (PostgreSQL 15 and later)
//     holds SET on log_statement or pgaudit.log. Audit parameters are
//     superuser-only before 15; the version query selects the superuser-only answer.
//
// KNOWN GAPS (not examined): privileges on sequences, functions and procedures
// (a SECURITY DEFINER function can write on the caller's behalf), large objects,
// foreign data wrappers and servers, event triggers, languages and tablespaces;
// row-level security effects; column-level privileges other than INSERT/UPDATE;
// default privileges that will apply to future objects; and PostgreSQL before 15
// grants CREATE on the public schema to everyone by default, so can_ddl reports
// yes there (a conservative false FAIL).
const (
	sqlIdSystemNS = "n.nspname NOT IN ('pg_catalog','information_schema') " +
		"AND n.nspname NOT LIKE 'pg\\_toast%' AND n.nspname NOT LIKE 'pg\\_temp%'"

	sqlIdWrite = "SELECT EXISTS (SELECT 1 FROM pg_roles x WHERE pg_has_role(current_user, x.oid, 'MEMBER') AND (" +
		"x.rolsuper OR x.rolname = 'pg_write_all_data' OR EXISTS (" +
		"SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace " +
		"WHERE c.relkind IN ('r','p','v','f') AND " + sqlIdSystemNS + " AND (" +
		"has_table_privilege(x.oid, c.oid, 'INSERT') OR has_table_privilege(x.oid, c.oid, 'UPDATE') OR " +
		"has_table_privilege(x.oid, c.oid, 'DELETE') OR has_table_privilege(x.oid, c.oid, 'TRUNCATE') OR " +
		"has_any_column_privilege(x.oid, c.oid, 'INSERT') OR has_any_column_privilege(x.oid, c.oid, 'UPDATE')))))"
	sqlIdDDL = "SELECT EXISTS (SELECT 1 FROM pg_roles x WHERE pg_has_role(current_user, x.oid, 'MEMBER') AND (" +
		"x.rolsuper OR has_database_privilege(x.oid, current_database(), 'CREATE') OR EXISTS (" +
		"SELECT 1 FROM pg_namespace n WHERE " + sqlIdSystemNS + " AND has_schema_privilege(x.oid, n.oid, 'CREATE')))) " +
		"OR EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace " +
		"WHERE " + sqlIdSystemNS + " AND pg_has_role(current_user, c.relowner, 'MEMBER'))"
	sqlIdAdmin = "SELECT EXISTS (SELECT 1 FROM pg_roles x WHERE pg_has_role(current_user, x.oid, 'MEMBER') AND (" +
		"x.rolsuper OR x.rolcreaterole OR x.rolcreatedb OR x.rolbypassrls OR x.rolreplication OR (" +
		"x.rolname LIKE 'pg\\_%' AND x.rolname NOT IN ('pg_read_all_data','pg_read_all_settings'," +
		"'pg_read_all_stats','pg_stat_scan_tables','pg_monitor','pg_database_owner'))))"
	sqlIdSuper = "SELECT EXISTS (SELECT 1 FROM pg_roles x WHERE x.rolsuper AND pg_has_role(current_user, x.oid, 'MEMBER'))"
	sqlIdVer   = "SELECT current_setting('server_version_num')::int"
	sqlIdParam = "SELECT COALESCE(bool_or(has_parameter_privilege(x.oid, p, 'SET')), false) FROM pg_roles x, " +
		"unnest(ARRAY['log_statement','pgaudit.log']) AS p WHERE pg_has_role(current_user, x.oid, 'MEMBER')"
)

// pgParameterPrivilegeVersion is the first server version with
// has_parameter_privilege (PostgreSQL 15).
const pgParameterPrivilegeVersion = 150000

// runCheckReadOnlyIdentity answers the four identity questions. It is allowed in
// client mode and lab mode alike; it reads catalogs only.
func (a *Adapter) runCheckReadOnlyIdentity(ctx context.Context, spec dbprobe.DBProbeSpec, mode dbprobe.ExecMode) (dbprobe.ProbeResult, error) {
	var res dbprobe.ProbeResult
	if spec.FixtureID != "" {
		return res, errors.New("dbprobe/postgres: check_readonly_identity takes no fixture")
	}
	res.AgentTime = time.Now().UTC()
	res.Notes = append(res.Notes, a.notes...)
	q := func(sqlText string) ([][]any, error) {
		if a.broken {
			return nil, errors.New("connection closed")
		}
		return a.exportQuery(ctx, spec, mode, sqlText)
	}
	write := yesNo(q(sqlIdWrite))
	ddl := yesNo(q(sqlIdDDL))
	admin := yesNo(q(sqlIdAdmin))
	super := yesNo(q(sqlIdSuper))
	audit := super
	n, err := strconv.Atoi(countOf(q(sqlIdVer)))
	switch {
	case err != nil:
		// Without the version the parameter question cannot be chosen safely: a
		// held superuser answer still stands, anything else is unknown.
		if super != dbprobe.IdentityYes {
			audit = dbprobe.IdentityUnknown
		}
	case n >= pgParameterPrivilegeVersion:
		param := yesNo(q(sqlIdParam))
		switch {
		case super == dbprobe.IdentityYes || param == dbprobe.IdentityYes:
			audit = dbprobe.IdentityYes
		case super == dbprobe.IdentityNo && param == dbprobe.IdentityNo:
			audit = dbprobe.IdentityNo
		default:
			audit = dbprobe.IdentityUnknown
		}
	}
	res.Notes = append(res.Notes, dbprobe.IdentityChecksNote(write, ddl, admin, audit))
	res.ErrorClass = dbprobe.IdentityVerdict(write, ddl, admin, audit)
	return res, nil
}
