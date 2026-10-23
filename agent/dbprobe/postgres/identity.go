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
//   - can_write: superuser, membership in pg_write_all_data, or INSERT, UPDATE,
//     DELETE or TRUNCATE on any non-system table (table or column level).
//   - can_ddl: superuser, CREATE on the current database, CREATE on any non-system
//     schema, or ownership (by membership) of any non-system relation (an owner
//     can ALTER and DROP it).
//   - can_admin: membership (including the role itself) in any role that is a
//     superuser or has CREATEROLE, CREATEDB, BYPASSRLS or REPLICATION.
//   - can_audit: able to change an audit setting. Audit parameters (log_statement,
//     pgaudit.log) are superuser-only unless PostgreSQL 15 or later granted SET on
//     the parameter, so this is superuser membership, plus has_parameter_privilege
//     on 15 or later. On an older server the parameter function does not exist and
//     the version query selects the superuser-only answer.
//
// Not covered: privileges on sequences, functions and large objects are not
// examined; a role that can ALTER ROLE ... SET for audit parameters needs
// CREATEROLE or ownership, which can_admin and can_ddl already report.
const (
	sqlIdWrite = "SELECT (r.rolsuper OR CASE WHEN to_regrole('pg_write_all_data') IS NULL THEN false " +
		"ELSE pg_has_role(current_user, 'pg_write_all_data', 'MEMBER') END OR EXISTS (" +
		"SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace " +
		"WHERE c.relkind IN ('r','p') AND n.nspname NOT IN ('pg_catalog','information_schema') " +
		"AND n.nspname NOT LIKE 'pg\\_toast%' AND n.nspname NOT LIKE 'pg\\_temp%' AND (" +
		"has_table_privilege(c.oid, 'INSERT') OR has_table_privilege(c.oid, 'UPDATE') OR " +
		"has_table_privilege(c.oid, 'DELETE') OR has_table_privilege(c.oid, 'TRUNCATE') OR " +
		"has_any_column_privilege(c.oid, 'INSERT') OR has_any_column_privilege(c.oid, 'UPDATE')))) " +
		"FROM pg_roles r WHERE r.rolname = current_user"
	sqlIdDDL = "SELECT (r.rolsuper OR has_database_privilege(current_database(), 'CREATE') OR EXISTS (" +
		"SELECT 1 FROM pg_namespace n WHERE n.nspname NOT IN ('pg_catalog','information_schema') " +
		"AND n.nspname NOT LIKE 'pg\\_toast%' AND n.nspname NOT LIKE 'pg\\_temp%' " +
		"AND has_schema_privilege(n.oid, 'CREATE')) OR EXISTS (" +
		"SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace " +
		"WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg\\_toast%' " +
		"AND n.nspname NOT LIKE 'pg\\_temp%' AND pg_has_role(current_user, c.relowner, 'USAGE'))) " +
		"FROM pg_roles r WHERE r.rolname = current_user"
	sqlIdAdmin = "SELECT EXISTS (SELECT 1 FROM pg_roles x WHERE (x.rolsuper OR x.rolcreaterole OR x.rolcreatedb " +
		"OR x.rolbypassrls OR x.rolreplication) AND pg_has_role(current_user, x.oid, 'MEMBER'))"
	sqlIdSuper = "SELECT EXISTS (SELECT 1 FROM pg_roles x WHERE x.rolsuper AND pg_has_role(current_user, x.oid, 'MEMBER'))"
	sqlIdVer   = "SELECT current_setting('server_version_num')::int"
	sqlIdParam = "SELECT bool_or(has_parameter_privilege(current_user, p, 'SET')) FROM unnest(ARRAY['log_statement','pgaudit.log']) AS p"
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
