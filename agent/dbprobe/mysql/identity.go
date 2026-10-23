package mysql

import (
	"context"
	"errors"
	"strings"
	"time"

	"audspect/agent/dbprobe"
)

// check_readonly_identity (Task 16, client mode release gate) reads the
// CONNECTED account's privileges from information_schema in one fixed,
// parameter-free query per scope and classifies them with
// dbprobe.ClassifyMySQLPrivileges.
//
//   - The grantee is matched on its exact 'user'@'host' form (user = everything
//     before the last '@'), as check_export_privileges does. A real account always
//     has at least a USAGE row, so zero rows means the match failed and every
//     answer is unknown, never "holds nothing".
//   - CURRENT_ROLE(): privileges that arrive through an active role are invisible
//     in these views, so an active role makes every answer unknown. MySQL 5.7 has
//     no roles (the function is error 1305), which means no role is active.
//   - information_schema.APPLICABLE_ROLES (8.0) lists roles GRANTED to the account
//     whether or not active. Any row means unknown for every answer the roles
//     could change (a definite "yes" from the direct privileges survives). The
//     table not existing (error 1109, MySQL 5.7) is a clean "no roles"; ANY other
//     error reading it is unknown, never "no roles".
//   - GRANT OPTION is not a PRIVILEGE_TYPE row; it is IS_GRANTABLE='YES' on
//     another row, so IS_GRANTABLE is selected and any YES means admin.
//   - EXECUTE makes can_write unknown (SECURITY DEFINER routines can write).
//   - A privilege list that reaches maxIdentityPrivRows is treated as truncated
//     and proves nothing (unknown).
//
// Not covered: column-level SELECT detail, PROXY grants (mysql.proxies_priv) and
// the reach of PROCESS. Schema names containing '_' or '%' are wildcards in
// SCHEMA_PRIVILEGES, so can_ddl/can_audit report yes for them (a conservative
// false FAIL). NEVER RUN against a real server: UNVERIFIED until the
// dbsim_integration tests run on staging.
const (
	idGrantee = "CONCAT('''', LEFT(CURRENT_USER(), CHAR_LENGTH(CURRENT_USER()) - CHAR_LENGTH(SUBSTRING_INDEX(CURRENT_USER(), '@', -1)) - 1), " +
		"'''@''', SUBSTRING_INDEX(CURRENT_USER(), '@', -1), '''')"
	sqlIdPrivileges = "SELECT 'G', '', PRIVILEGE_TYPE, IS_GRANTABLE FROM information_schema.USER_PRIVILEGES WHERE GRANTEE = " + idGrantee +
		" UNION ALL SELECT 'S', TABLE_SCHEMA, PRIVILEGE_TYPE, IS_GRANTABLE FROM information_schema.SCHEMA_PRIVILEGES WHERE GRANTEE = " + idGrantee +
		" UNION ALL SELECT 'T', TABLE_SCHEMA, PRIVILEGE_TYPE, IS_GRANTABLE FROM information_schema.TABLE_PRIVILEGES WHERE GRANTEE = " + idGrantee +
		" UNION ALL SELECT 'C', TABLE_SCHEMA, PRIVILEGE_TYPE, IS_GRANTABLE FROM information_schema.COLUMN_PRIVILEGES WHERE GRANTEE = " + idGrantee
	// Roles granted to the account, active or not: SET ROLE can activate any of them.
	sqlIdApplicableRoles = "SELECT ROLE_NAME FROM information_schema.APPLICABLE_ROLES"
)

const maxIdentityPrivRows = 500

func (a *Adapter) runCheckReadOnlyIdentity(ctx context.Context, spec dbprobe.DBProbeSpec, mode dbprobe.ExecMode) (dbprobe.ProbeResult, error) {
	var res dbprobe.ProbeResult
	if spec.FixtureID != "" {
		return res, errors.New("dbprobe/mysql: check_readonly_identity takes no fixture")
	}
	res.AgentTime = time.Now().UTC()
	res.Notes = append(res.Notes, a.notes...)
	q := func(sqlText string, maxRows int) ([][]any, error) {
		if a.broken {
			return nil, errors.New("connection closed")
		}
		return a.exportQuery(ctx, spec, mode, sqlText, maxRows)
	}

	rolesKnown, rolesActive := false, false
	if rows, err := q(sqlExportRole, 1); err == nil && len(rows) == 1 && len(rows[0]) == 1 {
		rolesKnown = true
		r := strings.TrimSpace(str(rows[0][0]))
		rolesActive = r != "" && !strings.EqualFold(r, "NONE")
	} else if mysqlErrNumber(err) == 1305 {
		rolesKnown = true // 5.7: no roles exist
	}

	// Granted (not necessarily active) roles can be activated with SET ROLE.
	grantedRoles := false
	if rolesKnown && !rolesActive {
		rows, err := q(sqlIdApplicableRoles, maxIdentityPrivRows)
		switch {
		case err == nil:
			grantedRoles = len(rows) > 0
		case mysqlErrNumber(err) == 1109: // table absent: MySQL 5.7, no roles
		default:
			rolesKnown = false // cannot tell: unknown, never "no roles"
		}
	}

	write, ddl, admin, audit := dbprobe.IdentityUnknown, dbprobe.IdentityUnknown, dbprobe.IdentityUnknown, dbprobe.IdentityUnknown
	if rolesKnown && !rolesActive {
		if rows, err := q(sqlIdPrivileges, maxIdentityPrivRows); err == nil && len(rows) < maxIdentityPrivRows {
			priv := make([]dbprobe.PrivRow, 0, len(rows))
			wellFormed := true
			for _, r := range rows {
				if len(r) != 4 {
					wellFormed = false
					break
				}
				priv = append(priv, dbprobe.PrivRow{Scope: str(r[0]), Schema: str(r[1]), Privilege: str(r[2]), Grantable: str(r[3])})
			}
			if wellFormed {
				write, ddl, admin, audit = dbprobe.ClassifyMySQLPrivileges(priv)
				if grantedRoles {
					for _, p := range []*string{&write, &ddl, &admin, &audit} {
						if *p == dbprobe.IdentityNo {
							*p = dbprobe.IdentityUnknown
						}
					}
				}
			}
		}
	}
	res.Notes = append(res.Notes, dbprobe.IdentityChecksNote(write, ddl, admin, audit))
	res.ErrorClass = dbprobe.IdentityVerdict(write, ddl, admin, audit)
	return res, nil
}
