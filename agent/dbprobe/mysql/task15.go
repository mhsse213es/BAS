package mysql

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	drv "github.com/go-sql-driver/mysql"

	"audspect/agent/dbprobe"
)

// mysqlErrNumber returns the server error number carried by err, or 0.
func mysqlErrNumber(err error) uint16 {
	var me *drv.MySQLError
	if errors.As(err, &me) {
		return me.Number
	}
	return 0
}

// isAuditTamperDenied is the ONLY thing that counts as the server refusing the
// session-scoped audit change: error 1227 (ER_SPECIFIC_ACCESS_DENIED_ERROR, "you
// need SUPER or SYSTEM_VARIABLES_ADMIN"). Everything else (unknown variable,
// read-only variable, syntax, login denial, timeout, network, ...) is not.
func isAuditTamperDenied(err error) bool { return mysqlErrNumber(err) == 1227 }

// isWriteDenied recognises the write denials of a SELECT-only account: 1142
// (table), 1143 (column) and 1044 (database) access denied. Nothing else.
func isWriteDenied(err error) bool {
	switch mysqlErrNumber(err) {
	case 1142, 1143, 1044:
		return true
	}
	return false
}

// writeOutcome classifies the result of one write attempt.
func writeOutcome(err error) string {
	switch {
	case err == nil:
		return dbprobe.WriteAllowed
	case isWriteDenied(err):
		return dbprobe.WriteDenied
	}
	return dbprobe.WriteError
}

// createThrowaway creates the throwaway account and registers it in the adapter's
// undo record exactly as auth_after_revoke does (R-AL): tracked before the CREATE
// is sent, untracked only when the server definitively refused it. The password
// is hex (safe in a quoted literal; the statement cannot take parameters), joins
// the scrubber and is never returned, noted or logged.
func (a *Adapter) createThrowaway(ctx context.Context, lit, name, pw string) error {
	if err := a.refuseSecondAccount(); err != nil {
		return err
	}
	a.addSecret(pw)
	a.acct = acctState{name: name, mayExist: true}
	err := a.s.Exec(ctx, "CREATE USER "+lit+" IDENTIFIED BY '"+pw+"'")
	if err == nil {
		return nil
	}
	if mysqlErrNumber(err) != 0 {
		a.acct.mayExist = false // refused by the server: nothing was created
	}
	if isCtxErr(err) || ctx.Err() != nil {
		a.markBroken()
	}
	return err
}

// refuseSecondAccount stops a second throwaway-account probe on an adapter that
// still tracks one: overwriting the undo record (and clearing it when the second
// CREATE is refused as "exists") would orphan the first account. Nothing is sent.
func (a *Adapter) refuseSecondAccount() error {
	if a.acct.mayExist {
		return errors.New("dbprobe/mysql: the adapter already tracks a throwaway account; refusing a second create")
	}
	return nil
}

// labFixture checks the lab-mode and required-fixture preconditions shared by the
// fixture-bound Task 15 probes and returns the active fixture.
func (a *Adapter) labFixture(def dbprobe.ProbeDef, spec dbprobe.DBProbeSpec, mode dbprobe.ExecMode) (dbprobe.Fixture, error) {
	if mode != dbprobe.ModeLab {
		return dbprobe.Fixture{}, fmt.Errorf("dbprobe/mysql: %s refused outside lab mode", def.ID)
	}
	fx, err := a.Current()
	if err != nil {
		return dbprobe.Fixture{}, fmt.Errorf("dbprobe/mysql: %s needs the run's seeded fixture", def.ID)
	}
	if fx.Kind != def.RequiredFixture || spec.FixtureID != fx.Kind {
		return dbprobe.Fixture{}, errors.New("dbprobe/mysql: the active fixture is not the one this probe requires")
	}
	return fx, nil
}

// runTryDisableAudit is DB-08 (see the PostgreSQL adapter). The throwaway
// account has no privileges and dials with no default database (dialAs). Only
// error 1227 is a denial; if SET SESSION sql_log_off succeeds the connection is
// closed at once and nothing else is sent on it.
func (a *Adapter) runTryDisableAudit(ctx context.Context, def dbprobe.ProbeDef, spec dbprobe.DBProbeSpec, mode dbprobe.ExecMode) (dbprobe.ProbeResult, error) {
	var res dbprobe.ProbeResult
	fx, err := a.labFixture(def, spec, mode)
	if err != nil {
		return res, err
	}
	if err := a.refuseSecondAccount(); err != nil {
		return res, err
	}
	stmt, ok := dbprobe.AuditTamperStatement(engineName)
	if !ok {
		return res, errors.New("dbprobe/mysql: no audit statement for this engine")
	}
	name, err := dbprobe.ThrowawayAccountName(fx.ID)
	if err != nil {
		return res, err
	}
	lit, err := userLit(name)
	if err != nil {
		return res, err
	}
	pw, err := dbprobe.NewThrowawayPassword()
	if err != nil {
		return res, err
	}

	ctx, cancel := dbprobe.WithDeadline(ctx, spec.Limits)
	defer cancel()
	res.AgentTime = time.Now().UTC()
	res.Notes = append(res.Notes, a.notes...)

	create, baseline, attempt := dbprobe.TamperStepSkipped, dbprobe.TamperStepSkipped, dbprobe.TamperStepSkipped
	finish := func(class string) (dbprobe.ProbeResult, error) {
		res.ErrorClass = class
		res.Notes = append(res.Notes, dbprobe.AuditTamperStepsNote(create, baseline, attempt))
		return res, nil
	}
	detail := func(step string, err error) {
		res.Notes = append(res.Notes, "tamper_detail: "+step+": "+dbprobe.TruncateUTF8(a.wrap(step, err).Error(), 200))
	}

	if err := a.createThrowaway(ctx, lit, name, pw); err != nil {
		create = dbprobe.TamperStepFailed
		detail("create", err)
		return finish("account_create_failed")
	}
	create = dbprobe.TamperStepOK

	sess, err := a.dialAs(ctx, name, pw)
	if err == nil {
		var rows [][]any
		// F1: the baseline carries the meta tag, never the per-dispatch marker.
		rows, err = sess.Query(ctx, markerComment(metaMarker)+" "+sqlClock, 1)
		if err == nil && len(rows) == 1 && len(rows[0]) == 1 {
			res.DBTime = toTime(rows[0][0])
		}
	}
	if err != nil {
		closeSession(sess)
		baseline = dbprobe.TamperStepFailed
		detail("baseline", err)
		return finish("baseline_failed")
	}
	baseline = dbprobe.TamperStepOK

	aerr := sess.Exec(ctx, markerComment(spec.Marker)+" "+stmt)
	closeSession(sess)
	switch {
	case aerr == nil:
		attempt = dbprobe.TamperAttemptAllowed
		return finish("")
	case isAuditTamperDenied(aerr) && ctx.Err() == nil:
		attempt = dbprobe.TamperAttemptDenied
		res.Denied = true
		return finish("permission_denied")
	default:
		attempt = dbprobe.TamperAttemptError
		detail("attempt", aerr)
		return finish("attempt_error")
	}
}

// fingerprintSQL is the fixed state fingerprint of the fixture table, computed on
// the server (a row count and a sum of per-row CRC32): no row content reaches the
// wire. %s is the quoted fixture table.
const fingerprintSQL = "SELECT COUNT(*), COALESCE(SUM(CRC32(CONCAT_WS('|', id, synthetic, account_ref, display_name, email, balance_cents))), 0) FROM %s"

func (a *Adapter) fingerprint(ctx context.Context, table string) (string, error) {
	rows, err := a.s.Query(ctx, markerComment(metaMarker)+" "+fmt.Sprintf(fingerprintSQL, table), 1)
	if err != nil {
		if isCtxErr(err) || ctx.Err() != nil {
			a.markBroken() // uniform with create/grant: the connection is in an unknown state
		}
		return "", err
	}
	if len(rows) != 1 || len(rows[0]) != 2 {
		return "", errors.New("unexpected fingerprint shape")
	}
	return str(rows[0][0]) + "|" + str(rows[0][1]), nil
}

// runTryWriteFixture is DB-10 (see the PostgreSQL adapter). The account holds
// SELECT on the fixture schema only. It dials with no default database (dialAs)
// and every statement names the schema-qualified table; this is a deliberate
// choice over naming the fixture schema as the default database, because a
// default-schema mismatch is exactly what produced error 1044 for DB-06.
func (a *Adapter) runTryWriteFixture(ctx context.Context, def dbprobe.ProbeDef, spec dbprobe.DBProbeSpec, mode dbprobe.ExecMode) (dbprobe.ProbeResult, error) {
	var res dbprobe.ProbeResult
	fx, err := a.labFixture(def, spec, mode)
	if err != nil {
		return res, err
	}
	if err := a.refuseSecondAccount(); err != nil {
		return res, err
	}
	_, tbl, err := a.Resolve(dbprobe.WriteFixtureTable)
	if err != nil {
		return res, fmt.Errorf("dbprobe/mysql: %w", err)
	}
	schema, _, err := fixtureNames(fx.ID)
	if err != nil {
		return res, err
	}
	qschema, err := quoteIdent(schema)
	if err != nil {
		return res, err
	}
	qtbl, err := quoteTable(schema + "." + tbl.Name)
	if err != nil {
		return res, err
	}
	name, err := dbprobe.ThrowawayAccountName(fx.ID)
	if err != nil {
		return res, err
	}
	lit, err := userLit(name)
	if err != nil {
		return res, err
	}
	pw, err := dbprobe.NewThrowawayPassword()
	if err != nil {
		return res, err
	}

	ctx, cancel := dbprobe.WithDeadline(ctx, spec.Limits)
	defer cancel()
	res.AgentTime = time.Now().UTC()
	res.Notes = append(res.Notes, a.notes...)

	ins, upd, del, fp := dbprobe.WriteSkipped, dbprobe.WriteSkipped, dbprobe.WriteSkipped, dbprobe.FingerprintSkipped
	finish := func(class string) (dbprobe.ProbeResult, error) {
		res.ErrorClass = class
		res.Notes = append(res.Notes, dbprobe.WriteAttemptStepsNote(ins, upd, del, fp))
		return res, nil
	}
	detail := func(step string, err error) {
		res.Notes = append(res.Notes, "write_detail: "+step+": "+dbprobe.TruncateUTF8(a.wrap(step, err).Error(), 200))
	}

	if err := a.createThrowaway(ctx, lit, name, pw); err != nil {
		detail("create", err)
		return finish("account_create_failed")
	}
	// F2: _ and % are wildcards in a database-level GRANT even inside backticks, so
	// they are escaped here only (the schema name is otherwise validated by
	// fixtureNames/quoteIdent and is dbsim_<hex id>).
	gschema := strings.NewReplacer("_", `\_`, "%", `\%`).Replace(qschema)
	if err := a.s.Exec(ctx, "GRANT SELECT ON "+gschema+".* TO "+lit); err != nil {
		if isCtxErr(err) || ctx.Err() != nil {
			a.markBroken()
		}
		detail("grant", err)
		return finish("grant_failed")
	}

	before, err := a.fingerprint(ctx, qtbl)
	if err != nil {
		fp = dbprobe.FingerprintError
		detail("fingerprint_before", err)
		return finish("fingerprint_failed")
	}

	sess, err := a.dialAs(ctx, name, pw)
	if err == nil {
		var rows [][]any
		rows, err = sess.Query(ctx, markerComment(metaMarker)+" SELECT UTC_TIMESTAMP(6), COUNT(*) FROM "+qtbl, 1)
		if err == nil && len(rows) == 1 && len(rows[0]) >= 1 {
			res.DBTime = toTime(rows[0][0])
		}
	}
	if err != nil {
		closeSession(sess)
		detail("baseline", err)
		return finish("baseline_failed")
	}

	mc := markerComment(spec.Marker) + " "
	ins = writeOutcome(sess.Exec(ctx, mc+fmt.Sprintf(dbprobe.WriteInsertSQL, qtbl)))
	upd = writeOutcome(sess.Exec(ctx, mc+fmt.Sprintf(dbprobe.WriteUpdateSQL, qtbl)))
	del = writeOutcome(sess.Exec(ctx, mc+fmt.Sprintf(dbprobe.WriteDeleteSQL, qtbl)))
	closeSession(sess)
	outcomes := []string{ins, upd, del}

	after, ferr := a.fingerprint(ctx, qtbl)
	switch {
	case ferr != nil:
		fp = dbprobe.FingerprintError
		detail("fingerprint_after", ferr)
	case after == before:
		fp = dbprobe.FingerprintUnchanged
	default:
		fp = dbprobe.FingerprintChanged
	}

	anyOf := func(v string) bool {
		for _, o := range outcomes {
			if o == v {
				return true
			}
		}
		return false
	}
	switch {
	case anyOf(dbprobe.WriteAllowed):
		res.Notes = append(res.Notes, dbprobe.WriteFixtureChangedKey+"=true")
		return finish("")
	case anyOf(dbprobe.WriteError):
		return finish("attempt_error")
	case fp == dbprobe.FingerprintError:
		return finish("fingerprint_failed")
	case fp == dbprobe.FingerprintChanged:
		return finish("fixture_state_inconsistent")
	}
	res.Denied = true
	return finish("permission_denied")
}

// Fixed read-only catalog queries of check_export_privileges (DB-11).
//
//   - privileges: the GLOBAL privileges of the connected account from
//     information_schema.USER_PRIVILEGES, matched on its exact 'user'@'host'
//     grantee (user = everything before the last '@'). A real account always has
//     at least a USAGE row, so zero rows means the match failed and the answer is
//     unknown, never "holds nothing".
//   - CURRENT_ROLE(): privileges that arrive through an active role are not
//     visible in USER_PRIVILEGES; with an active role the privilege checks are
//     reported unknown. MySQL 5.7 has no roles (the function is error 1305).
//   - FILE is the single server-file privilege: it covers both reading and writing
//     server files, so file_write and file_read both derive from it. MySQL has no
//     server-side program-execution grant, so program_exec is reported "na".
//   - dump_privs: a count of the non-system tables visible to the account in
//     information_schema.TABLES (visibility requires a privilege on the table); an
//     approximation of the tables it could dump, count only.
const (
	sqlExportPrivileges = "SELECT PRIVILEGE_TYPE FROM information_schema.USER_PRIVILEGES WHERE GRANTEE = CONCAT(" +
		"'''', LEFT(CURRENT_USER(), CHAR_LENGTH(CURRENT_USER()) - CHAR_LENGTH(SUBSTRING_INDEX(CURRENT_USER(), '@', -1)) - 1), " +
		"'''@''', SUBSTRING_INDEX(CURRENT_USER(), '@', -1), '''')"
	sqlExportRole     = "SELECT CURRENT_ROLE()"
	sqlExportSecure   = "SELECT @@GLOBAL.secure_file_priv"
	sqlExportDumpable = "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA NOT IN ('mysql','sys','information_schema','performance_schema') " +
		"AND TABLE_TYPE IN ('BASE TABLE','VIEW')"
)

const maxExportPrivRows = 200

func (a *Adapter) exportQuery(ctx context.Context, spec dbprobe.DBProbeSpec, mode dbprobe.ExecMode, sqlText string, maxRows int) ([][]any, error) {
	var rows [][]any
	err := a.inTxn(ctx, mode, dbprobe.ClassReadOnly, spec.Limits, spec.Marker, func(ctx context.Context, comment string) error {
		var qerr error
		rows, qerr = a.s.Query(ctx, comment+sqlText, maxRows)
		return qerr
	})
	return rows, err
}

// runCheckExportPrivileges is DB-11: fixed read-only catalog queries about the
// connected account's export/backup capability. No export is performed.
func (a *Adapter) runCheckExportPrivileges(ctx context.Context, spec dbprobe.DBProbeSpec, mode dbprobe.ExecMode) (dbprobe.ProbeResult, error) {
	var res dbprobe.ProbeResult
	if mode != dbprobe.ModeLab {
		return res, errors.New("dbprobe/mysql: check_export_privileges refused outside lab mode")
	}
	res.AgentTime = time.Now().UTC()
	res.Notes = append(res.Notes, a.notes...)
	q := func(sqlText string, maxRows int) ([][]any, error) {
		if a.broken {
			return nil, errors.New("connection closed")
		}
		return a.exportQuery(ctx, spec, mode, sqlText, maxRows)
	}

	// Roles first: an active role hides privileges from USER_PRIVILEGES.
	rolesKnown, rolesActive := false, false
	if rows, err := q(sqlExportRole, 1); err == nil && len(rows) == 1 && len(rows[0]) == 1 {
		rolesKnown = true
		r := strings.TrimSpace(str(rows[0][0]))
		rolesActive = r != "" && !strings.EqualFold(r, "NONE")
	} else if mysqlErrNumber(err) == 1305 {
		rolesKnown = true // 5.7: no roles exist
	}

	fw, pe, fr, bulk := dbprobe.ExportUnknown, dbprobe.ExportNA, dbprobe.ExportUnknown, dbprobe.ExportUnknown
	reload, lock := dbprobe.ExportUnknown, dbprobe.ExportUnknown
	if rolesKnown && !rolesActive {
		if rows, err := q(sqlExportPrivileges, maxExportPrivRows); err == nil && len(rows) > 0 && len(rows) < maxExportPrivRows {
			held := map[string]bool{}
			for _, r := range rows {
				if len(r) == 1 {
					held[strings.ToUpper(strings.TrimSpace(str(r[0])))] = true
				}
			}
			yn := func(p string) string {
				if held[p] {
					return dbprobe.ExportYes
				}
				return dbprobe.ExportNo
			}
			fw, fr, bulk = yn("FILE"), yn("FILE"), yn("SELECT")
			reload, lock = yn("RELOAD"), yn("LOCK TABLES")
		}
	}
	dump := dbprobe.ExportUnknown
	if rows, err := q(sqlExportDumpable, 1); err == nil && len(rows) == 1 && len(rows[0]) == 1 {
		var n int64
		if _, serr := fmt.Sscan(str(rows[0][0]), &n); serr == nil {
			dump = dbprobe.ExportCount(n)
		}
	}
	sfp := dbprobe.ExportUnknown
	if rows, err := q(sqlExportSecure, 1); err == nil && len(rows) == 1 && len(rows[0]) == 1 {
		switch v := rows[0][0]; {
		case v == nil:
			sfp = "null" // import/export disabled
		case strings.TrimSpace(str(v)) == "":
			sfp = "empty" // unrestricted
		default:
			sfp = "path" // restricted to a directory
		}
	}
	res.Notes = append(res.Notes, dbprobe.ExportChecksNote(fw, pe, fr, bulk, dump))
	res.Notes = append(res.Notes, "export_context=reload="+reload+",lock_tables="+lock+",secure_file_priv="+sfp)
	res.ErrorClass, res.Denied = dbprobe.ExportVerdict(fw, pe, fr, bulk, dump)
	return res, nil
}
