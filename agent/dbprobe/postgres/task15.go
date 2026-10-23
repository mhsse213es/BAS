package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"audspect/agent/dbprobe"
)

// isPermissionDenied is the ONLY thing that counts as the server refusing a
// statement for lack of privilege: SQLSTATE 42501 (insufficient_privilege).
// Every other failure (unknown parameter, syntax, auth, read-only transaction,
// undefined table, timeout, network, ...) is not evidence of a denial.
func isPermissionDenied(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "42501"
}

// writeOutcome classifies the result of one write attempt.
func writeOutcome(err error) string {
	switch {
	case err == nil:
		return dbprobe.WriteAllowed
	case isPermissionDenied(err):
		return dbprobe.WriteDenied
	}
	return dbprobe.WriteError
}

// createThrowaway creates the throwaway LOGIN role and registers it in the
// adapter's undo record (R-AL): tracking is set before the CREATE is sent, so a
// lost acknowledgement is still cleaned up, and cleared only when the server
// definitively refused it (this call then created nothing and must never drop
// the name). The password is hex, so splicing it into the literal cannot break
// out; the statement cannot take bound parameters. The password joins the
// redaction set and is never returned, noted or logged.
func (a *Adapter) createThrowaway(ctx context.Context, name, pw string) error {
	if err := a.refuseSecondAccount(); err != nil {
		return err
	}
	a.secrets = append(a.secrets, pw)
	a.acct = acctState{name: name, mayExist: true}
	err := a.s.Exec(ctx, "CREATE ROLE "+pgx.Identifier{name}.Sanitize()+" LOGIN PASSWORD '"+pw+"'")
	if err == nil {
		return nil
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
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
		return errors.New("dbprobe/postgres: the adapter already tracks a throwaway account; refusing a second create")
	}
	return nil
}

// labFixture checks the lab-mode and required-fixture preconditions shared by the
// fixture-bound Task 15 probes and returns the active fixture.
func (a *Adapter) labFixture(def dbprobe.ProbeDef, spec dbprobe.DBProbeSpec, mode dbprobe.ExecMode) (dbprobe.Fixture, error) {
	if mode != dbprobe.ModeLab {
		return dbprobe.Fixture{}, fmt.Errorf("dbprobe/postgres: %s refused outside lab mode", def.ID)
	}
	fx, err := a.Current()
	if err != nil {
		return dbprobe.Fixture{}, fmt.Errorf("dbprobe/postgres: %s needs the run's seeded fixture", def.ID)
	}
	if fx.Kind != def.RequiredFixture || spec.FixtureID != fx.Kind {
		return dbprobe.Fixture{}, errors.New("dbprobe/postgres: the active fixture is not the one this probe requires")
	}
	return fx, nil
}

// runTryDisableAudit is DB-08. A throwaway account with NO privileges opens a NEW
// connection, proves it works (baseline), then attempts the one fixed
// SESSION-scoped audit statement, tagged with the marker. A denial is recognised
// only by SQLSTATE 42501. If the statement succeeds the connection is closed at
// once (the change is session scoped, so there is nothing to restore) and
// nothing else is sent on it. No statement here can change global or persistent
// state: see dbprobe.AuditTamperStatements.
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
		return res, errors.New("dbprobe/postgres: no audit statement for this engine")
	}
	name, err := dbprobe.ThrowawayAccountName(fx.ID)
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
		res.Notes = append(res.Notes, "tamper_detail: "+step+": "+dbprobe.TruncateUTF8(redact(err.Error(), a.secrets...), 200))
	}

	if err := a.createThrowaway(ctx, name, pw); err != nil {
		create = dbprobe.TamperStepFailed
		detail("create", err)
		return finish("account_create_failed")
	}
	create = dbprobe.TamperStepOK

	// BASELINE: a NEW connection as the account logs in and runs one tagged
	// statement. A failed login is baseline_failed, never a denial.
	sess, err := a.dialAs(ctx, name, pw)
	if err == nil {
		var rows [][]any
		// F1: the baseline carries the meta tag, never the per-dispatch marker, so
		// only the attempt statement can be credited as detected.
		rows, err = sess.Query(ctx, markerComment(metaMarker)+" "+sqlClock, 1)
		if err == nil && len(rows) == 1 && len(rows[0]) == 1 {
			if t, ok := rows[0][0].(time.Time); ok {
				res.DBTime = t.UTC()
			}
		}
	}
	if err != nil {
		closeSession(sess)
		baseline = dbprobe.TamperStepFailed
		detail("baseline", err)
		return finish("baseline_failed")
	}
	baseline = dbprobe.TamperStepOK

	// ATTEMPT: the one fixed session-scoped statement; the connection is closed
	// right after it whatever the outcome.
	aerr := sess.Exec(ctx, markerComment(spec.Marker)+" "+stmt)
	closeSession(sess)
	switch {
	case aerr == nil:
		attempt = dbprobe.TamperAttemptAllowed
		return finish("") // Allowed: the account can tamper with audit for its own session
	case isPermissionDenied(aerr) && ctx.Err() == nil:
		attempt = dbprobe.TamperAttemptDenied
		res.Denied = true
		return finish("permission_denied")
	default:
		attempt = dbprobe.TamperAttemptError // never read as a denial
		detail("attempt", aerr)
		return finish("attempt_error")
	}
}

// fingerprintSQL is the fixed state fingerprint of the fixture table, computed
// on the server (a row count and an md5 over the ordered text form of every
// row): no row content reaches the wire. %s is the quoted fixture table.
const fingerprintSQL = "SELECT count(*)::text, COALESCE(md5(string_agg(t::text, '|' ORDER BY t.id)), '') FROM %s AS t"

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

// runTryWriteFixture is DB-10. A throwaway account holding SELECT only on the
// fixture's accounts table attempts one INSERT, UPDATE and DELETE (fixed
// statements, adapter-resolved table, marker-tagged). The table state is
// fingerprinted through the LAB connection before and after.
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
		return res, fmt.Errorf("dbprobe/postgres: %w", err)
	}
	schema, _, err := fixtureNames(fx.ID)
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
	pw, err := dbprobe.NewThrowawayPassword()
	if err != nil {
		return res, err
	}
	qn := pgx.Identifier{name}.Sanitize()

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
		res.Notes = append(res.Notes, "write_detail: "+step+": "+dbprobe.TruncateUTF8(redact(err.Error(), a.secrets...), 200))
	}

	// 1. The throwaway account, SELECT only on the fixture table (and USAGE on the
	// fixture schema so that SELECT is reachable). No write privilege is granted.
	if err := a.createThrowaway(ctx, name, pw); err != nil {
		detail("create", err)
		return finish("account_create_failed")
	}
	for _, g := range []string{
		"GRANT USAGE ON SCHEMA " + pgx.Identifier{schema}.Sanitize() + " TO " + qn,
		"GRANT SELECT ON " + qtbl + " TO " + qn,
	} {
		if err := a.s.Exec(ctx, g); err != nil {
			if isCtxErr(err) || ctx.Err() != nil {
				a.markBroken()
			}
			detail("grant", err)
			return finish("grant_failed")
		}
	}

	// 2. Fingerprint BEFORE, through the lab connection.
	before, err := a.fingerprint(ctx, qtbl)
	if err != nil {
		fp = dbprobe.FingerprintError
		detail("fingerprint_before", err)
		return finish("fingerprint_failed")
	}

	// 3. BASELINE: the account logs in on a NEW connection and can read the table
	// (so a later denial of writes is about writes, not about a dead login).
	sess, err := a.dialAs(ctx, name, pw)
	if err == nil {
		var rows [][]any
		rows, err = sess.Query(ctx, markerComment(metaMarker)+" SELECT clock_timestamp(), count(*) FROM "+qtbl, 1)
		if err == nil && len(rows) == 1 && len(rows[0]) >= 1 {
			if t, ok := rows[0][0].(time.Time); ok {
				res.DBTime = t.UTC()
			}
		}
	}
	if err != nil {
		closeSession(sess)
		detail("baseline", err)
		return finish("baseline_failed")
	}

	// 4. The three write attempts, in order, on the throwaway session.
	mc := markerComment(spec.Marker) + " "
	ins = writeOutcome(sess.Exec(ctx, mc+fmt.Sprintf(dbprobe.WriteInsertSQL, qtbl)))
	upd = writeOutcome(sess.Exec(ctx, mc+fmt.Sprintf(dbprobe.WriteUpdateSQL, qtbl)))
	del = writeOutcome(sess.Exec(ctx, mc+fmt.Sprintf(dbprobe.WriteDeleteSQL, qtbl)))
	closeSession(sess)
	outcomes := []string{ins, upd, del}

	// 5. Fingerprint AFTER, through the lab connection.
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
		// A write was accepted: a real finding, and the fixture is dirty.
		res.Notes = append(res.Notes, dbprobe.WriteFixtureChangedKey+"=true")
		return finish("")
	case anyOf(dbprobe.WriteError):
		return finish("attempt_error")
	case fp == dbprobe.FingerprintError:
		return finish("fingerprint_failed")
	case fp == dbprobe.FingerprintChanged:
		// Every attempt reported denied yet the table moved: the evidence
		// contradicts itself, so this is never a pass.
		return finish("fixture_state_inconsistent")
	}
	res.Denied = true
	return finish("permission_denied")
}

// Fixed read-only catalog queries of check_export_privileges (DB-11). Each answers
// one question about the CONNECTED account; superuser implies every one of the
// server-file/program capabilities (it can use pg_read_file, COPY ... PROGRAM,
// ...), and membership is tested with MEMBER (conservative: it includes a
// non-inherited membership the account could SET ROLE into). to_regrole guards
// roles that do not exist on older servers. Replication is folded into
// bulk_select: a replication-capable role can take a full base backup.
const (
	sqlExportFileWrite = "SELECT (r.rolsuper OR CASE WHEN to_regrole('pg_write_server_files') IS NULL THEN false " +
		"ELSE pg_has_role(current_user, 'pg_write_server_files', 'MEMBER') END) FROM pg_roles r WHERE r.rolname = current_user"
	sqlExportProgramExec = "SELECT (r.rolsuper OR CASE WHEN to_regrole('pg_execute_server_program') IS NULL THEN false " +
		"ELSE pg_has_role(current_user, 'pg_execute_server_program', 'MEMBER') END) FROM pg_roles r WHERE r.rolname = current_user"
	sqlExportFileRead = "SELECT (r.rolsuper OR CASE WHEN to_regrole('pg_read_server_files') IS NULL THEN false " +
		"ELSE pg_has_role(current_user, 'pg_read_server_files', 'MEMBER') END) FROM pg_roles r WHERE r.rolname = current_user"
	sqlExportBulkSelect = "SELECT (r.rolsuper OR r.rolreplication OR CASE WHEN to_regrole('pg_read_all_data') IS NULL THEN false " +
		"ELSE pg_has_role(current_user, 'pg_read_all_data', 'MEMBER') END) FROM pg_roles r WHERE r.rolname = current_user"
	// dump_privs: a count of the non-system tables the account may SELECT (the
	// "can dump" indicator). A count only; no table name is read.
	sqlExportDumpPrivs = "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace " +
		"WHERE c.relkind IN ('r','p','m','v') AND n.nspname NOT IN ('pg_catalog','information_schema') " +
		"AND n.nspname NOT LIKE 'pg\\_toast%' AND n.nspname NOT LIKE 'pg\\_temp%' AND has_table_privilege(c.oid, 'SELECT')"
)

// exportQuery runs one fixed catalog query in its own READ ONLY transaction (a
// failed statement would otherwise abort a shared one).
func (a *Adapter) exportQuery(ctx context.Context, spec dbprobe.DBProbeSpec, mode dbprobe.ExecMode, sql string) ([][]any, error) {
	var rows [][]any
	err := a.inTxn(ctx, mode, dbprobe.ClassReadOnly, spec.Limits, spec.Marker, func(ctx context.Context, comment string) error {
		var qerr error
		rows, qerr = a.s.Query(ctx, comment+sql, 2)
		return qerr
	})
	return rows, err
}

func yesNo(rows [][]any, err error) string {
	if err != nil || len(rows) != 1 || len(rows[0]) != 1 {
		return dbprobe.ExportUnknown
	}
	b, ok := rows[0][0].(bool)
	switch {
	case !ok:
		return dbprobe.ExportUnknown
	case b:
		return dbprobe.ExportYes
	}
	return dbprobe.ExportNo
}

func countOf(rows [][]any, err error) string {
	if err != nil || len(rows) != 1 || len(rows[0]) != 1 {
		return dbprobe.ExportUnknown
	}
	switch v := rows[0][0].(type) {
	case int64:
		return dbprobe.ExportCount(v)
	case int32:
		return dbprobe.ExportCount(int64(v))
	case int:
		return dbprobe.ExportCount(int64(v))
	}
	return dbprobe.ExportUnknown
}

// runCheckExportPrivileges is DB-11: fixed read-only catalog queries about the
// connected account's export/backup capability. No export is performed.
func (a *Adapter) runCheckExportPrivileges(ctx context.Context, spec dbprobe.DBProbeSpec, mode dbprobe.ExecMode) (dbprobe.ProbeResult, error) {
	var res dbprobe.ProbeResult
	if mode != dbprobe.ModeLab {
		return res, errors.New("dbprobe/postgres: check_export_privileges refused outside lab mode")
	}
	res.AgentTime = time.Now().UTC()
	res.Notes = append(res.Notes, a.notes...)
	q := func(sql string) ([][]any, error) {
		if a.broken {
			return nil, errors.New("connection closed")
		}
		return a.exportQuery(ctx, spec, mode, sql)
	}
	fw := yesNo(q(sqlExportFileWrite))
	pe := yesNo(q(sqlExportProgramExec))
	fr := yesNo(q(sqlExportFileRead))
	bulk := yesNo(q(sqlExportBulkSelect))
	dump := countOf(q(sqlExportDumpPrivs))
	res.Notes = append(res.Notes, dbprobe.ExportChecksNote(fw, pe, fr, bulk, dump))
	res.ErrorClass, res.Denied = dbprobe.ExportVerdict(fw, pe, fr, bulk, dump)
	return res, nil
}
