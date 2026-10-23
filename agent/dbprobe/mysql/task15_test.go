package mysql

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"audspect/agent/dbprobe"
)

func execSession(d *dialScript, queryFn func(string, []any) ([][]any, error), execFn func(string) error) func() (session, error) {
	return func() (session, error) {
		s := &fakeSession{queryFn: queryFn, execFn: execFn}
		d.sess = append(d.sess, s)
		return s, nil
	}
}

func hasPrefixCall(f *fakeSession, p string) bool {
	_, ok := findPrefix(f, p)
	return ok
}

// ---- DB-08 try_disable_audit ---------------------------------------------

func tamperSpec() dbprobe.DBProbeSpec {
	s := spec(dbprobe.ProbeTryDisableAudit, dbprobe.ModeLab, nil)
	s.FixtureID = "empty"
	return s
}

func TestTryDisableAuditDenied1227(t *testing.T) {
	d := &dialScript{}
	d.steps = []func() (session, error){execSession(d, clockQuery, func(sql string) error {
		if strings.Contains(sql, "sql_log_off") {
			return myErr(1227, "Access denied; you need (at least one of) the SUPER or SYSTEM_VARIABLES_ADMIN privilege(s)")
		}
		return nil
	})}
	a, admin := revokeAdapter(t, d)
	res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeTryDisableAudit), tamperSpec())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Denied || res.ErrorClass != "permission_denied" {
		t.Fatalf("1227 is the denial: %+v", res)
	}
	if !hasNote(res.Notes, "audit_tamper_steps=create=ok,baseline=ok,attempt=denied") {
		t.Fatalf("typed note: %v", res.Notes)
	}
	if len(d.users) != 1 || d.users[0] != revokeAcct || d.dbs[0] != "" {
		t.Fatalf("one NEW connection as the privilege-less account with NO default database: users=%v dbs=%v", d.users, d.dbs)
	}
	sess := d.sess[0]
	var attempts []string
	for _, c := range sess.calls {
		if strings.Contains(c.sql, "sql_log_off") {
			attempts = append(attempts, c.sql)
		}
	}
	if len(attempts) != 1 || attempts[0] != "/* dbsim:dbsim-abc123 */ SET SESSION sql_log_off = 1" {
		t.Fatalf("the marker rides on the attempt statement: %q", attempts)
	}
	if !sess.closed {
		t.Fatal("throwaway connection must be closed")
	}
	for _, s := range execSQL(admin) {
		if strings.Contains(s, "sql_log_off") {
			t.Fatalf("the lab connection ran %q", s)
		}
	}
}

func TestTryDisableAuditSuccessIsAllowedAndClosesImmediately(t *testing.T) {
	d := &dialScript{}
	d.steps = []func() (session, error){d.okSession(clockQuery)}
	a, _ := revokeAdapter(t, d)
	res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeTryDisableAudit), tamperSpec())
	if err != nil {
		t.Fatal(err)
	}
	if res.Denied || res.ErrorClass != "" || !hasNote(res.Notes, "audit_tamper_steps=create=ok,baseline=ok,attempt=allowed") {
		t.Fatalf("%+v %v", res, res.Notes)
	}
	calls := execSQL(d.sess[0])
	if !d.sess[0].closed || !strings.Contains(calls[len(calls)-1], "SET SESSION sql_log_off = 1") {
		t.Fatalf("nothing may follow the successful SET and the connection must close: %v", calls)
	}
}

func TestTryDisableAuditOnlyExactDenialCodeIsBlocked(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
	}{
		{"unknown variable", myErr(1193, "Unknown system variable")},
		{"read only variable", myErr(1238, "Variable is a read only variable")},
		{"syntax", myErr(1064, "syntax error")},
		{"table denied", myErr(1142, "denied")},
		{"db denied", myErr(1044, "denied")},
		{"access denied login", myErr(1045, "Access denied")},
		{"query timeout", myErr(3024, "timeout")},
		{"generic", errors.New("invalid connection")},
		{"deadline", context.DeadlineExceeded},
	} {
		d := &dialScript{}
		err := c.err
		d.steps = []func() (session, error){execSession(d, clockQuery, func(sql string) error {
			if strings.Contains(sql, "sql_log_off") {
				return err
			}
			return nil
		})}
		a, _ := revokeAdapter(t, d)
		res, rerr := a.RunProbe(context.Background(), def(dbprobe.ProbeTryDisableAudit), tamperSpec())
		if rerr != nil {
			t.Fatalf("%s: %v", c.name, rerr)
		}
		if res.Denied || res.ErrorClass != "attempt_error" || !hasNote(res.Notes, "audit_tamper_steps=create=ok,baseline=ok,attempt=error") {
			t.Errorf("%s must be attempt_error, never a denial: %+v %v", c.name, res, res.Notes)
		}
	}
}

func TestTryDisableAuditBaseline1044IsNotADenial(t *testing.T) {
	d := &dialScript{}
	d.steps = []func() (session, error){failWith(myErr(1044, "Access denied for user to database"))}
	a, _ := revokeAdapter(t, d)
	res, _ := a.RunProbe(context.Background(), def(dbprobe.ProbeTryDisableAudit), tamperSpec())
	if res.Denied || res.ErrorClass != "baseline_failed" || !hasNote(res.Notes, "audit_tamper_steps=create=ok,baseline=failed,attempt=skipped") {
		t.Fatalf("%+v %v", res, res.Notes)
	}
}

func TestTryDisableAuditRefusalsAndTracking(t *testing.T) {
	d := &dialScript{}
	a, admin := revokeAdapter(t, d)
	admin.execFn = func(sql string) error {
		if strings.HasPrefix(sql, "CREATE USER") {
			return myErr(1396, "Operation CREATE USER failed")
		}
		return nil
	}
	res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeTryDisableAudit), tamperSpec())
	if err != nil || res.ErrorClass != "account_create_failed" || len(d.users) != 0 || a.acct.mayExist {
		t.Fatalf("%+v %v users=%v tracked=%v", res, err, d.users, a.acct.mayExist)
	}
	for _, c := range []struct {
		name  string
		setup func(a *Adapter)
		spec  func(s *dbprobe.DBProbeSpec)
	}{
		{"client connection", func(a *Adapter) { a.mode = dbprobe.ModeClient }, func(*dbprobe.DBProbeSpec) {}},
		{"client spec", func(*Adapter) {}, func(s *dbprobe.DBProbeSpec) { s.Mode = dbprobe.ModeClient }},
		{"no active fixture", func(a *Adapter) { a.UnbindFixture() }, func(*dbprobe.DBProbeSpec) {}},
		{"wrong fixture bound", func(a *Adapter) { _ = a.BindFixture(accountsFixture()) }, func(*dbprobe.DBProbeSpec) {}},
		{"a parameter", func(*Adapter) {}, func(s *dbprobe.DBProbeSpec) { s.Params = map[string]string{"statement": "SET x"} }},
	} {
		d := &dialScript{}
		a, admin := revokeAdapter(t, d)
		c.setup(a)
		s := tamperSpec()
		c.spec(&s)
		if _, err := a.RunProbe(context.Background(), def(dbprobe.ProbeTryDisableAudit), s); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
		if len(admin.calls) != 0 || len(d.users) != 0 || a.acct.mayExist {
			t.Errorf("%s: SQL, login or undo on a refusal", c.name)
		}
	}
}

func TestTryDisableAuditNoGlobalStatementAndCleanup(t *testing.T) {
	d := &dialScript{}
	d.steps = []func() (session, error){execSession(d, clockQuery, func(sql string) error {
		if strings.Contains(sql, "sql_log_off") {
			return myErr(1227, "denied")
		}
		return nil
	})}
	a, admin := revokeAdapter(t, d)
	if _, err := a.RunProbe(context.Background(), def(dbprobe.ProbeTryDisableAudit), tamperSpec()); err != nil {
		t.Fatal(err)
	}
	for _, s := range append(execSQL(admin), execSQL(d.sess[0])...) {
		up := strings.ToUpper(s)
		for _, bad := range []string{"SET GLOBAL", "SET PERSIST", "PERSIST_ONLY", "INSTALL PLUGIN", "UNINSTALL", "FLUSH", "RESET PERSIST"} {
			if strings.Contains(up, bad) {
				t.Fatalf("persistent/global statement %q sent: %q", bad, s)
			}
		}
	}
	admin.calls = nil
	admin.queryFn = func(string, []any) ([][]any, error) { return nil, nil }
	res, err := a.Cleanup(context.Background(), emptyFixture())
	if err != nil || len(res.Residual) != 0 || !contains(res.Removed, "user:"+revokeAcct) {
		t.Fatalf("%+v %v removed=%v", res, err, res.Removed)
	}
	if !hasPrefixCall(admin, "DROP USER IF EXISTS "+revokeLit) {
		t.Fatalf("%v", execSQL(admin))
	}
}

func TestTryDisableAuditPasswordNeverInResult(t *testing.T) {
	d := &dialScript{}
	a, admin := revokeAdapter(t, d)
	pwOf := func() string {
		c, _ := findPrefix(admin, "CREATE USER")
		return c[strings.Index(c, "IDENTIFIED BY '")+len("IDENTIFIED BY '") : len(c)-1]
	}
	d.steps = []func() (session, error){func() (session, error) {
		return nil, errors.New("connection failed password=" + pwOf() + " host=x")
	}}
	res, _ := a.RunProbe(context.Background(), def(dbprobe.ProbeTryDisableAudit), tamperSpec())
	b, _ := json.Marshal(res)
	if pw := pwOf(); len(pw) < 32 || strings.Contains(string(b), pw) {
		t.Fatalf("password in result: %s", b)
	}
}

// ---- DB-10 try_write_fixture ---------------------------------------------

func accountsFull() dbprobe.Fixture {
	cols := []string{"id", "synthetic", "account_ref", "display_name", "email", "balance_cents"}
	var fc []dbprobe.FixtureColumn
	for i, c := range cols {
		typ := dbprobe.FixtureColText
		if c == "id" || c == "balance_cents" {
			typ = dbprobe.FixtureColInt
		}
		fc = append(fc, dbprobe.FixtureColumn{Name: c, Type: typ, PK: i == 0})
	}
	return dbprobe.Fixture{ID: testFixtureID, Kind: "accounts", Tables: []dbprobe.FixtureTable{{Name: "accounts", Columns: fc}}}
}

func writeSpec() dbprobe.DBProbeSpec {
	s := spec(dbprobe.ProbeTryWriteFixture, dbprobe.ModeLab, nil)
	s.FixtureID = "accounts"
	return s
}

const fpMarker = "SUM(CRC32("

func writeAdapter(t *testing.T, fp func(n int) ([][]any, error), writeFn func(sql string) error) (*Adapter, *fakeSession, *dialScript) {
	t.Helper()
	d := &dialScript{}
	d.steps = []func() (session, error){execSession(d, func(sql string, _ []any) ([][]any, error) {
		if strings.Contains(sql, "UTC_TIMESTAMP") {
			return [][]any{{time.Unix(1700000000, 0).UTC(), int64(10)}}, nil
		}
		return nil, nil
	}, writeFn)}
	admin := &fakeSession{}
	n := 0
	admin.queryFn = func(sql string, _ []any) ([][]any, error) {
		if strings.Contains(sql, fpMarker) {
			n++
			return fp(n)
		}
		return nil, nil
	}
	a := &Adapter{s: admin, mode: dbprobe.ModeLab, dial: d.dial}
	a.target = dbprobe.ConnectionConfig{Host: "db.example", Port: 3306, Database: "dbsim", TLSMode: "disable"}
	if err := a.BindFixture(accountsFull()); err != nil {
		t.Fatal(err)
	}
	return a, admin, d
}

func sameFP(int) ([][]any, error) { return [][]any{{int64(10), []byte("12345")}}, nil }

func denyAllWrites(sql string) error {
	if strings.HasPrefix(sql, "/*") && (strings.Contains(sql, "INSERT INTO") || strings.Contains(sql, "UPDATE ") || strings.Contains(sql, "DELETE FROM")) {
		return myErr(1142, "INSERT command denied to user for table")
	}
	return nil
}

func TestWriteDeniedLeavesFixtureUnchanged(t *testing.T) {
	a, admin, d := writeAdapter(t, sameFP, denyAllWrites)
	res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeTryWriteFixture), writeSpec())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Denied || res.ErrorClass != "permission_denied" {
		t.Fatalf("%+v", res)
	}
	if !hasNote(res.Notes, "write_attempt_steps=insert=denied,update=denied,delete=denied,fingerprint=unchanged") {
		t.Fatalf("typed note: %v", res.Notes)
	}
	for _, n := range res.Notes {
		if strings.HasPrefix(n, "fixture_changed=") {
			t.Fatalf("an unchanged fixture must not report fixture_changed: %v", res.Notes)
		}
	}
	var grants []string
	for _, s := range execSQL(admin) {
		if strings.HasPrefix(s, "GRANT") {
			grants = append(grants, s)
		}
	}
	if len(grants) != 1 || grants[0] != "GRANT SELECT ON `dbsim_"+testFixtureID+"`.* TO "+revokeLit {
		t.Fatalf("grants (SELECT only on the fixture schema): %q", grants)
	}
	if d.dbs[0] != "" {
		t.Fatalf("the account is dialled with no default database (documented choice): %v", d.dbs)
	}
	tbl := "`dbsim_" + testFixtureID + "`.`accounts`"
	m := "/* dbsim:dbsim-abc123 */ "
	want := []string{
		m + fmt.Sprintf(dbprobe.WriteInsertSQL, tbl),
		m + fmt.Sprintf(dbprobe.WriteUpdateSQL, tbl),
		m + fmt.Sprintf(dbprobe.WriteDeleteSQL, tbl),
	}
	var writes []string
	for _, s := range execSQL(d.sess[0]) {
		if strings.Contains(s, "INSERT INTO") || strings.Contains(s, "UPDATE ") || strings.Contains(s, "DELETE FROM") {
			writes = append(writes, s)
		}
	}
	if strings.Join(writes, "\n") != strings.Join(want, "\n") {
		t.Fatalf("writes:\n%q\nwant\n%q", writes, want)
	}
	for _, s := range execSQL(admin) {
		if strings.Contains(s, "INSERT INTO") || strings.Contains(s, "UPDATE ") || strings.Contains(s, "DELETE FROM") {
			t.Fatalf("the lab connection must never write: %q", s)
		}
	}
	if !d.sess[0].closed {
		t.Fatal("throwaway session must be closed")
	}
}

func TestWriteSucceedingIsAFailAndReportsChangedFixture(t *testing.T) {
	a, _, _ := writeAdapter(t, func(n int) ([][]any, error) {
		if n == 1 {
			return [][]any{{int64(10), []byte("12345")}}, nil
		}
		return [][]any{{int64(11), []byte("99999")}}, nil
	}, func(sql string) error {
		if strings.Contains(sql, "INSERT INTO") {
			return nil
		}
		return denyAllWrites(sql)
	})
	res, _ := a.RunProbe(context.Background(), def(dbprobe.ProbeTryWriteFixture), writeSpec())
	if res.Denied || res.ErrorClass != "" ||
		!hasNote(res.Notes, "write_attempt_steps=insert=allowed,update=denied,delete=denied,fingerprint=changed") ||
		!hasNote(res.Notes, "fixture_changed=true") {
		t.Fatalf("%+v %v", res, res.Notes)
	}
}

func TestUnchangedFingerprintRequiredForPass(t *testing.T) {
	a, _, _ := writeAdapter(t, func(n int) ([][]any, error) {
		if n == 1 {
			return [][]any{{int64(10), []byte("12345")}}, nil
		}
		return [][]any{{int64(10), []byte("12346")}}, nil
	}, denyAllWrites)
	res, _ := a.RunProbe(context.Background(), def(dbprobe.ProbeTryWriteFixture), writeSpec())
	if res.Denied || res.ErrorClass != "fixture_state_inconsistent" {
		t.Fatalf("%+v", res)
	}
	a2, _, _ := writeAdapter(t, func(n int) ([][]any, error) {
		if n == 1 {
			return [][]any{{int64(10), []byte("12345")}}, nil
		}
		return nil, errors.New("connection lost")
	}, denyAllWrites)
	res, _ = a2.RunProbe(context.Background(), def(dbprobe.ProbeTryWriteFixture), writeSpec())
	if res.Denied || res.ErrorClass != "fingerprint_failed" || !hasNote(res.Notes, "write_attempt_steps=insert=denied,update=denied,delete=denied,fingerprint=error") {
		t.Fatalf("%+v %v", res, res.Notes)
	}
	a3, _, d3 := writeAdapter(t, func(int) ([][]any, error) { return nil, errors.New("nope") }, denyAllWrites)
	res, _ = a3.RunProbe(context.Background(), def(dbprobe.ProbeTryWriteFixture), writeSpec())
	if res.Denied || res.ErrorClass != "fingerprint_failed" || len(d3.users) != 0 ||
		!hasNote(res.Notes, "write_attempt_steps=insert=skipped,update=skipped,delete=skipped,fingerprint=error") {
		t.Fatalf("%+v users=%v %v", res, d3.users, res.Notes)
	}
}

func TestDenialCodesAreExact(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want string
	}{
		{"table access denied", myErr(1142, "x"), "denied"},
		{"column access denied", myErr(1143, "x"), "denied"},
		{"db access denied", myErr(1044, "x"), "denied"},
		{"wrapped", fmt.Errorf("wrapped: %w", myErr(1142, "x")), "denied"},
		{"login denied", myErr(1045, "x"), "error"},
		{"specific privilege (audit code)", myErr(1227, "x"), "error"},
		{"no such table", myErr(1146, "x"), "error"},
		{"read only txn", myErr(1792, "x"), "error"},
		{"duplicate key", myErr(1062, "x"), "error"},
		{"timeout", myErr(3024, "x"), "error"},
		{"generic text", errors.New("INSERT command denied to user"), "error"},
		{"deadline", context.DeadlineExceeded, "error"},
		{"nil", nil, "allowed"},
	} {
		if got := writeOutcome(c.err); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	a, _, _ := writeAdapter(t, sameFP, func(sql string) error {
		if strings.Contains(sql, "UPDATE ") {
			return myErr(1146, "no such table")
		}
		return denyAllWrites(sql)
	})
	res, _ := a.RunProbe(context.Background(), def(dbprobe.ProbeTryWriteFixture), writeSpec())
	if res.Denied || res.ErrorClass != "attempt_error" || !hasNote(res.Notes, "write_attempt_steps=insert=denied,update=error,delete=denied,fingerprint=unchanged") {
		t.Fatalf("%+v %v", res, res.Notes)
	}
}

func TestWriteProbeRefusalsBaselineGrantAndCleanup(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(a *Adapter)
		spec  func(s *dbprobe.DBProbeSpec)
	}{
		{"client connection", func(a *Adapter) { a.mode = dbprobe.ModeClient }, func(*dbprobe.DBProbeSpec) {}},
		{"client spec", func(*Adapter) {}, func(s *dbprobe.DBProbeSpec) { s.Mode = dbprobe.ModeClient }},
		{"no active fixture", func(a *Adapter) { a.UnbindFixture() }, func(*dbprobe.DBProbeSpec) {}},
		{"wrong fixture bound", func(a *Adapter) { _ = a.BindFixture(emptyFixture()) }, func(*dbprobe.DBProbeSpec) {}},
		{"a table param", func(*Adapter) {}, func(s *dbprobe.DBProbeSpec) { s.Params = map[string]string{"table": "ledger"} }},
	} {
		a, admin, d := writeAdapter(t, sameFP, denyAllWrites)
		c.setup(a)
		s := writeSpec()
		c.spec(&s)
		if _, err := a.RunProbe(context.Background(), def(dbprobe.ProbeTryWriteFixture), s); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
		if len(admin.calls) != 0 || len(d.users) != 0 || a.acct.mayExist {
			t.Errorf("%s: SQL, login or undo on a refusal", c.name)
		}
	}
	a, _, d := writeAdapter(t, sameFP, denyAllWrites)
	d.steps = []func() (session, error){failWith(myErr(1045, "x"))}
	res, _ := a.RunProbe(context.Background(), def(dbprobe.ProbeTryWriteFixture), writeSpec())
	if res.Denied || res.ErrorClass != "baseline_failed" {
		t.Fatalf("%+v", res)
	}
	a, admin, d := writeAdapter(t, sameFP, denyAllWrites)
	admin.execFn = func(sql string) error {
		if strings.HasPrefix(sql, "GRANT SELECT") {
			return myErr(1044, "denied")
		}
		return nil
	}
	res, _ = a.RunProbe(context.Background(), def(dbprobe.ProbeTryWriteFixture), writeSpec())
	if res.Denied || res.ErrorClass != "grant_failed" || len(d.users) != 0 || !a.acct.mayExist {
		t.Fatalf("%+v users=%v tracked=%v", res, d.users, a.acct.mayExist)
	}
	// Cleanup of a normal run drops the schema and the account.
	a, admin, _ = writeAdapter(t, sameFP, denyAllWrites)
	if _, err := a.RunProbe(context.Background(), def(dbprobe.ProbeTryWriteFixture), writeSpec()); err != nil {
		t.Fatal(err)
	}
	admin.calls = nil
	admin.queryFn = func(string, []any) ([][]any, error) { return nil, nil }
	cr, err := a.Cleanup(context.Background(), accountsFull())
	if err != nil || len(cr.Residual) != 0 || !contains(cr.Removed, "user:"+revokeAcct) {
		t.Fatalf("%+v %v", cr, err)
	}
	if !hasPrefixCall(admin, "DROP USER IF EXISTS "+revokeLit) {
		t.Fatalf("%v", execSQL(admin))
	}
}

// ---- DB-11 check_export_privileges ---------------------------------------

func exportSpec() dbprobe.DBProbeSpec {
	return spec(dbprobe.ProbeCheckExportPrivileges, dbprobe.ModeLab, nil)
}

func exportAdapter(answers map[string]func() ([][]any, error)) (*Adapter, *fakeSession) {
	f := &fakeSession{}
	f.queryFn = func(sql string, args []any) ([][]any, error) {
		for frag, fn := range answers {
			if strings.Contains(sql, frag) {
				return fn()
			}
		}
		return nil, errors.New("unexpected query: " + sql)
	}
	return &Adapter{s: f, mode: dbprobe.ModeLab}, f
}

func privRows(privs ...string) func() ([][]any, error) {
	return func() ([][]any, error) {
		var out [][]any
		for _, p := range privs {
			out = append(out, []any{[]byte(p)})
		}
		return out, nil
	}
}

func exportAnswers(privs []string, role any, sfp any, tables int64) map[string]func() ([][]any, error) {
	return map[string]func() ([][]any, error){
		"USER_PRIVILEGES":           privRows(privs...),
		"CURRENT_ROLE":              func() ([][]any, error) { return [][]any{{role}}, nil },
		"secure_file_priv":          func() ([][]any, error) { return [][]any{{sfp}}, nil },
		"information_schema.TABLES": func() ([][]any, error) { return [][]any{{tables}}, nil },
	}
}

func TestCheckExportPrivilegesNoneHeldIsBlocked(t *testing.T) {
	a, f := exportAdapter(exportAnswers([]string{"USAGE"}, []byte("NONE"), []byte("/var/lib/mysql-files/"), 7))
	res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeCheckExportPrivileges), exportSpec())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Denied || res.ErrorClass != "" {
		t.Fatalf("%+v", res)
	}
	if !hasNote(res.Notes, "export_checks=file_write=no,program_exec=na,file_read=no,bulk_select=no,dump_privs=7") {
		t.Fatalf("note %v", res.Notes)
	}
	if !hasNote(res.Notes, "export_context=reload=no,lock_tables=no,secure_file_priv=path") {
		t.Fatalf("context note %v", res.Notes)
	}
	if !hasPrefixCall(f, "START TRANSACTION READ ONLY") {
		t.Fatalf("catalog reads must run in a READ ONLY transaction: %v", execSQL(f))
	}
	for _, c := range f.calls {
		up := strings.ToUpper(c.sql)
		if strings.Contains(up, "INTO OUTFILE") || strings.Contains(up, "LOAD_FILE") || strings.Contains(up, "LOAD DATA") || strings.Contains(up, "FLUSH") {
			t.Errorf("an export primitive was used: %q", c.sql)
		}
		if len(c.args) != 0 {
			t.Errorf("parameter reached a catalog query: %q", c.sql)
		}
	}
}

func TestCheckExportPrivilegesHeldIsAllowed(t *testing.T) {
	a, _ := exportAdapter(exportAnswers([]string{"SELECT", "FILE", "RELOAD", "LOCK TABLES"}, []byte("NONE"), nil, 7))
	res, _ := a.RunProbe(context.Background(), def(dbprobe.ProbeCheckExportPrivileges), exportSpec())
	if res.Denied || res.ErrorClass != "" ||
		!hasNote(res.Notes, "export_checks=file_write=yes,program_exec=na,file_read=yes,bulk_select=yes,dump_privs=7") ||
		!hasNote(res.Notes, "export_context=reload=yes,lock_tables=yes,secure_file_priv=null") {
		t.Fatalf("%+v %v", res, res.Notes)
	}
}

func TestCheckExportPrivilegesRoleOrNoPrivilegeRowIsUnknown(t *testing.T) {
	// Privileges reachable through an active role are not assessed: never clear.
	a, _ := exportAdapter(exportAnswers([]string{"USAGE"}, []byte("`app_role`@`%`"), []byte(""), 7))
	res, _ := a.RunProbe(context.Background(), def(dbprobe.ProbeCheckExportPrivileges), exportSpec())
	if res.Denied || res.ErrorClass != "export_check_incomplete" ||
		!hasNote(res.Notes, "export_checks=file_write=unknown,program_exec=na,file_read=unknown,bulk_select=unknown,dump_privs=7") {
		t.Fatalf("%+v %v", res, res.Notes)
	}
	// No USER_PRIVILEGES row for the account (grantee string mismatch): unknown,
	// not "no privileges".
	a, _ = exportAdapter(exportAnswers(nil, []byte("NONE"), []byte(""), 7))
	res, _ = a.RunProbe(context.Background(), def(dbprobe.ProbeCheckExportPrivileges), exportSpec())
	if res.Denied || res.ErrorClass != "export_check_incomplete" ||
		!hasNote(res.Notes, "export_checks=file_write=unknown,program_exec=na,file_read=unknown,bulk_select=unknown,dump_privs=7") {
		t.Fatalf("%+v %v", res, res.Notes)
	}
	// MySQL 5.7 has no CURRENT_ROLE(): error 1305 means no roles exist.
	ans := exportAnswers([]string{"USAGE"}, nil, []byte(""), 7)
	ans["CURRENT_ROLE"] = func() ([][]any, error) { return nil, myErr(1305, "FUNCTION CURRENT_ROLE does not exist") }
	a, _ = exportAdapter(ans)
	res, _ = a.RunProbe(context.Background(), def(dbprobe.ProbeCheckExportPrivileges), exportSpec())
	if !res.Denied || !hasNote(res.Notes, "export_checks=file_write=no,program_exec=na,file_read=no,bulk_select=no,dump_privs=7") {
		t.Fatalf("%+v %v", res, res.Notes)
	}
	// Any other error reading the role is unknown.
	ans = exportAnswers([]string{"USAGE"}, nil, []byte(""), 7)
	ans["CURRENT_ROLE"] = func() ([][]any, error) { return nil, myErr(1227, "denied") }
	a, _ = exportAdapter(ans)
	res, _ = a.RunProbe(context.Background(), def(dbprobe.ProbeCheckExportPrivileges), exportSpec())
	if res.Denied || res.ErrorClass != "export_check_incomplete" {
		t.Fatalf("%+v %v", res, res.Notes)
	}
}

func TestCheckExportPrivilegesUnobservableIsNeverClear(t *testing.T) {
	ans := exportAnswers([]string{"USAGE"}, []byte("NONE"), []byte(""), 7)
	ans["information_schema.TABLES"] = func() ([][]any, error) { return nil, myErr(1227, "denied") }
	a, _ := exportAdapter(ans)
	res, _ := a.RunProbe(context.Background(), def(dbprobe.ProbeCheckExportPrivileges), exportSpec())
	if res.Denied || res.ErrorClass != "export_check_incomplete" ||
		!hasNote(res.Notes, "export_checks=file_write=no,program_exec=na,file_read=no,bulk_select=no,dump_privs=unknown") {
		t.Fatalf("%+v %v", res, res.Notes)
	}
	// A held privilege beats an unobservable check.
	ans = exportAnswers([]string{"FILE"}, []byte("NONE"), []byte(""), 7)
	ans["information_schema.TABLES"] = func() ([][]any, error) { return nil, errors.New("boom") }
	a, _ = exportAdapter(ans)
	res, _ = a.RunProbe(context.Background(), def(dbprobe.ProbeCheckExportPrivileges), exportSpec())
	if res.Denied || res.ErrorClass != "" || !hasNote(res.Notes, "export_checks=file_write=yes,program_exec=na,file_read=yes,bulk_select=no,dump_privs=unknown") {
		t.Fatalf("%+v %v", res, res.Notes)
	}
}

func TestCheckExportPrivilegesRefusals(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(a *Adapter)
		spec  func(s *dbprobe.DBProbeSpec)
	}{
		{"client connection", func(a *Adapter) { a.mode = dbprobe.ModeClient }, func(*dbprobe.DBProbeSpec) {}},
		{"client spec", func(*Adapter) {}, func(s *dbprobe.DBProbeSpec) { s.Mode = dbprobe.ModeClient }},
		{"a fixture", func(*Adapter) {}, func(s *dbprobe.DBProbeSpec) { s.FixtureID = "accounts" }},
		{"a parameter", func(*Adapter) {}, func(s *dbprobe.DBProbeSpec) { s.Params = map[string]string{"x": "y"} }},
	} {
		a, f := exportAdapter(exportAnswers([]string{"USAGE"}, []byte("NONE"), []byte(""), 1))
		c.setup(a)
		s := exportSpec()
		c.spec(&s)
		if _, err := a.RunProbe(context.Background(), def(dbprobe.ProbeCheckExportPrivileges), s); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
		if len(f.calls) != 0 {
			t.Errorf("%s: SQL issued on a refusal: %v", c.name, execSQL(f))
		}
	}
}

func TestCapabilitiesOfferTask15Probes(t *testing.T) {
	offered := map[string]bool{}
	for _, id := range New().Capabilities().ProbeIDs {
		offered[id] = true
	}
	for _, id := range dbprobe.ProbeIDs() {
		if !offered[id] {
			t.Errorf("adapter does not offer catalog probe %q", id)
		}
	}
}
