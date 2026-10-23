package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"audspect/agent/dbprobe"
)

// ---- shared helpers -------------------------------------------------------

func execSession(d *dialScript, queryFn func(string, []any) ([][]any, error), execFn func(string) error) func() (session, error) {
	return func() (session, error) {
		s := &fakeSession{queryFn: queryFn, execFn: execFn}
		d.sess = append(d.sess, s)
		return s, nil
	}
}

func pgPerm(code string) error {
	return &pgconn.PgError{Severity: "ERROR", Code: code, Message: "permission denied"}
}

func tamperSpec() dbprobe.DBProbeSpec {
	s := spec(dbprobe.ProbeTryDisableAudit, dbprobe.ModeLab, nil)
	s.FixtureID = "empty"
	return s
}

func tamperAdapter(t *testing.T, d *dialScript) (*Adapter, *fakeSession) {
	return revokeAdapter(t, d) // empty fixture bound, lab mode, injected dial
}

func hasPrefixCall(f *fakeSession, p string) bool {
	_, ok := findPrefix(f, p)
	return ok
}

// ---- DB-08 try_disable_audit ---------------------------------------------

func TestTryDisableAuditDenied(t *testing.T) {
	d := &dialScript{}
	d.steps = []func() (session, error){execSession(d, clockQuery, func(sql string) error {
		if strings.Contains(sql, "SET log_statement") {
			return pgPerm("42501")
		}
		return nil
	})}
	a, admin := tamperAdapter(t, d)
	res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeTryDisableAudit), tamperSpec())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Denied || res.ErrorClass != "permission_denied" {
		t.Fatalf("42501 is the denial: %+v", res)
	}
	if !hasNote(res.Notes, "audit_tamper_steps=create=ok,baseline=ok,attempt=denied") {
		t.Fatalf("typed note: %v", res.Notes)
	}
	if len(d.users) != 1 || d.users[0] != revokeAcct {
		t.Fatalf("one NEW connection as the throwaway account: %v", d.users)
	}
	sess := d.sess[0]
	var attempts []string
	for _, c := range sess.calls {
		if strings.Contains(c.sql, "SET log_statement") {
			attempts = append(attempts, c.sql)
		}
	}
	if len(attempts) != 1 || attempts[0] != "/* dbsim:dbsim-abc123 */ SET log_statement = 'none'" {
		t.Fatalf("the marker rides on the attempt statement: %q", attempts)
	}
	if !sess.closed {
		t.Fatal("the throwaway connection must be closed")
	}
	// The lab connection never runs the tamper statement.
	for _, s := range execSQL(admin) {
		if strings.Contains(s, "log_statement") {
			t.Fatalf("the lab connection ran %q", s)
		}
	}
}

func TestTryDisableAuditSuccessIsAllowedAndClosesImmediately(t *testing.T) {
	d := &dialScript{}
	d.steps = []func() (session, error){d.okSession(clockQuery)}
	a, _ := tamperAdapter(t, d)
	res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeTryDisableAudit), tamperSpec())
	if err != nil {
		t.Fatal(err)
	}
	if res.Denied || res.ErrorClass != "" {
		t.Fatalf("a succeeding session-scoped SET is Allowed (a finding), not an error: %+v", res)
	}
	if !hasNote(res.Notes, "audit_tamper_steps=create=ok,baseline=ok,attempt=allowed") {
		t.Fatalf("typed note: %v", res.Notes)
	}
	sess := d.sess[0]
	calls := execSQL(sess)
	if !sess.closed || !strings.Contains(calls[len(calls)-1], "SET log_statement = 'none'") {
		t.Fatalf("no statement may follow the successful SET and the connection must close: %v closed=%v", calls, sess.closed)
	}
}

func TestTryDisableAuditOnlyExactDenialCodeIsBlocked(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
	}{
		{"unknown parameter", pgPerm("42704")},
		{"syntax", pgPerm("42601")},
		{"invalid value", pgPerm("22023")},
		{"auth failure", pgPerm("28000")},
		{"read only txn", pgPerm("25006")},
		{"statement timeout", pgPerm("57014")},
		{"generic", errors.New("write tcp: broken pipe")},
		{"deadline", context.DeadlineExceeded},
	} {
		d := &dialScript{}
		err := c.err
		d.steps = []func() (session, error){execSession(d, clockQuery, func(sql string) error {
			if strings.Contains(sql, "SET log_statement") {
				return err
			}
			return nil
		})}
		a, _ := tamperAdapter(t, d)
		res, rerr := a.RunProbe(context.Background(), def(dbprobe.ProbeTryDisableAudit), tamperSpec())
		if rerr != nil {
			t.Fatalf("%s: %v", c.name, rerr)
		}
		if res.Denied || res.ErrorClass != "attempt_error" {
			t.Errorf("%s must be attempt_error, never a denial: %+v", c.name, res)
		}
		if !hasNote(res.Notes, "audit_tamper_steps=create=ok,baseline=ok,attempt=error") {
			t.Errorf("%s: note %v", c.name, res.Notes)
		}
	}
}

func TestTryDisableAuditBaselineFailureIsNotADenial(t *testing.T) {
	for _, fail := range []func() (session, error){
		failWith(pgErr("28P01", "password authentication failed")),
		func() (session, error) {
			return &fakeSession{queryFn: func(string, []any) ([][]any, error) { return nil, errors.New("boom") }}, nil
		},
	} {
		d := &dialScript{}
		d.steps = []func() (session, error){fail}
		a, _ := tamperAdapter(t, d)
		res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeTryDisableAudit), tamperSpec())
		if err != nil {
			t.Fatal(err)
		}
		if res.Denied || res.ErrorClass != "baseline_failed" {
			t.Fatalf("a failed login is baseline_failed: %+v", res)
		}
		if !hasNote(res.Notes, "audit_tamper_steps=create=ok,baseline=failed,attempt=skipped") {
			t.Fatalf("note %v", res.Notes)
		}
	}
}

func TestTryDisableAuditCreateFailureTrackingAndRefusals(t *testing.T) {
	d := &dialScript{}
	a, admin := tamperAdapter(t, d)
	admin.execFn = func(sql string) error {
		if strings.HasPrefix(sql, "CREATE ROLE") {
			return &pgconn.PgError{Code: "42710", Message: "role already exists"}
		}
		return nil
	}
	res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeTryDisableAudit), tamperSpec())
	if err != nil || res.ErrorClass != "account_create_failed" || len(d.users) != 0 || a.acct.mayExist {
		t.Fatalf("%+v %v users=%v tracked=%v", res, err, d.users, a.acct.mayExist)
	}
	if !hasNote(res.Notes, "audit_tamper_steps=create=failed,baseline=skipped,attempt=skipped") {
		t.Fatalf("note %v", res.Notes)
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
		{"wrong fixture in spec", func(*Adapter) {}, func(s *dbprobe.DBProbeSpec) { s.FixtureID = "accounts" }},
		{"a parameter", func(*Adapter) {}, func(s *dbprobe.DBProbeSpec) { s.Params = map[string]string{"statement": "SET x"} }},
	} {
		d := &dialScript{}
		a, admin := tamperAdapter(t, d)
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

func TestTryDisableAuditCleanupDropsTheAccountAndNoGlobalStatementIsEverSent(t *testing.T) {
	d := &dialScript{}
	d.steps = []func() (session, error){execSession(d, clockQuery, func(sql string) error {
		if strings.Contains(sql, "SET log_statement") {
			return pgPerm("42501")
		}
		return nil
	})}
	a, admin := tamperAdapter(t, d)
	if _, err := a.RunProbe(context.Background(), def(dbprobe.ProbeTryDisableAudit), tamperSpec()); err != nil {
		t.Fatal(err)
	}
	all := append(execSQL(admin), execSQL(d.sess[0])...)
	for _, s := range all {
		up := strings.ToUpper(s)
		for _, bad := range []string{"ALTER SYSTEM", "SET GLOBAL", "SET PERSIST", "PG_RELOAD_CONF", "ALTER DATABASE", "ALTER ROLE"} {
			if strings.Contains(up, bad) {
				t.Fatalf("persistent/global statement %q sent: %q", bad, s)
			}
		}
	}
	admin.calls = nil
	res, err := a.Cleanup(context.Background(), emptyFixture())
	if err != nil || len(res.Residual) != 0 || !contains(res.Removed, "role:"+revokeAcct) {
		t.Fatalf("%+v %v", res, err)
	}
	if !hasPrefixCall(admin, `DROP ROLE IF EXISTS "`+revokeAcct+`"`) {
		t.Fatalf("account not dropped: %v", execSQL(admin))
	}
}

func TestTryDisableAuditPasswordNeverInResult(t *testing.T) {
	d := &dialScript{}
	a, admin := tamperAdapter(t, d)
	d.steps = []func() (session, error){func() (session, error) {
		c, _ := findPrefix(admin, "CREATE ROLE")
		pw := c[strings.Index(c, "PASSWORD '")+len("PASSWORD '") : len(c)-1]
		return nil, errors.New("connection failed password=" + pw + " host=x")
	}}
	res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeTryDisableAudit), tamperSpec())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(res)
	c, _ := findPrefix(admin, "CREATE ROLE")
	pw := c[strings.Index(c, "PASSWORD '")+len("PASSWORD '") : len(c)-1]
	if len(pw) < 32 || strings.Contains(string(b), pw) {
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

const fpMarker = "md5(string_agg"

// writeAdapter wires a lab connection whose fingerprint answers come from fp
// (called once per fingerprint query) and a throwaway session whose write
// statements are answered by writeFn.
func writeAdapter(t *testing.T, fp func(n int) ([][]any, error), writeFn func(sql string) error) (*Adapter, *fakeSession, *dialScript) {
	t.Helper()
	d := &dialScript{}
	d.steps = []func() (session, error){execSession(d, func(sql string, _ []any) ([][]any, error) {
		if strings.Contains(sql, "clock_timestamp") {
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
	a.target = dbprobe.ConnectionConfig{Host: "db.example", Port: 5432, Database: "dbsim", TLSMode: "disable"}
	if err := a.BindFixture(accountsFull()); err != nil {
		t.Fatal(err)
	}
	return a, admin, d
}

func sameFP(int) ([][]any, error) { return [][]any{{"10", "abc"}}, nil }

func denyAllWrites(sql string) error {
	if strings.HasPrefix(sql, "/*") && (strings.Contains(sql, "INSERT INTO") || strings.Contains(sql, "UPDATE ") || strings.Contains(sql, "DELETE FROM")) {
		return pgPerm("42501")
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
	// The grants: USAGE on the schema and SELECT on the one table, nothing else.
	var grants []string
	for _, s := range execSQL(admin) {
		if strings.HasPrefix(s, "GRANT") {
			grants = append(grants, s)
		}
	}
	wantTbl := `"dbsim_` + testFixtureID + `"."accounts"`
	if len(grants) != 2 ||
		grants[0] != `GRANT USAGE ON SCHEMA "dbsim_`+testFixtureID+`" TO "`+revokeAcct+`"` ||
		grants[1] != `GRANT SELECT ON `+wantTbl+` TO "`+revokeAcct+`"` {
		t.Fatalf("grants: %q", grants)
	}
	// Exactly insert, update, delete in order, fixed text, marker-tagged, on the
	// throwaway session; none on the lab connection.
	var writes []string
	for _, s := range execSQL(d.sess[0]) {
		if strings.Contains(s, "INSERT INTO") || strings.Contains(s, "UPDATE ") || strings.Contains(s, "DELETE FROM") {
			writes = append(writes, s)
		}
	}
	m := "/* dbsim:dbsim-abc123 */ "
	want := []string{
		m + fmt.Sprintf(dbprobe.WriteInsertSQL, wantTbl),
		m + fmt.Sprintf(dbprobe.WriteUpdateSQL, wantTbl),
		m + fmt.Sprintf(dbprobe.WriteDeleteSQL, wantTbl),
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
	// The INSERT is (wrongly) permitted: Allowed, the fixture is dirty.
	a, _, _ := writeAdapter(t, func(n int) ([][]any, error) {
		if n == 1 {
			return [][]any{{"10", "abc"}}, nil
		}
		return [][]any{{"11", "def"}}, nil
	}, func(sql string) error {
		if strings.Contains(sql, "INSERT INTO") {
			return nil
		}
		return denyAllWrites(sql)
	})
	res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeTryWriteFixture), writeSpec())
	if err != nil {
		t.Fatal(err)
	}
	if res.Denied || res.ErrorClass != "" {
		t.Fatalf("a permitted write is Allowed: %+v", res)
	}
	if !hasNote(res.Notes, "write_attempt_steps=insert=allowed,update=denied,delete=denied,fingerprint=changed") {
		t.Fatalf("typed note: %v", res.Notes)
	}
	if !hasNote(res.Notes, "fixture_changed=true") {
		t.Fatalf("a succeeding write must report fixture_changed=true: %v", res.Notes)
	}
}

func TestWriteAllowedEvenIfFingerprintDoesNotMove(t *testing.T) {
	// A permitted DELETE that matched nothing still proves the privilege exists;
	// the fixture is reported dirty because a write was accepted.
	a, _, _ := writeAdapter(t, sameFP, func(sql string) error {
		if strings.Contains(sql, "DELETE FROM") {
			return nil
		}
		return denyAllWrites(sql)
	})
	res, _ := a.RunProbe(context.Background(), def(dbprobe.ProbeTryWriteFixture), writeSpec())
	if res.Denied || res.ErrorClass != "" || !hasNote(res.Notes, "fixture_changed=true") {
		t.Fatalf("%+v", res)
	}
}

func TestUnchangedFingerprintRequiredForPass(t *testing.T) {
	// All three denied but the table state differs afterwards: inconsistent, an
	// ERROR class, never Denied.
	a, _, _ := writeAdapter(t, func(n int) ([][]any, error) {
		if n == 1 {
			return [][]any{{"10", "abc"}}, nil
		}
		return [][]any{{"10", "zzz"}}, nil
	}, denyAllWrites)
	res, _ := a.RunProbe(context.Background(), def(dbprobe.ProbeTryWriteFixture), writeSpec())
	if res.Denied || res.ErrorClass != "fixture_state_inconsistent" {
		t.Fatalf("%+v", res)
	}
	if !hasNote(res.Notes, "write_attempt_steps=insert=denied,update=denied,delete=denied,fingerprint=changed") {
		t.Fatalf("note %v", res.Notes)
	}
	// An unreadable AFTER fingerprint is never a pass either.
	a2, _, _ := writeAdapter(t, func(n int) ([][]any, error) {
		if n == 1 {
			return [][]any{{"10", "abc"}}, nil
		}
		return nil, errors.New("connection lost")
	}, denyAllWrites)
	res, _ = a2.RunProbe(context.Background(), def(dbprobe.ProbeTryWriteFixture), writeSpec())
	if res.Denied || res.ErrorClass != "fingerprint_failed" {
		t.Fatalf("%+v", res)
	}
	if !hasNote(res.Notes, "write_attempt_steps=insert=denied,update=denied,delete=denied,fingerprint=error") {
		t.Fatalf("note %v", res.Notes)
	}
	// An unreadable BEFORE fingerprint: nothing is attempted.
	a3, _, d3 := writeAdapter(t, func(int) ([][]any, error) { return nil, errors.New("nope") }, denyAllWrites)
	res, _ = a3.RunProbe(context.Background(), def(dbprobe.ProbeTryWriteFixture), writeSpec())
	if res.Denied || res.ErrorClass != "fingerprint_failed" || len(d3.users) != 0 {
		t.Fatalf("%+v users=%v", res, d3.users)
	}
	if !hasNote(res.Notes, "write_attempt_steps=insert=skipped,update=skipped,delete=skipped,fingerprint=error") {
		t.Fatalf("note %v", res.Notes)
	}
}

func TestDenialCodesAreExact(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want string
	}{
		{"insufficient privilege", pgPerm("42501"), "denied"},
		{"wrapped insufficient privilege", fmt.Errorf("wrapped: %w", pgPerm("42501")), "denied"},
		{"undefined table", pgPerm("42P01"), "error"},
		{"read only", pgPerm("25006"), "error"},
		{"auth", pgPerm("28000"), "error"},
		{"unique violation", pgPerm("23505"), "error"},
		{"timeout", pgPerm("57014"), "error"},
		{"generic", errors.New("permission denied for table accounts"), "error"},
		{"deadline", context.DeadlineExceeded, "error"},
		{"nil", nil, "allowed"},
	} {
		if got := writeOutcome(c.err); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	// A non-denial error on any statement is attempt_error, never Denied.
	a, _, _ := writeAdapter(t, sameFP, func(sql string) error {
		if strings.Contains(sql, "UPDATE ") {
			return pgPerm("42P01")
		}
		return denyAllWrites(sql)
	})
	res, _ := a.RunProbe(context.Background(), def(dbprobe.ProbeTryWriteFixture), writeSpec())
	if res.Denied || res.ErrorClass != "attempt_error" {
		t.Fatalf("%+v", res)
	}
	if !hasNote(res.Notes, "write_attempt_steps=insert=denied,update=error,delete=denied,fingerprint=unchanged") {
		t.Fatalf("note %v", res.Notes)
	}
}

func TestWriteProbeRefusalsAndBaseline(t *testing.T) {
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
	// A failed login (or failed SELECT baseline) is baseline_failed, never denied.
	a, _, d := writeAdapter(t, sameFP, denyAllWrites)
	d.steps = []func() (session, error){failWith(pgErr("28000", "x"))}
	res, _ := a.RunProbe(context.Background(), def(dbprobe.ProbeTryWriteFixture), writeSpec())
	if res.Denied || res.ErrorClass != "baseline_failed" {
		t.Fatalf("%+v", res)
	}
	if !hasNote(res.Notes, "write_attempt_steps=insert=skipped,update=skipped,delete=skipped,fingerprint=skipped") {
		t.Fatalf("note %v", res.Notes)
	}
}

func TestWriteGrantFailureStopsBeforeAnyAttempt(t *testing.T) {
	a, admin, d := writeAdapter(t, sameFP, denyAllWrites)
	admin.execFn = func(sql string) error {
		if strings.HasPrefix(sql, "GRANT SELECT") {
			return pgPerm("42501")
		}
		return nil
	}
	res, _ := a.RunProbe(context.Background(), def(dbprobe.ProbeTryWriteFixture), writeSpec())
	if res.Denied || res.ErrorClass != "grant_failed" || len(d.users) != 0 {
		t.Fatalf("%+v users=%v", res, d.users)
	}
	if !a.acct.mayExist {
		t.Fatal("the created account stays tracked for cleanup")
	}
}

func TestWriteProbeCleanupDropsAccountAndSchema(t *testing.T) {
	a, admin, _ := writeAdapter(t, sameFP, denyAllWrites)
	if _, err := a.RunProbe(context.Background(), def(dbprobe.ProbeTryWriteFixture), writeSpec()); err != nil {
		t.Fatal(err)
	}
	admin.calls = nil
	admin.queryFn = func(string, []any) ([][]any, error) { return nil, nil }
	res, err := a.Cleanup(context.Background(), accountsFull())
	if err != nil || len(res.Residual) != 0 || !contains(res.Removed, "role:"+revokeAcct) {
		t.Fatalf("%+v %v", res, err)
	}
	if !hasPrefixCall(admin, `DROP SCHEMA IF EXISTS "dbsim_`+testFixtureID+`" CASCADE`) || !hasPrefixCall(admin, `DROP ROLE IF EXISTS "`+revokeAcct+`"`) {
		t.Fatalf("%v", execSQL(admin))
	}
}

// ---- DB-11 check_export_privileges ---------------------------------------

func exportSpec() dbprobe.DBProbeSpec {
	return spec(dbprobe.ProbeCheckExportPrivileges, dbprobe.ModeLab, nil)
}

// exportAnswers maps a recognisable SQL fragment to an answer.
func exportAdapter(answers map[string]func() ([][]any, error)) (*Adapter, *fakeSession) {
	f := &fakeSession{}
	f.queryFn = func(sql string, args []any) ([][]any, error) {
		if strings.Contains(sql, "clock_timestamp") {
			return [][]any{{time.Unix(1700000000, 0).UTC()}}, nil
		}
		for frag, fn := range answers {
			if strings.Contains(sql, frag) {
				return fn()
			}
		}
		return nil, errors.New("unexpected query: " + sql)
	}
	return &Adapter{s: f, mode: dbprobe.ModeLab}, f
}

func boolRow(v bool) func() ([][]any, error) {
	return func() ([][]any, error) { return [][]any{{v}}, nil }
}

func allExport(fw, pe, fr, bulk bool, dump int64) map[string]func() ([][]any, error) {
	return map[string]func() ([][]any, error){
		"pg_write_server_files":     boolRow(fw),
		"pg_execute_server_program": boolRow(pe),
		"pg_read_server_files":      boolRow(fr),
		"pg_read_all_data":          boolRow(bulk),
		"has_table_privilege":       func() ([][]any, error) { return [][]any{{dump}}, nil },
	}
}

func TestCheckExportPrivilegesNoneHeldIsBlocked(t *testing.T) {
	a, f := exportAdapter(allExport(false, false, false, false, 12))
	res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeCheckExportPrivileges), exportSpec())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Denied || res.ErrorClass != "" {
		t.Fatalf("%+v", res)
	}
	if !hasNote(res.Notes, "export_checks=file_write=no,program_exec=no,file_read=no,bulk_select=no,dump_privs=12") {
		t.Fatalf("note %v", res.Notes)
	}
	// Fixed, read-only, parameter-free catalog queries.
	for _, c := range f.calls {
		if len(c.args) != 0 && !strings.Contains(c.sql, "set_config") {
			t.Errorf("a parameter reached the catalog query: %q %v", c.sql, c.args)
		}
		if strings.Contains(c.sql, "COPY") || strings.Contains(c.sql, "pg_read_file") || strings.Contains(c.sql, "lo_export") {
			t.Errorf("an export primitive was used: %q", c.sql)
		}
	}
	if !hasPrefixCall(f, "BEGIN READ ONLY") {
		t.Fatalf("catalog reads must run in a READ ONLY transaction: %v", execSQL(f))
	}
}

func TestCheckExportPrivilegesAnyHeldIsAllowed(t *testing.T) {
	for _, c := range []struct {
		fw, pe, fr bool
		want       string
	}{
		{true, false, false, "export_checks=file_write=yes,program_exec=no,file_read=no,bulk_select=no,dump_privs=3"},
		{false, true, false, "export_checks=file_write=no,program_exec=yes,file_read=no,bulk_select=no,dump_privs=3"},
		{false, false, true, "export_checks=file_write=no,program_exec=no,file_read=yes,bulk_select=no,dump_privs=3"},
	} {
		a, _ := exportAdapter(allExport(c.fw, c.pe, c.fr, false, 3))
		res, _ := a.RunProbe(context.Background(), def(dbprobe.ProbeCheckExportPrivileges), exportSpec())
		if res.Denied || res.ErrorClass != "" || !hasNote(res.Notes, c.want) {
			t.Errorf("%+v notes=%v", res, res.Notes)
		}
	}
}

func TestCheckExportPrivilegesUnobservableIsNeverClear(t *testing.T) {
	ans := allExport(false, false, false, false, 5)
	ans["pg_read_server_files"] = func() ([][]any, error) { return nil, pgPerm("42501") }
	a, _ := exportAdapter(ans)
	res, _ := a.RunProbe(context.Background(), def(dbprobe.ProbeCheckExportPrivileges), exportSpec())
	if res.Denied || res.ErrorClass != "export_check_incomplete" {
		t.Fatalf("%+v", res)
	}
	if !hasNote(res.Notes, "export_checks=file_write=no,program_exec=no,file_read=unknown,bulk_select=no,dump_privs=5") {
		t.Fatalf("note %v", res.Notes)
	}
	// A wrong-shaped answer is unknown as well.
	ans = allExport(false, false, false, false, 5)
	ans["pg_write_server_files"] = func() ([][]any, error) { return nil, nil }
	a, _ = exportAdapter(ans)
	res, _ = a.RunProbe(context.Background(), def(dbprobe.ProbeCheckExportPrivileges), exportSpec())
	if res.Denied || !hasNote(res.Notes, "export_checks=file_write=unknown,program_exec=no,file_read=no,bulk_select=no,dump_privs=5") {
		t.Fatalf("%+v %v", res, res.Notes)
	}
	// A held privilege beats an unobservable one: a definite finding.
	ans = allExport(true, false, false, false, 5)
	ans["pg_read_all_data"] = func() ([][]any, error) { return nil, errors.New("boom") }
	a, _ = exportAdapter(ans)
	res, _ = a.RunProbe(context.Background(), def(dbprobe.ProbeCheckExportPrivileges), exportSpec())
	if res.Denied || res.ErrorClass != "" || !hasNote(res.Notes, "export_checks=file_write=yes,program_exec=no,file_read=no,bulk_select=unknown,dump_privs=5") {
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
		a, f := exportAdapter(allExport(false, false, false, false, 1))
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
