package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"audspect/agent/dbprobe"
)

const revokeAcct = "dbsim_abc123def456_acct"

func emptyFixture() dbprobe.Fixture {
	return dbprobe.Fixture{ID: testFixtureID, Kind: "empty", Tables: []dbprobe.FixtureTable{{
		Name: "empty_table", Columns: []dbprobe.FixtureColumn{{Name: "id", Type: dbprobe.FixtureColInt, PK: true}},
	}}}
}

func classifiedFixture() dbprobe.Fixture {
	return dbprobe.Fixture{ID: testFixtureID, Kind: "classified-pii", Tables: []dbprobe.FixtureTable{{
		Name: "customers_pii", Columns: []dbprobe.FixtureColumn{{Name: "id", Type: dbprobe.FixtureColInt, PK: true}, {Name: "ssn", Type: dbprobe.FixtureColText}},
	}}}
}

func revokeSpec() dbprobe.DBProbeSpec {
	s := spec(dbprobe.ProbeAuthAfterRevoke, dbprobe.ModeLab, nil)
	s.FixtureID = "empty"
	return s
}

// dialScript answers successive dial calls in order and records who logged in.
type dialScript struct {
	steps []func() (session, error)
	users []string
	pws   []string
	sess  []*fakeSession
}

func (d *dialScript) dial(ctx context.Context, cfg dbprobe.ConnectionConfig) (session, error) {
	d.users = append(d.users, cfg.User)
	d.pws = append(d.pws, cfg.Password)
	if len(d.steps) == 0 {
		return nil, errors.New("unexpected extra dial")
	}
	f := d.steps[0]
	d.steps = d.steps[1:]
	return f()
}

func (d *dialScript) okSession(queryFn func(string, []any) ([][]any, error)) func() (session, error) {
	return func() (session, error) {
		s := &fakeSession{queryFn: queryFn}
		d.sess = append(d.sess, s)
		return s, nil
	}
}

func failWith(err error) func() (session, error) {
	return func() (session, error) { return nil, err }
}

func pgErr(code, msg string) error {
	return fmt.Errorf("failed to connect: %w", &pgconn.PgError{Severity: "FATAL", Code: code, Message: msg})
}

func clockQuery(sql string, _ []any) ([][]any, error) {
	if strings.Contains(sql, "clock_timestamp") {
		return [][]any{{time.Unix(1700000000, 0).UTC()}}, nil
	}
	return nil, nil
}

func revokeAdapter(t *testing.T, d *dialScript) (*Adapter, *fakeSession) {
	t.Helper()
	admin := &fakeSession{}
	a := &Adapter{s: admin, mode: dbprobe.ModeLab, dial: d.dial}
	a.target = dbprobe.ConnectionConfig{Host: "db.example", Port: 5432, Database: "dbsim", TLSMode: "disable"}
	if err := a.BindFixture(emptyFixture()); err != nil {
		t.Fatal(err)
	}
	return a, admin
}

func execSQL(f *fakeSession) []string {
	var out []string
	for _, c := range f.calls {
		out = append(out, c.sql)
	}
	return out
}

func findPrefix(f *fakeSession, p string) (string, bool) {
	for _, c := range f.calls {
		if strings.HasPrefix(c.sql, p) {
			return c.sql, true
		}
	}
	return "", false
}

func TestAuthAfterRevokeDeniedAfterRevoke(t *testing.T) {
	d := &dialScript{}
	d.steps = []func() (session, error){d.okSession(clockQuery), failWith(pgErr("28000", `role "dbsim_abc123def456_acct" is not permitted to log in`))}
	a, admin := revokeAdapter(t, d)
	res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeAuthAfterRevoke), revokeSpec())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Denied || res.ErrorClass != "auth_failed" || res.RowsRead != 0 {
		t.Fatalf("a refused post-revoke login is Denied/auth_failed: %+v", res)
	}
	if !hasNote(res.Notes, "revoke_steps=create=ok,baseline=ok,revoke=ok,reconnect=denied") {
		t.Fatalf("typed step note missing: %v", res.Notes)
	}
	create, ok := findPrefix(admin, `CREATE ROLE "`+revokeAcct+`" LOGIN PASSWORD '`)
	if !ok {
		t.Fatalf("no CREATE ROLE ... LOGIN: %v", execSQL(admin))
	}
	pw := regexp.MustCompile(`PASSWORD '([0-9a-f]+)'$`).FindStringSubmatch(create)
	if pw == nil || len(pw[1]) < 32 {
		t.Fatalf("password literal shape: %q", create)
	}
	if _, ok := findPrefix(admin, `ALTER ROLE "`+revokeAcct+`" NOLOGIN`); !ok {
		t.Fatalf("revoke statement missing: %v", execSQL(admin))
	}
	// Order: create, then revoke; the revoke only after the baseline.
	if len(d.users) != 2 || d.users[0] != revokeAcct || d.users[1] != revokeAcct {
		t.Fatalf("both logins must be NEW connections as the throwaway account: %v", d.users)
	}
	if d.pws[0] != pw[1] || d.pws[1] != pw[1] {
		t.Fatal("the logins must use the generated password")
	}
	// The baseline statement carries the marker and ran on the account's own session.
	if len(d.sess) != 1 {
		t.Fatalf("baseline session: %d", len(d.sess))
	}
	base := d.sess[0]
	if len(base.calls) != 1 || !strings.HasPrefix(base.calls[0].sql, "/* dbsim:dbsim-abc123 */ ") || !base.closed {
		t.Fatalf("baseline must be one tagged statement on a session that is then closed: %+v closed=%v", base.calls, base.closed)
	}
	if !base.calls[0].hasDeadline {
		t.Error("baseline without a deadline")
	}
	if res.DBTime.IsZero() {
		t.Error("DBTime must come from the tagged baseline statement")
	}
	// The password never reaches the result.
	b, _ := json.Marshal(res)
	if strings.Contains(string(b), pw[1]) {
		t.Fatalf("password leaked into the result: %s", b)
	}
	// ... and is registered for redaction of any later error text.
	if !strings.Contains(strings.Join(a.secrets, "|"), pw[1]) {
		t.Fatal("password must join the redaction secret set")
	}
	if !a.acct.mayExist || a.acct.name != revokeAcct {
		t.Fatalf("undo tracking: %+v", a.acct)
	}
}

func TestAuthAfterRevokeBaselineFailureIsNeverAPass(t *testing.T) {
	d := &dialScript{}
	d.steps = []func() (session, error){failWith(pgErr("28P01", "password authentication failed"))}
	a, admin := revokeAdapter(t, d)
	res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeAuthAfterRevoke), revokeSpec())
	if err != nil {
		t.Fatal(err)
	}
	if res.Denied || res.ErrorClass != "baseline_failed" {
		t.Fatalf("a failed baseline must be baseline_failed and NOT a denial: %+v", res)
	}
	if !hasNote(res.Notes, "revoke_steps=create=ok,baseline=failed,revoke=skipped,reconnect=skipped") {
		t.Fatalf("notes %v", res.Notes)
	}
	if _, ok := findPrefix(admin, "ALTER ROLE"); ok {
		t.Fatal("nothing is revoked when the baseline did not work")
	}
	if len(d.users) != 1 {
		t.Fatalf("no second login after a failed baseline: %v", d.users)
	}
}

func TestAuthAfterRevokeStillConnectsIsAllowed(t *testing.T) {
	d := &dialScript{}
	d.steps = []func() (session, error){d.okSession(clockQuery), d.okSession(clockQuery)}
	a, _ := revokeAdapter(t, d)
	res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeAuthAfterRevoke), revokeSpec())
	if err != nil {
		t.Fatal(err)
	}
	if res.Denied || res.ErrorClass != "" {
		t.Fatalf("a login that still works after the revoke is the FAIL the scenario exists to catch (Allowed): %+v", res)
	}
	if !hasNote(res.Notes, "revoke_steps=create=ok,baseline=ok,revoke=ok,reconnect=connected") {
		t.Fatalf("notes %v", res.Notes)
	}
	if len(d.sess) != 2 || !d.sess[1].closed {
		t.Fatal("the post-revoke connection must be closed")
	}
}

func TestAuthAfterRevokeOtherErrorsAreNeverBlocked(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
	}{
		{"network", errors.New("dial tcp 10.0.0.5:5432: connect: connection refused")},
		{"timeout", context.DeadlineExceeded},
		{"tls", errors.New("tls: failed to verify certificate")},
		{"too many connections", pgErr("53300", "too many connections for role")},
		{"database missing", pgErr("3D000", "database does not exist")},
		{"unknown", errors.New("kaboom")},
	} {
		d := &dialScript{}
		d.steps = []func() (session, error){d.okSession(clockQuery), failWith(c.err)}
		a, _ := revokeAdapter(t, d)
		res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeAuthAfterRevoke), revokeSpec())
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if res.Denied || res.ErrorClass != "reconnect_error" {
			t.Errorf("%s: only SQLSTATE 28000/28P01 or 'not permitted to log in' may read as a denial: %+v", c.name, res)
		}
		if !hasNote(res.Notes, "revoke_steps=create=ok,baseline=ok,revoke=ok,reconnect=error") {
			t.Errorf("%s: notes %v", c.name, res.Notes)
		}
	}
}

func TestAuthAfterRevokeDenialClassification(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want bool
	}{
		{"28000", pgErr("28000", "x"), true},
		{"28P01", pgErr("28P01", "x"), true},
		{"message only", errors.New(`FATAL: role "x" is not permitted to log in`), true},
		{"28xxx other", pgErr("28002", "x"), false},
		{"42501", pgErr("42501", "permission denied"), false},
	} {
		if got := isLoginDenied(c.err); got != c.want {
			t.Errorf("%s: isLoginDenied=%v want %v", c.name, got, c.want)
		}
	}
}

func TestAuthAfterRevokeRevokeFailure(t *testing.T) {
	d := &dialScript{}
	d.steps = []func() (session, error){d.okSession(clockQuery)}
	a, admin := revokeAdapter(t, d)
	admin.execFn = func(sql string) error {
		if strings.HasPrefix(sql, "ALTER ROLE") {
			return &pgconn.PgError{Code: "42501", Message: "permission denied to alter role"}
		}
		return nil
	}
	res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeAuthAfterRevoke), revokeSpec())
	if err != nil {
		t.Fatal(err)
	}
	if res.Denied || res.ErrorClass != "revoke_failed" {
		t.Fatalf("%+v", res)
	}
	if !hasNote(res.Notes, "revoke_steps=create=ok,baseline=ok,revoke=failed,reconnect=skipped") {
		t.Fatalf("notes %v", res.Notes)
	}
	if len(d.users) != 1 {
		t.Fatal("no reconnect attempt when the revoke failed")
	}
}

func TestAuthAfterRevokeCreateFailureTracking(t *testing.T) {
	// A definite server refusal (the role already exists) means this call created
	// nothing: it must never be dropped.
	d := &dialScript{}
	a, admin := revokeAdapter(t, d)
	admin.execFn = func(sql string) error {
		if strings.HasPrefix(sql, "CREATE ROLE") {
			return &pgconn.PgError{Code: "42710", Message: "role already exists"}
		}
		return nil
	}
	res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeAuthAfterRevoke), revokeSpec())
	if err != nil {
		t.Fatal(err)
	}
	if res.ErrorClass != "account_create_failed" || res.Denied || len(d.users) != 0 {
		t.Fatalf("%+v dials=%v", res, d.users)
	}
	if !hasNote(res.Notes, "revoke_steps=create=failed,baseline=skipped,revoke=skipped,reconnect=skipped") {
		t.Fatalf("notes %v", res.Notes)
	}
	if a.acct.mayExist {
		t.Fatal("a refused CREATE created nothing: no undo may be registered (R-AA)")
	}
	admin.calls = nil
	if _, err := a.Cleanup(context.Background(), emptyFixture()); err != nil {
		t.Fatal(err)
	}
	if _, ok := findPrefix(admin, `DROP ROLE IF EXISTS "`+revokeAcct+`"`); ok {
		t.Fatalf("cleanup dropped an account this call did not create: %v", execSQL(admin))
	}

	// An unknown outcome (lost connection) keeps the undo: the CREATE may have run.
	d2 := &dialScript{}
	a2, admin2 := revokeAdapter(t, d2)
	admin2.execFn = func(sql string) error {
		if strings.HasPrefix(sql, "CREATE ROLE") {
			return errors.New("write tcp: broken pipe")
		}
		return nil
	}
	if _, err := a2.RunProbe(context.Background(), def(dbprobe.ProbeAuthAfterRevoke), revokeSpec()); err != nil {
		t.Fatal(err)
	}
	if !a2.acct.mayExist {
		t.Fatal("an ambiguous CREATE must stay tracked so cleanup removes it")
	}
}

func TestAuthAfterRevokeCleanupDropsExactlyTheTrackedAccount(t *testing.T) {
	d := &dialScript{}
	d.steps = []func() (session, error){d.okSession(clockQuery), failWith(pgErr("28000", "x"))}
	a, admin := revokeAdapter(t, d)
	if _, err := a.RunProbe(context.Background(), def(dbprobe.ProbeAuthAfterRevoke), revokeSpec()); err != nil {
		t.Fatal(err)
	}
	admin.calls = nil
	admin.queryFn = func(sql string, args []any) ([][]any, error) { return nil, nil }
	res, err := a.Cleanup(context.Background(), emptyFixture())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findPrefix(admin, `DROP ROLE IF EXISTS "`+revokeAcct+`"`); !ok {
		t.Fatalf("throwaway account not dropped: %v", execSQL(admin))
	}
	if len(res.Residual) != 0 || !contains(res.Removed, "role:"+revokeAcct) {
		t.Fatalf("%+v", res)
	}
	// Tracking stays: VerifyClean (InspectFixture) must keep proving it is gone.
	if !a.acct.mayExist {
		t.Fatal("tracking must outlive cleanup so VerifyClean still inspects the account")
	}
}

func TestAuthAfterRevokeLeftoverAccountIsResidual(t *testing.T) {
	d := &dialScript{}
	d.steps = []func() (session, error){d.okSession(clockQuery), failWith(pgErr("28000", "x"))}
	a, admin := revokeAdapter(t, d)
	if _, err := a.RunProbe(context.Background(), def(dbprobe.ProbeAuthAfterRevoke), revokeSpec()); err != nil {
		t.Fatal(err)
	}
	admin.queryFn = func(sql string, args []any) ([][]any, error) {
		if strings.Contains(sql, "pg_roles") && len(args) == 1 && args[0] == revokeAcct {
			return [][]any{{1}}, nil // the account is still there
		}
		return nil, nil
	}
	res, _ := a.Cleanup(context.Background(), emptyFixture())
	if !contains(res.Residual, "role:"+revokeAcct) {
		t.Fatalf("a surviving account must be reported residual: %+v", res)
	}
	objs, err := a.InspectFixture(context.Background(), emptyFixture())
	if err != nil || !contains(objs, "role:"+revokeAcct) {
		t.Fatalf("VerifyClean relies on InspectFixture listing the account: %v %v", objs, err)
	}
}

func TestAuthAfterRevokeRefusals(t *testing.T) {
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
	} {
		d := &dialScript{}
		a, admin := revokeAdapter(t, d)
		c.setup(a)
		s := revokeSpec()
		c.spec(&s)
		if _, err := a.RunProbe(context.Background(), def(dbprobe.ProbeAuthAfterRevoke), s); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
		if len(admin.calls) != 0 || len(d.users) != 0 {
			t.Errorf("%s: SQL or login issued on a refusal: %v %v", c.name, execSQL(admin), d.users)
		}
		if a.acct.mayExist {
			t.Errorf("%s: undo registered on a refusal", c.name)
		}
	}
}

func TestAuthAfterRevokeNeverTouchesConfiguredAccounts(t *testing.T) {
	d := &dialScript{}
	d.steps = []func() (session, error){d.okSession(clockQuery), failWith(pgErr("28000", "x"))}
	a, admin := revokeAdapter(t, d)
	a.target.User = "bas_target_user"
	if _, err := a.RunProbe(context.Background(), def(dbprobe.ProbeAuthAfterRevoke), revokeSpec()); err != nil {
		t.Fatal(err)
	}
	for _, s := range execSQL(admin) {
		up := strings.ToUpper(s)
		if (strings.Contains(up, "ROLE") || strings.Contains(up, "USER")) && !strings.Contains(s, revokeAcct) && !strings.HasPrefix(s, "BEGIN") {
			t.Errorf("statement addresses an account other than the throwaway one: %q", s)
		}
	}
}

func TestAuthAfterRevokeDialErrorRedactsThePassword(t *testing.T) {
	var pw string
	d := &dialScript{}
	d.steps = []func() (session, error){
		func() (session, error) { return nil, errors.New("boom") }, // replaced below
	}
	a, admin := revokeAdapter(t, d)
	d.steps[0] = func() (session, error) {
		c, _ := findPrefix(admin, "CREATE ROLE")
		pw = regexp.MustCompile(`'([0-9a-f]+)'$`).FindStringSubmatch(c)[1]
		return nil, errors.New("connection failed password=" + pw + " host=x")
	}
	res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeAuthAfterRevoke), revokeSpec())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(res)
	if pw == "" || strings.Contains(string(b), pw) {
		t.Fatalf("password in result: %s", b)
	}
}

func contains(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}

// read_classified_fixture (DB-07)

func classifiedAdapter(t *testing.T, rows [][]any) (*Adapter, *fakeSession) {
	t.Helper()
	f := &fakeSession{queryFn: func(sql string, args []any) ([][]any, error) {
		if strings.Contains(sql, "clock_timestamp") {
			return [][]any{{time.Unix(1700000000, 0).UTC()}}, nil
		}
		return rows, nil
	}}
	a := &Adapter{s: f, mode: dbprobe.ModeLab}
	if err := a.BindFixture(classifiedFixture()); err != nil {
		t.Fatal(err)
	}
	return a, f
}

func classifiedSpec(maxRows int) dbprobe.DBProbeSpec {
	s := spec(dbprobe.ProbeReadClassifiedFixture, dbprobe.ModeLab, nil)
	s.FixtureID = "classified-pii"
	s.Limits.MaxRows = maxRows
	return s
}

func TestReadClassifiedFixtureIsFixedBoundedSQL(t *testing.T) {
	a, f := classifiedAdapter(t, mkRows(6, 1, "000-12-3456"))
	res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeReadClassifiedFixture), classifiedSpec(100))
	if err != nil {
		t.Fatal(err)
	}
	const want = `/* dbsim:dbsim-abc123 */ SELECT * FROM "dbsim_abc123def456"."customers_pii" LIMIT $1`
	c := findCall(t, f, "/* dbsim:dbsim-abc123 */ SELECT * FROM")
	if c.sql != want || len(c.args) != 1 || c.args[0] != dbprobe.SuspiciousReadMaxRows+1 {
		t.Fatalf("sql %q args %v", c.sql, c.args)
	}
	if res.RowsRead != 6 || res.Denied || res.ErrorClass != "" || !hasNote(res.Notes, "row_cap_applied=25") {
		t.Fatalf("%+v", res)
	}
	if f.calls[0].sql != "BEGIN READ ONLY" {
		t.Fatalf("first statement %q", f.calls[0].sql)
	}
	// No row content on the wire.
	b, _ := json.Marshal(res)
	if strings.Contains(string(b), "000-12-3456") {
		t.Fatalf("row contents leaked: %s", b)
	}
}

func TestReadClassifiedFixtureRefusals(t *testing.T) {
	// Wrong fixture bound, client mode, and no fixture all fail before any SQL.
	a, f := classifiedAdapter(t, nil)
	_ = a.BindFixture(accountsFixture())
	if _, err := a.RunProbe(context.Background(), def(dbprobe.ProbeReadClassifiedFixture), classifiedSpec(5)); err == nil {
		t.Error("accepted with a fixture that has no customers_pii table")
	}
	a2, _ := classifiedAdapter(t, nil)
	f2 := a2.s.(*fakeSession)
	s := classifiedSpec(5)
	s.Mode = dbprobe.ModeClient
	if _, err := a2.RunProbe(context.Background(), def(dbprobe.ProbeReadClassifiedFixture), s); err == nil {
		t.Error("client mode accepted")
	}
	a2.UnbindFixture()
	if _, err := a2.RunProbe(context.Background(), def(dbprobe.ProbeReadClassifiedFixture), classifiedSpec(5)); err == nil {
		t.Error("no fixture accepted")
	}
	if len(f.calls) != 0 || len(f2.calls) != 0 {
		t.Errorf("SQL on a refusal: %v %v", execSQL(f), execSQL(f2))
	}
	// A kind other than classified-pii, even with a customers_pii table, is refused.
	a3, _ := classifiedAdapter(t, nil)
	fx := classifiedFixture()
	fx.Kind = "accounts"
	_ = a3.BindFixture(fx)
	if _, err := a3.RunProbe(context.Background(), def(dbprobe.ProbeReadClassifiedFixture), classifiedSpec(5)); err == nil {
		t.Error("fixture kind mismatch accepted")
	}
}

// F3: DB-06 shares the throwaway-account tracking; a second run on an adapter
// that still tracks an account is refused before anything is sent.
func TestAuthAfterRevokeSecondRunRefusedWhileTracked(t *testing.T) {
	d := &dialScript{}
	a, admin := revokeAdapter(t, d)
	a.acct = acctState{name: "dbsim_x_acct", mayExist: true}
	_, err := a.RunProbe(context.Background(), def(dbprobe.ProbeAuthAfterRevoke), revokeSpec())
	if err == nil || !strings.Contains(err.Error(), "already tracks") {
		t.Fatalf("want refusal, got %v", err)
	}
	if len(admin.calls) != 0 || a.acct.name != "dbsim_x_acct" || !a.acct.mayExist {
		t.Fatalf("nothing sent, tracking kept: %v %+v", execSQL(admin), a.acct)
	}
}
