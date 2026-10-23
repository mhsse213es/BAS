package mysql

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	drv "github.com/go-sql-driver/mysql"

	"audspect/agent/dbprobe"
)

const revokeAcct = "dbsim_abc123def456_acct"
const revokeLit = "'" + revokeAcct + "'@'%'"

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

type dialScript struct {
	steps []func() (session, error)
	users []string
	dbs   []string
	pws   []string
	sess  []*fakeSession
}

func (d *dialScript) dial(ctx context.Context, cfg dbprobe.ConnectionConfig) (session, error) {
	d.users = append(d.users, cfg.User)
	d.dbs = append(d.dbs, cfg.Database)
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

func myErr(n uint16, msg string) error {
	return fmt.Errorf("Error %d: %w", n, &drv.MySQLError{Number: n, Message: msg})
}

func clockQuery(sql string, _ []any) ([][]any, error) {
	if strings.Contains(sql, "UTC_TIMESTAMP") {
		return [][]any{{time.Unix(1700000000, 0).UTC()}}, nil
	}
	return nil, nil
}

func revokeAdapter(t *testing.T, d *dialScript) (*Adapter, *fakeSession) {
	t.Helper()
	admin := &fakeSession{}
	a := &Adapter{s: admin, mode: dbprobe.ModeLab, dial: d.dial}
	a.target = dbprobe.ConnectionConfig{Host: "db.example", Port: 3306, Database: "dbsim", TLSMode: "disable"}
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

func contains(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}

func TestAuthAfterRevokeDeniedAfterLock(t *testing.T) {
	for _, denial := range []error{myErr(3118, "Access denied for user. Account is locked."), myErr(1045, "Access denied for user")} {
		d := &dialScript{}
		d.steps = []func() (session, error){d.okSession(clockQuery), failWith(denial)}
		a, admin := revokeAdapter(t, d)
		res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeAuthAfterRevoke), revokeSpec())
		if err != nil {
			t.Fatal(err)
		}
		if !res.Denied || res.ErrorClass != "auth_failed" || res.RowsRead != 0 {
			t.Fatalf("a refused post-lock login is Denied/auth_failed: %+v", res)
		}
		if !hasNote(res.Notes, "revoke_steps=create=ok,baseline=ok,revoke=ok,reconnect=denied") {
			t.Fatalf("typed step note missing: %v", res.Notes)
		}
		create, ok := findPrefix(admin, "CREATE USER "+revokeLit+" IDENTIFIED BY '")
		if !ok {
			t.Fatalf("no CREATE USER: %v", execSQL(admin))
		}
		pw := regexp.MustCompile(`IDENTIFIED BY '([0-9a-f]+)'$`).FindStringSubmatch(create)
		if pw == nil || len(pw[1]) < 32 {
			t.Fatalf("password literal shape: %q", create)
		}
		if _, ok := findPrefix(admin, "ALTER USER "+revokeLit+" ACCOUNT LOCK"); !ok {
			t.Fatalf("revoke statement missing: %v", execSQL(admin))
		}
		if len(d.users) != 2 || d.users[0] != revokeAcct || d.users[1] != revokeAcct || d.pws[0] != pw[1] || d.pws[1] != pw[1] {
			t.Fatalf("both logins must be NEW connections as the throwaway account with its password: %v", d.users)
		}
		base := d.sess[0]
		if len(base.calls) != 1 || !strings.HasPrefix(base.calls[0].sql, "/* dbsim:dbsim-abc123 */ ") || !base.closed || !base.calls[0].hasDeadline {
			t.Fatalf("baseline must be one tagged, bounded statement on a session that is then closed: %+v", base.calls)
		}
		if res.DBTime.IsZero() {
			t.Error("DBTime must come from the tagged baseline statement")
		}
		b, _ := json.Marshal(res)
		if strings.Contains(string(b), pw[1]) {
			t.Fatalf("password leaked into the result: %s", b)
		}
		if !a.acct.mayExist || a.acct.name != revokeAcct {
			t.Fatalf("undo tracking: %+v", a.acct)
		}
	}
}

func TestAuthAfterRevokeBaselineFailureIsNeverAPass(t *testing.T) {
	d := &dialScript{}
	d.steps = []func() (session, error){failWith(myErr(1045, "Access denied"))}
	a, admin := revokeAdapter(t, d)
	res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeAuthAfterRevoke), revokeSpec())
	if err != nil {
		t.Fatal(err)
	}
	if res.Denied || res.ErrorClass != "baseline_failed" {
		t.Fatalf("a failed baseline is baseline_failed and NOT a denial: %+v", res)
	}
	if !hasNote(res.Notes, "revoke_steps=create=ok,baseline=failed,revoke=skipped,reconnect=skipped") {
		t.Fatalf("notes %v", res.Notes)
	}
	if _, ok := findPrefix(admin, "ALTER USER"); ok || len(d.users) != 1 {
		t.Fatal("nothing is revoked and nobody reconnects when the baseline did not work")
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
	if res.Denied || res.ErrorClass != "" || !hasNote(res.Notes, "revoke_steps=create=ok,baseline=ok,revoke=ok,reconnect=connected") {
		t.Fatalf("%+v", res)
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
		{"network", errors.New("dial tcp 10.0.0.5:3306: connect: connection refused")},
		{"timeout", context.DeadlineExceeded},
		{"tls", errors.New("x509: certificate signed by unknown authority")},
		{"too many connections", myErr(1040, "Too many connections")},
		{"unknown database", myErr(1049, "Unknown database")},
		{"host not allowed", myErr(1130, "Host is not allowed to connect")},
		{"unknown", errors.New("kaboom")},
	} {
		d := &dialScript{}
		d.steps = []func() (session, error){d.okSession(clockQuery), failWith(c.err)}
		a, _ := revokeAdapter(t, d)
		res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeAuthAfterRevoke), revokeSpec())
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if res.Denied || res.ErrorClass != "reconnect_error" || !hasNote(res.Notes, "revoke_steps=create=ok,baseline=ok,revoke=ok,reconnect=error") {
			t.Errorf("%s: only MySQL 1045/3118 may read as a denial: %+v", c.name, res)
		}
	}
}

func TestAuthAfterRevokeDenialClassification(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want bool
	}{
		{"1045", myErr(1045, "x"), true},
		{"3118", myErr(3118, "x"), true},
		{"1698", myErr(1698, "x"), false}, // auth plugin mismatch is not a revocation
		{"1044", myErr(1044, "x"), false},
		{"plain text", errors.New("Access denied for user"), false},
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
		if strings.HasPrefix(sql, "ALTER USER") {
			return myErr(1227, "Access denied; you need the CREATE USER privilege")
		}
		return nil
	}
	res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeAuthAfterRevoke), revokeSpec())
	if err != nil {
		t.Fatal(err)
	}
	if res.Denied || res.ErrorClass != "revoke_failed" || len(d.users) != 1 ||
		!hasNote(res.Notes, "revoke_steps=create=ok,baseline=ok,revoke=failed,reconnect=skipped") {
		t.Fatalf("%+v dials=%v", res, d.users)
	}
}

func TestAuthAfterRevokeCreateFailureTracking(t *testing.T) {
	d := &dialScript{}
	a, admin := revokeAdapter(t, d)
	admin.execFn = func(sql string) error {
		if strings.HasPrefix(sql, "CREATE USER") {
			return myErr(1396, "Operation CREATE USER failed")
		}
		return nil
	}
	res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeAuthAfterRevoke), revokeSpec())
	if err != nil {
		t.Fatal(err)
	}
	if res.ErrorClass != "account_create_failed" || res.Denied || len(d.users) != 0 ||
		!hasNote(res.Notes, "revoke_steps=create=failed,baseline=skipped,revoke=skipped,reconnect=skipped") {
		t.Fatalf("%+v", res)
	}
	if a.acct.mayExist {
		t.Fatal("a refused CREATE created nothing: no undo may be registered (R-AA)")
	}
	admin.calls = nil
	if _, err := a.Cleanup(context.Background(), emptyFixture()); err != nil {
		t.Fatal(err)
	}
	if _, ok := findPrefix(admin, "DROP USER IF EXISTS "+revokeLit); ok {
		t.Fatalf("cleanup dropped an account this call did not create: %v", execSQL(admin))
	}

	d2 := &dialScript{}
	a2, admin2 := revokeAdapter(t, d2)
	admin2.execFn = func(sql string) error {
		if strings.HasPrefix(sql, "CREATE USER") {
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
	d.steps = []func() (session, error){d.okSession(clockQuery), failWith(myErr(3118, "locked"))}
	a, admin := revokeAdapter(t, d)
	if _, err := a.RunProbe(context.Background(), def(dbprobe.ProbeAuthAfterRevoke), revokeSpec()); err != nil {
		t.Fatal(err)
	}
	admin.calls = nil
	res, err := a.Cleanup(context.Background(), emptyFixture())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findPrefix(admin, "DROP USER IF EXISTS "+revokeLit); !ok {
		t.Fatalf("throwaway account not dropped: %v", execSQL(admin))
	}
	if len(res.Residual) != 0 || !contains(res.Removed, "user:"+revokeAcct) {
		t.Fatalf("%+v", res)
	}
	if !a.acct.mayExist {
		t.Fatal("tracking must outlive cleanup so VerifyClean still inspects the account")
	}
}

func TestAuthAfterRevokeLeftoverAccountIsResidual(t *testing.T) {
	d := &dialScript{}
	d.steps = []func() (session, error){d.okSession(clockQuery), failWith(myErr(3118, "locked"))}
	a, admin := revokeAdapter(t, d)
	if _, err := a.RunProbe(context.Background(), def(dbprobe.ProbeAuthAfterRevoke), revokeSpec()); err != nil {
		t.Fatal(err)
	}
	admin.queryFn = func(sql string, args []any) ([][]any, error) {
		if sql == sqlUserExists && len(args) == 1 && args[0] == revokeAcct {
			return [][]any{{1}}, nil
		}
		return nil, nil
	}
	res, _ := a.Cleanup(context.Background(), emptyFixture())
	if !contains(res.Residual, "user:"+revokeAcct) {
		t.Fatalf("a surviving account must be reported residual: %+v", res)
	}
	objs, err := a.InspectFixture(context.Background(), emptyFixture())
	if err != nil || !contains(objs, "user:"+revokeAcct) {
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
		if len(admin.calls) != 0 || len(d.users) != 0 || a.acct.mayExist {
			t.Errorf("%s: SQL, login or undo registered on a refusal: %v %v", c.name, execSQL(admin), d.users)
		}
	}
}

func TestAuthAfterRevokeNeverTouchesConfiguredAccounts(t *testing.T) {
	d := &dialScript{}
	d.steps = []func() (session, error){d.okSession(clockQuery), failWith(myErr(3118, "locked"))}
	a, admin := revokeAdapter(t, d)
	a.target.User = "bas_target_user"
	if _, err := a.RunProbe(context.Background(), def(dbprobe.ProbeAuthAfterRevoke), revokeSpec()); err != nil {
		t.Fatal(err)
	}
	for _, s := range execSQL(admin) {
		up := strings.ToUpper(s)
		if (strings.Contains(up, "USER") || strings.Contains(up, "GRANT")) && !strings.Contains(s, revokeLit) {
			t.Errorf("statement addresses an account other than the throwaway one: %q", s)
		}
	}
}

func TestAuthAfterRevokeDialErrorRedactsThePassword(t *testing.T) {
	var pw string
	d := &dialScript{}
	a, admin := revokeAdapter(t, d)
	d.steps = []func() (session, error){func() (session, error) {
		c, _ := findPrefix(admin, "CREATE USER")
		pw = regexp.MustCompile(`'([0-9a-f]+)'$`).FindStringSubmatch(c)[1]
		return nil, errors.New("connection failed with " + pw + " in the text")
	}}
	res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeAuthAfterRevoke), revokeSpec())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(res)
	if pw == "" || strings.Contains(string(b), pw) {
		t.Fatalf("password in result: %s", b)
	}
}

// read_classified_fixture (DB-07)

func classifiedAdapter(t *testing.T, rows [][]any) (*Adapter, *fakeSession) {
	t.Helper()
	f := &fakeSession{queryFn: func(sql string, args []any) ([][]any, error) {
		if strings.Contains(sql, "UTC_TIMESTAMP") {
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
	const want = "/* dbsim:dbsim-abc123 */ SELECT * FROM `dbsim_abc123def456`.`customers_pii` LIMIT ?"
	c := findCall(t, f, "/* dbsim:dbsim-abc123 */ SELECT * FROM")
	if c.sql != want || len(c.args) != 1 || c.args[0] != dbprobe.SuspiciousReadMaxRows+1 {
		t.Fatalf("sql %q args %v", c.sql, c.args)
	}
	if res.RowsRead != 6 || res.Denied || res.ErrorClass != "" || !hasNote(res.Notes, "row_cap_applied=25") {
		t.Fatalf("%+v", res)
	}
	b, _ := json.Marshal(res)
	if strings.Contains(string(b), "000-12-3456") {
		t.Fatalf("row contents leaked: %s", b)
	}
}

func TestReadClassifiedFixtureRefusals(t *testing.T) {
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
	a3, _ := classifiedAdapter(t, nil)
	fx := classifiedFixture()
	fx.Kind = "accounts"
	_ = a3.BindFixture(fx)
	if _, err := a3.RunProbe(context.Background(), def(dbprobe.ProbeReadClassifiedFixture), classifiedSpec(5)); err == nil {
		t.Error("fixture kind mismatch accepted")
	}
}

// Live run 2: MySQL refuses (1044) a connection that names a default schema the
// account has no privilege on, and the throwaway account has none by design. Its
// baseline and post-lock connections therefore carry NO default database, while
// the adapter's own target keeps its database.
func TestThrowawayAccountDialsWithoutDefaultDatabase(t *testing.T) {
	d := &dialScript{}
	d.steps = []func() (session, error){d.okSession(clockQuery), failWith(myErr(3118, "Account is locked."))}
	a, _ := revokeAdapter(t, d)
	if _, err := a.RunProbe(context.Background(), def(dbprobe.ProbeAuthAfterRevoke), revokeSpec()); err != nil {
		t.Fatal(err)
	}
	if len(d.dbs) != 2 || d.dbs[0] != "" || d.dbs[1] != "" {
		t.Fatalf("throwaway dials must have an empty Database, got %q", d.dbs)
	}
	if a.target.Database != "dbsim" {
		t.Fatalf("the adapter target must keep its database, got %q", a.target.Database)
	}
}

func TestBuildConfigEmptyDatabaseMeansNoDefaultSchema(t *testing.T) {
	mc, _, err := buildConfig(dbprobe.ConnectionConfig{Host: "db.example", Port: 3306, Database: "", TLSMode: "disable", User: "u", Password: "p"})
	if err != nil || mc.DBName != "" {
		t.Fatalf("err=%v DBName=%q", err, mc.DBName)
	}
	mc, _, _ = buildConfig(dbprobe.ConnectionConfig{Host: "db.example", Port: 3306, Database: "dbsim", TLSMode: "disable"})
	if mc.DBName != "dbsim" {
		t.Fatalf("DBName=%q", mc.DBName)
	}
}

// 1044 (no privilege on the default schema) on the baseline is a failed baseline
// and an ERROR: it must never read as a denial, a Blocked or a pass.
func TestAuthAfterRevokeBaseline1044IsBaselineFailedNeverDenied(t *testing.T) {
	d := &dialScript{}
	d.steps = []func() (session, error){failWith(myErr(1044, "Access denied for user to database 'dbsim'"))}
	a, _ := revokeAdapter(t, d)
	res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeAuthAfterRevoke), revokeSpec())
	if err != nil || res.Denied || res.ErrorClass != "baseline_failed" {
		t.Fatalf("err=%v %+v", err, res)
	}
	if isLoginDenied(myErr(1044, "x")) {
		t.Fatal("1044 is not a login denial")
	}
}
