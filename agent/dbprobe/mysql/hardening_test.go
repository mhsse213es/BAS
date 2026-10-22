package mysql

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	drv "github.com/go-sql-driver/mysql"

	"audspect/agent/dbprobe"
)

func assertTxnShape(t *testing.T, f *fakeSession, wantQuerySub string) {
	t.Helper()
	if len(f.calls) < 4 {
		t.Fatalf("too few statements: %+v", f.calls)
	}
	if f.calls[0].sql != "START TRANSACTION READ ONLY" {
		t.Fatalf("first %q", f.calls[0].sql)
	}
	if f.calls[1].sql != "SET SESSION max_execution_time = 30000" {
		t.Fatalf("time limit stmt %q", f.calls[1].sql)
	}
	found := false
	for _, c := range f.calls[2 : len(f.calls)-1] {
		if strings.HasPrefix(c.sql, "/* dbsim:") && strings.Contains(c.sql, wantQuerySub) {
			found = true
		}
	}
	if !found {
		t.Fatalf("query with marker comment %q not found: %+v", wantQuerySub, f.calls)
	}
	if f.calls[len(f.calls)-1].sql != "ROLLBACK" {
		t.Fatalf("last %q", f.calls[len(f.calls)-1].sql)
	}
	for i, c := range f.calls {
		if !c.hasDeadline {
			t.Errorf("call %d (%q) ran without a deadline", i, c.sql)
		}
	}
}

func TestMetadataQueriesRunInReadOnlyTxnClientMode(t *testing.T) {
	cases := map[string]struct {
		run  func(a *Adapter) error
		want string
		resp [][]any
	}{
		"identity": {func(a *Adapter) error { _, err := a.Identity(context.Background()); return err }, "@@server_uuid", [][]any{{[]byte("11111111-2222-3333-4444-555555555555")}}},
		"roles":    {func(a *Adapter) error { _, err := a.EnumerateRoles(context.Background()); return err }, "mysql.user", [][]any{{[]byte("r"), []byte("%"), int64(1), int64(0)}}},
		"grants":   {func(a *Adapter) error { _, err := a.ReadGrants(context.Background()); return err }, "TABLE_PRIVILEGES", [][]any{{[]byte("'r'@'%'"), []byte("s.t"), []byte("SELECT")}}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := &fakeSession{queryFn: func(sql string, args []any) ([][]any, error) {
				if strings.Contains(sql, c.want) {
					return c.resp, nil
				}
				return nil, nil
			}}
			a := &Adapter{s: f, mode: dbprobe.ModeClient}
			if err := c.run(a); err != nil {
				t.Fatal(err)
			}
			assertTxnShape(t, f, c.want)
		})
	}
}

func TestMetadataQueriesRefuseWhenNotConnected(t *testing.T) {
	a := New()
	if _, err := a.Identity(context.Background()); err == nil {
		t.Fatal("identity")
	}
	if _, err := a.EnumerateRoles(context.Background()); err == nil {
		t.Fatal("roles")
	}
	if _, err := a.ReadGrants(context.Background()); err == nil {
		t.Fatal("grants")
	}
}

func TestIdentityValueAndFailClosed(t *testing.T) {
	const uuid = "11111111-2222-3333-4444-555555555555"
	f := &fakeSession{queryFn: func(sql string, args []any) ([][]any, error) {
		return [][]any{{[]byte(uuid)}}, nil
	}}
	got, err := (&Adapter{s: f, mode: dbprobe.ModeClient}).Identity(context.Background())
	if err != nil || got != uuid {
		t.Fatalf("%q %v", got, err)
	}
	// MariaDB: no @@server_uuid -> error 1193 -> clear error, never an identity.
	f2 := &fakeSession{queryFn: func(sql string, args []any) ([][]any, error) {
		return nil, mysqlErr(1193, "Unknown system variable 'server_uuid'")
	}}
	got, err = (&Adapter{s: f2, mode: dbprobe.ModeClient}).Identity(context.Background())
	if err == nil || got != "" || !strings.Contains(err.Error(), "server_uuid") || !strings.Contains(err.Error(), "MariaDB") {
		t.Fatalf("expected clear MariaDB error, got %q %v", got, err)
	}
	// Empty or NULL value also fails closed.
	for _, rows := range [][][]any{nil, {{nil}}, {{[]byte("")}}, {{[]byte("a")}, {[]byte("b")}}} {
		rows := rows
		f3 := &fakeSession{queryFn: func(sql string, args []any) ([][]any, error) { return rows, nil }}
		if got, err := (&Adapter{s: f3, mode: dbprobe.ModeClient}).Identity(context.Background()); err == nil || got != "" {
			t.Errorf("rows %v: want error, got %q %v", rows, got, err)
		}
	}
}

func TestMetadataOverflowIsAnErrorNotSilentTruncation(t *testing.T) {
	f := &fakeSession{queryFn: func(sql string, args []any) ([][]any, error) {
		rows := make([][]any, metaLimits.MaxRows+1)
		for i := range rows {
			rows[i] = []any{[]byte("r"), []byte("h"), int64(0), int64(0)}
		}
		return rows, nil
	}}
	if _, err := (&Adapter{s: f, mode: dbprobe.ModeClient}).EnumerateRoles(context.Background()); err == nil {
		t.Fatal("overflow silently truncated")
	}
}

func TestToRolesAndGrants(t *testing.T) {
	roles := toRoles([][]any{
		{[]byte("root"), []byte("localhost"), int64(1), int64(1)},
		{[]byte("app"), []byte("%"), int64(1), int64(0)},
		{[]byte("lock"), []byte("%"), int64(0), int64(0)},
		{[]byte("short")},
	})
	if len(roles) != 3 {
		t.Fatalf("%+v", roles)
	}
	if roles[0].Name != "root@localhost" || !roles[0].Login || !roles[0].Superuser {
		t.Errorf("%+v", roles[0])
	}
	if roles[1].Name != "app" || !roles[1].Login || roles[1].Superuser {
		t.Errorf("%+v", roles[1])
	}
	if roles[2].Login {
		t.Errorf("%+v", roles[2])
	}
	gs := toGrants([][]any{{[]byte("'r'@'%'"), []byte("s.t"), []byte("SELECT")}, {[]byte("x")}})
	if len(gs) != 1 || gs[0].Role != "r" || gs[0].Object != "s.t" || gs[0].Privilege != "SELECT" {
		t.Fatalf("%+v", gs)
	}
}

func TestTLSFor(t *testing.T) {
	c, note, err := tlsFor("", "db.example")
	if err != nil || c == nil || c.InsecureSkipVerify || c.MinVersion < tls.VersionTLS12 || c.ServerName != "db.example" || note != "" {
		t.Fatalf("default: %+v %q %v", c, note, err)
	}
	c, _, err = tlsFor("verify-full", "h")
	if err != nil || c == nil || c.InsecureSkipVerify || c.ServerName != "h" {
		t.Fatal("verify-full must verify")
	}
	c, note, err = tlsFor("insecure-skip-verify", "h")
	if err != nil || c == nil || !c.InsecureSkipVerify || !strings.Contains(note, "DISABLED") || c.MinVersion < tls.VersionTLS12 {
		t.Fatalf("insecure: %+v %q %v", c, note, err)
	}
	c, note, err = tlsFor("disable", "h")
	if err != nil || c != nil || !strings.Contains(note, "DISABLED") {
		t.Fatalf("disable: %+v %q %v", c, note, err)
	}
	for _, m := range []string{"require", "prefer", "preferred", "skip-verify", "true", "false", "VERIFY-FULL", "off", "x"} {
		if c, _, err := tlsFor(m, "h"); err == nil || c != nil {
			t.Errorf("unknown mode %q must fail closed", m)
		}
	}
	if _, _, err := tlsFor("", ""); err == nil {
		t.Error("verifying TLS needs a host for ServerName")
	}
}

func TestBuildConfigFieldByFieldNoDSN(t *testing.T) {
	cfg := dbprobe.ConnectionConfig{Host: "db.example", Port: 3307, Database: "app", User: "u@x:y/z", Password: "p@ss:w/ord(", TLSMode: "insecure-skip-verify"}
	mc, notes, err := buildConfig(cfg)
	if err != nil || mc == nil || len(notes) != 1 {
		t.Fatalf("%v %v %v", mc, notes, err)
	}
	// Characters that would corrupt a DSN are carried verbatim in fields.
	if mc.User != cfg.User || mc.Passwd != cfg.Password || mc.DBName != "app" || mc.Addr != "db.example:3307" || mc.Net != "tcp" {
		t.Fatalf("fields wrong: user=%q addr=%q net=%q", mc.User, mc.Addr, mc.Net)
	}
	if mc.TLS == nil || !mc.TLS.InsecureSkipVerify {
		t.Fatal("tls opt-out not applied")
	}
	if mc.AllowFallbackToPlaintext || mc.AllowAllFiles || mc.AllowCleartextPasswords || mc.AllowOldPasswords || mc.MultiStatements || mc.InterpolateParams {
		t.Fatalf("unsafe driver option enabled: %+v", mc)
	}
	if len(mc.Params) != 0 {
		t.Fatalf("unexpected session params %v", mc.Params)
	}
	if mc.ConnectionAttributes != "program_name:dbsim" {
		t.Fatalf("attrs %q", mc.ConnectionAttributes)
	}
	mc, notes, err = buildConfig(dbprobe.ConnectionConfig{Host: "h", Port: 3306})
	if err != nil || mc.TLS == nil || mc.TLS.InsecureSkipVerify || mc.TLS.ServerName != "h" || mc.AllowFallbackToPlaintext || len(notes) != 0 {
		t.Fatalf("default build %+v %v %v", mc.TLS, notes, err)
	}
	mc, notes, err = buildConfig(dbprobe.ConnectionConfig{Host: "h", TLSMode: "disable"})
	if err != nil || mc.TLS != nil || mc.TLSConfig != "" || len(notes) != 1 {
		t.Fatalf("disable build %+v %v %v", mc.TLS, notes, err)
	}
	if _, _, err := buildConfig(dbprobe.ConnectionConfig{Host: "h", TLSMode: "weird"}); err == nil {
		t.Fatal("unknown tls mode accepted")
	}
	if _, _, err := buildConfig(dbprobe.ConnectionConfig{Host: ""}); err == nil {
		t.Fatal("empty host accepted")
	}
	mc, _, err = buildConfig(dbprobe.ConnectionConfig{Host: "::1", Port: 3306})
	if err != nil || mc.Addr != "[::1]:3306" {
		t.Fatalf("ipv6 addr %v %v", mc, err)
	}
}

// The go-sql-driver/mysql version pinned in go.mod (v1.10.1) was read: it has no
// os.Getenv/LookupEnv calls and never opens my.cnf / .my.cnf / login paths; the
// only os.Open is LOAD DATA LOCAL INFILE (disabled; AllowAllFiles false). So
// MYSQL_* variables and option files cannot influence a connection. This test
// asserts the adapter side (config built only from ConnectionConfig) and, when
// the module cache is reachable, re-checks the driver source.
func TestBuildConfigIgnoresAmbientEnv(t *testing.T) {
	dir := t.TempDir()
	cnf := filepath.Join(dir, "my.cnf")
	if err := os.WriteFile(cnf, []byte("[client]\nhost=evil.example\nuser=evil\npassword=ambient-secret\ndatabase=evildb\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{
		"MYSQL_HOST": "evil.example", "MYSQL_PWD": "ambient-pw", "MYSQL_TCP_PORT": "1", "MYSQL_HOME": dir,
		"MYSQL_UNIX_PORT": "/tmp/evil.sock", "MYSQL_DATABASE": "evildb", "MYSQL_USER": "evil",
		"MYSQL_GROUP_SUFFIX": "evil", "HOME": dir, "USERPROFILE": dir, "MYSQL_SSL_MODE": "DISABLED",
	} {
		t.Setenv(k, v)
	}
	mc, _, err := buildConfig(dbprobe.ConnectionConfig{Host: "good.example", Port: 3306, Database: "gooddb", User: "good"})
	if err != nil {
		t.Fatal(err)
	}
	if mc.Addr != "good.example:3306" || mc.User != "good" || mc.DBName != "gooddb" || mc.Passwd != "" || mc.Net != "tcp" {
		t.Fatalf("ambient env leaked: %+v", mc)
	}
	if mc.TLS == nil {
		t.Fatal("MYSQL_SSL_MODE influenced TLS")
	}
}

func TestDriverSourceReadsNoAmbientConfig(t *testing.T) {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/go-sql-driver/mysql").Output()
	dir := strings.TrimSpace(string(out))
	if err != nil || dir == "" {
		t.Skipf("module cache not reachable: %v", err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
	if len(files) == 0 {
		t.Skip("no driver sources")
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		for _, bad := range []string{"os.Getenv", "os.LookupEnv", "os.Environ", "my.cnf", "UserHomeDir"} {
			if strings.Contains(src, bad) {
				t.Errorf("%s uses %s: ambient configuration is possible", filepath.Base(f), bad)
			}
		}
	}
}

func TestPortValidation(t *testing.T) {
	for _, p := range []int{-1, 65536, 70000} {
		if _, _, err := buildConfig(dbprobe.ConnectionConfig{Host: "h", Port: p}); err == nil {
			t.Errorf("port %d accepted", p)
		}
	}
	mc, _, err := buildConfig(dbprobe.ConnectionConfig{Host: "h", Port: 0})
	if err != nil || mc.Addr != "h:3306" {
		t.Errorf("default port: %v %v", mc, err)
	}
	mc, _, err = buildConfig(dbprobe.ConnectionConfig{Host: "h", Port: 65535})
	if err != nil || mc.Addr != "h:65535" {
		t.Errorf("max port: %v %v", mc, err)
	}
}

func TestReconnectClosesOldAndKeepsModeOnFailure(t *testing.T) {
	host, port := closedPort(t)
	old := &fakeSession{}
	a := &Adapter{s: old, mode: dbprobe.ModeLab}
	err := a.Connect(context.Background(), dbprobe.ConnectionConfig{Host: host, Port: port, Database: "d", User: "u",
		TLSMode: "disable", Mode: dbprobe.ModeClient})
	if err == nil {
		t.Fatal("expected failure")
	}
	if !old.closed {
		t.Error("old connection not closed")
	}
	if a.mode != dbprobe.ModeLab {
		t.Errorf("mode mutated to %q on failed connect", a.mode)
	}
	if a.s != nil {
		t.Error("stale session kept")
	}
	// Invalid config must not touch the existing connection or mode.
	old2 := &fakeSession{}
	b := &Adapter{s: old2, mode: dbprobe.ModeLab}
	if err := b.Connect(context.Background(), dbprobe.ConnectionConfig{Host: "h", Port: 70000, Mode: dbprobe.ModeClient}); err == nil {
		t.Fatal("bad port accepted")
	}
	if b.mode != dbprobe.ModeLab || old2.closed {
		t.Error("invalid config disturbed existing state")
	}
	// Mode must be exactly lab or client.
	if err := New().Connect(context.Background(), dbprobe.ConnectionConfig{Host: "h", Mode: "weird"}); err == nil {
		t.Error("unknown mode accepted")
	}
}

func TestTimeoutMarksAdapterBroken(t *testing.T) {
	f := &fakeSession{queryFn: func(sql string, args []any) ([][]any, error) {
		if strings.Contains(sql, "UTC_TIMESTAMP") {
			return [][]any{{nowUTC()}}, nil
		}
		return nil, context.DeadlineExceeded
	}}
	a := &Adapter{s: f, mode: dbprobe.ModeClient}
	res, err := a.RunProbe(context.Background(), def("auth_check"), spec("auth_check", dbprobe.ModeClient, nil))
	if err != nil {
		t.Fatal(err)
	}
	if res.ErrorClass != "timeout" {
		t.Fatalf("%+v", res)
	}
	if !strings.Contains(strings.Join(res.Notes, "|"), "connection closed") {
		t.Fatalf("notes %v", res.Notes)
	}
	if !f.closed {
		t.Fatal("connection not closed")
	}
	n := len(f.calls)
	if f.calls[n-1].sql == "ROLLBACK" {
		t.Fatal("ROLLBACK attempted on dead connection")
	}
	if _, err := a.RunProbe(context.Background(), def("auth_check"), spec("auth_check", dbprobe.ModeClient, nil)); err == nil || !strings.Contains(err.Error(), "reconnect") {
		t.Fatalf("expected clear broken error, got %v", err)
	}
	if _, err := a.Identity(context.Background()); err == nil {
		t.Fatal("identity on broken adapter")
	}
	if _, err := a.EnumerateRoles(context.Background()); err == nil {
		t.Fatal("roles on broken adapter")
	}
	if err := a.Seed(context.Background(), dbprobe.Fixture{ID: "ab12"}); err == nil {
		t.Fatal("seed on broken adapter")
	}
	if len(f.calls) != n {
		t.Fatal("SQL issued on broken adapter")
	}
}

func TestCancelVsTimeoutClassPreserved(t *testing.T) {
	// A canceled parent context: the result class is "canceled" and the chain
	// of a metadata error still satisfies errors.Is(context.Canceled).
	ctx, cancel := context.WithCancel(context.Background())
	f := &fakeSession{queryFn: func(sql string, args []any) ([][]any, error) {
		if strings.Contains(sql, "UTC_TIMESTAMP") {
			return [][]any{{nowUTC()}}, nil
		}
		cancel()
		return nil, fmt.Errorf("query: %w", ctx.Err())
	}}
	a := &Adapter{s: f, mode: dbprobe.ModeClient}
	res, err := a.RunProbe(ctx, def("auth_check"), spec("auth_check", dbprobe.ModeClient, nil))
	if err != nil || res.ErrorClass != "canceled" {
		t.Fatalf("probe: %+v %v", res, err)
	}

	ctx2, cancel2 := context.WithCancel(context.Background())
	f2 := &fakeSession{queryFn: func(sql string, args []any) ([][]any, error) {
		cancel2()
		return nil, ctx2.Err()
	}}
	_, err = (&Adapter{s: f2, mode: dbprobe.ModeClient}).Identity(ctx2)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel class lost from metadata error: %v", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancel misclassified as timeout: %v", err)
	}
	// Driver-style error that does not wrap ctx errors, but the context is dead.
	ctx3, cancel3 := context.WithCancel(context.Background())
	f3 := &fakeSession{queryFn: func(sql string, args []any) ([][]any, error) {
		cancel3()
		return nil, errors.New("invalid connection")
	}}
	_, err = (&Adapter{s: f3, mode: dbprobe.ModeClient}).Identity(ctx3)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel class lost when driver hides it: %v", err)
	}
}

func TestSeedAndCleanupUseDeadlines(t *testing.T) {
	f := &fakeSession{execFn: func(sql string) error {
		if strings.HasPrefix(sql, "CREATE TABLE") {
			return errors.New("boom")
		}
		return nil
	}}
	a := &Adapter{s: f, mode: dbprobe.ModeLab}
	if err := a.Seed(context.Background(), dbprobe.Fixture{ID: "ab12"}); err == nil {
		t.Fatal("expected seed failure")
	}
	// MySQL DDL cannot roll back: a failed seed must best-effort drop what it made.
	var dropped bool
	for _, c := range f.calls {
		if strings.HasPrefix(c.sql, "DROP SCHEMA IF EXISTS `dbsim_ab12`") {
			dropped = true
		}
		if !c.hasDeadline {
			t.Errorf("seed stmt %q without deadline", c.sql)
		}
	}
	if !dropped {
		t.Errorf("failed seed left schema behind: %+v", f.calls)
	}
	f2 := &fakeSession{}
	b := &Adapter{s: f2, mode: dbprobe.ModeLab}
	res, err := b.Cleanup(context.Background(), dbprobe.Fixture{ID: "ab12"})
	if err != nil {
		t.Fatal(err)
	}
	if len(f2.calls) == 0 || len(res.Residual) != 0 || len(res.Removed) != 2 {
		t.Fatalf("calls=%d res=%+v", len(f2.calls), res)
	}
	var sawVerify bool
	for _, c := range f2.calls {
		if !c.hasDeadline {
			t.Errorf("cleanup stmt %q without deadline", c.sql)
		}
		if strings.Contains(c.sql, "information_schema.SCHEMATA") && len(c.args) == 1 && c.args[0] == "dbsim_ab12" {
			sawVerify = true
		}
	}
	if !sawVerify {
		t.Error("cleanup did not verify the schema is gone")
	}
	// A schema that is still there after DROP is residual (safety incident).
	f3 := &fakeSession{queryFn: func(sql string, args []any) ([][]any, error) {
		return [][]any{{int64(1)}}, nil
	}}
	res, _ = (&Adapter{s: f3, mode: dbprobe.ModeLab}).Cleanup(context.Background(), dbprobe.Fixture{ID: "ab12"})
	if len(res.Residual) != 2 {
		t.Fatalf("residual not reported: %+v", res)
	}
}

const (
	leakPW   = "hunter2"
	leakHost = "db-internal-01.corp.example"
	leakUser = "svc_dbsim_probe"
)

func leakyErr() error {
	return fmt.Errorf("Error 1045 (28000): Access denied for user '%s'@'%s' (using password: YES) dsn %s:%s@tcp(%s:3306)/db?tls=true dial tcp %s:3306: refused password=%s",
		leakUser, leakHost, leakUser, leakPW, leakHost, leakHost, leakPW)
}

func mysqlErr(num uint16, msg string) error { return &drv.MySQLError{Number: num, Message: msg} }

func assertNoLeak(t *testing.T, what, s string) {
	t.Helper()
	for _, bad := range []string{leakPW, leakHost, leakUser, "@tcp("} {
		if strings.Contains(s, bad) {
			t.Errorf("%s leaks %q: %s", what, bad, s)
		}
	}
}

func newLeakAdapter(f *fakeSession) *Adapter {
	return &Adapter{s: f, mode: dbprobe.ModeClient, scrub: newScrubber(secretsFor(dbprobe.ConnectionConfig{Host: leakHost, User: leakUser, Password: leakPW}))}
}

func TestErrorsFromDriverAreRedactedOnEveryPath(t *testing.T) {
	f := &fakeSession{queryFn: func(sql string, args []any) ([][]any, error) {
		if strings.Contains(sql, "UTC_TIMESTAMP") {
			return [][]any{{nowUTC()}}, nil
		}
		return nil, leakyErr()
	}}
	a := newLeakAdapter(f)
	res, err := a.RunProbe(context.Background(), def("auth_check"), spec("auth_check", dbprobe.ModeClient, nil))
	if err == nil {
		t.Fatal("expected error")
	}
	assertNoLeak(t, "RunProbe error", err.Error())
	assertNoLeak(t, "RunProbe notes", strings.Join(res.Notes, "|"))

	f2 := &fakeSession{execFn: func(sql string) error { return leakyErr() }}
	_, err = newLeakAdapter(f2).RunProbe(context.Background(), def("auth_check"), spec("auth_check", dbprobe.ModeClient, nil))
	if err == nil {
		t.Fatal("expected begin error")
	}
	assertNoLeak(t, "begin error", err.Error())

	f3 := &fakeSession{queryFn: func(sql string, args []any) ([][]any, error) { return nil, leakyErr() }}
	a3 := newLeakAdapter(f3)
	if _, err := a3.Identity(context.Background()); err == nil {
		t.Fatal("identity should fail")
	} else {
		assertNoLeak(t, "identity error", err.Error())
	}
	if _, err := a3.EnumerateRoles(context.Background()); err == nil {
		t.Fatal("roles should fail")
	} else {
		assertNoLeak(t, "roles error", err.Error())
	}
	if _, err := a3.ReadGrants(context.Background()); err == nil {
		t.Fatal("grants should fail")
	} else {
		assertNoLeak(t, "grants error", err.Error())
	}

	f4 := &fakeSession{execFn: func(sql string) error { return leakyErr() }}
	a4 := newLeakAdapter(f4)
	a4.mode = dbprobe.ModeLab
	if err := a4.Seed(context.Background(), dbprobe.Fixture{ID: "ab12"}); err == nil {
		t.Fatal("seed should fail")
	} else {
		assertNoLeak(t, "seed error", err.Error())
	}
	cr, err := a4.Cleanup(context.Background(), dbprobe.Fixture{ID: "ab12"})
	if err != nil {
		t.Fatal(err)
	}
	assertNoLeak(t, "cleanup result", cr.Error+strings.Join(cr.Residual, ","))
}

func TestFormattingNeverShowsSecrets(t *testing.T) {
	cfg := dbprobe.ConnectionConfig{Engine: "mysql", Host: leakHost, Port: 3306, Database: "d", User: leakUser, Password: leakPW}
	a := &Adapter{s: &fakeSession{}, mode: dbprobe.ModeClient, scrub: newScrubber(secretsFor(cfg))}
	type holder struct{ A *Adapter }
	for name, v := range map[string]any{"cfg": cfg, "&cfg": &cfg, "adapter": *a, "&adapter": a, "holder": holder{a}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			out := fmt.Sprintf(verb, v)
			if strings.Contains(out, leakPW) {
				t.Errorf("%s %s leaks password: %s", name, verb, out)
			}
			if strings.HasPrefix(name, "adapter") || name == "&adapter" {
				assertNoLeak(t, name+" "+verb, out)
			}
		}
	}
	if !strings.Contains(a.String(), "mysql.Adapter") {
		t.Errorf("String: %s", a.String())
	}
}

func TestSecretsForSkipsShortIdentifiers(t *testing.T) {
	s := secretsFor(dbprobe.ConnectionConfig{Host: "h", User: "u", Password: "p"})
	if len(s) != 1 || s[0] != "p" {
		t.Fatalf("secrets %v", s)
	}
}
