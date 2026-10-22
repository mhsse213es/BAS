package postgres

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"audspect/agent/dbprobe"
)

func assertTxnShape(t *testing.T, f *fakeSession, wantQuerySub string) {
	t.Helper()
	if len(f.calls) < 5 {
		t.Fatalf("too few statements: %+v", f.calls)
	}
	if f.calls[0].sql != "BEGIN READ ONLY" {
		t.Fatalf("first %q", f.calls[0].sql)
	}
	if !strings.Contains(f.calls[1].sql, "statement_timeout") || len(f.calls[1].args) != 1 || f.calls[1].args[0] != "30000" {
		t.Fatalf("timeout stmt %+v", f.calls[1])
	}
	if !strings.Contains(f.calls[2].sql, "'application_name'") {
		t.Fatalf("app name stmt %+v", f.calls[2])
	}
	found := false
	for _, c := range f.calls[3 : len(f.calls)-1] {
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
		"identity": {func(a *Adapter) error { _, err := a.Identity(context.Background()); return err }, "pg_control_system", [][]any{{"7000000000000000001"}}},
		"roles":    {func(a *Adapter) error { _, err := a.EnumerateRoles(context.Background()); return err }, "pg_roles", [][]any{{"r", true, false}}},
		"grants":   {func(a *Adapter) error { _, err := a.ReadGrants(context.Background()); return err }, "role_table_grants", [][]any{{"r", "s.t", "SELECT"}}},
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
		t.Fatal("expected error")
	}
}

func TestTLSFor(t *testing.T) {
	c, note, err := tlsFor("", "db.example")
	if err != nil || c == nil || c.InsecureSkipVerify || c.MinVersion < tls.VersionTLS12 || c.ServerName != "db.example" || note != "" {
		t.Fatalf("default: %+v %q %v", c, note, err)
	}
	c, _, err = tlsFor("verify-full", "h")
	if err != nil || c == nil || c.InsecureSkipVerify {
		t.Fatal("verify-full must verify")
	}
	c, note, err = tlsFor("insecure-skip-verify", "h")
	if err != nil || c == nil || !c.InsecureSkipVerify || !strings.Contains(note, "DISABLED") {
		t.Fatalf("insecure: %+v %q %v", c, note, err)
	}
	c, note, err = tlsFor("disable", "h")
	if err != nil || c != nil || !strings.Contains(note, "DISABLED") {
		t.Fatalf("disable: %+v %q %v", c, note, err)
	}
	for _, m := range []string{"require", "prefer", "VERIFY-FULL", "off", "x"} {
		if c, _, err := tlsFor(m, "h"); err == nil || c != nil {
			t.Errorf("unknown mode %q must fail closed", m)
		}
	}
}

func TestBuildConnConfigRecordsOptOutNotes(t *testing.T) {
	cc, notes, err := buildConnConfig(dbprobe.ConnectionConfig{Host: "h", Port: 5432, Database: "d", User: "u", TLSMode: "insecure-skip-verify"})
	if err != nil || cc == nil || len(notes) != 1 {
		t.Fatalf("%v %v %v", cc, notes, err)
	}
	if cc.TLSConfig == nil || !cc.TLSConfig.InsecureSkipVerify || len(cc.Fallbacks) != 0 {
		t.Fatalf("tls cfg %+v fallbacks %d", cc.TLSConfig, len(cc.Fallbacks))
	}
	cc, notes, err = buildConnConfig(dbprobe.ConnectionConfig{Host: "h", Port: 5432, Database: "d", User: "u"})
	if err != nil || cc.TLSConfig == nil || cc.TLSConfig.InsecureSkipVerify || len(cc.Fallbacks) != 0 || len(notes) != 0 {
		t.Fatalf("default build %+v %v %v", cc.TLSConfig, notes, err)
	}
	if _, _, err := buildConnConfig(dbprobe.ConnectionConfig{Host: "h", TLSMode: "weird"}); err == nil {
		t.Fatal("unknown tls mode accepted")
	}
}

func TestBuildConnConfigIgnoresAmbientEnv(t *testing.T) {
	dir := t.TempDir()
	svc := filepath.Join(dir, "svc.conf")
	if err := os.WriteFile(svc, []byte("[evil]\nhost=evil.example\nuser=evil\ndbname=evildb\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pgpass := filepath.Join(dir, "pgpass")
	if err := os.WriteFile(pgpass, []byte("*:*:*:*:ambient-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PGSERVICEFILE", svc)
	t.Setenv("PGSERVICE", "evil")
	t.Setenv("PGPASSFILE", pgpass)
	t.Setenv("PGOPTIONS", "-c search_path=evil")
	t.Setenv("PGTARGETSESSIONATTRS", "read-write")
	t.Setenv("PGSSLMODE", "disable")
	t.Setenv("PGAPPNAME", "evilapp")
	t.Setenv("PGPASSWORD", "ambient-pw")

	cc, _, err := buildConnConfig(dbprobe.ConnectionConfig{Host: "good.example", Port: 5432, Database: "gooddb", User: "good"})
	if err != nil {
		t.Fatal(err)
	}
	if cc.Host != "good.example" || cc.User != "good" || cc.Database != "gooddb" {
		t.Fatalf("ambient env leaked into identity: %s %s %s", cc.Host, cc.User, cc.Database)
	}
	if cc.Password != "" {
		t.Fatalf("ambient password used: %q", cc.Password)
	}
	if len(cc.RuntimeParams) != 1 || cc.RuntimeParams["application_name"] != "dbsim" {
		t.Fatalf("runtime params polluted: %v", cc.RuntimeParams)
	}
	if cc.TLSConfig == nil || len(cc.Fallbacks) != 0 {
		t.Fatal("PGSSLMODE influenced TLS")
	}
	if cc.ValidateConnect != nil || cc.AfterConnect != nil {
		t.Fatal("unexpected hooks")
	}
}

func TestPortValidation(t *testing.T) {
	for _, p := range []int{-1, 65536, 70000} {
		if _, _, err := buildConnConfig(dbprobe.ConnectionConfig{Host: "h", Port: p}); err == nil {
			t.Errorf("port %d accepted", p)
		}
	}
	cc, _, err := buildConnConfig(dbprobe.ConnectionConfig{Host: "h", Port: 0})
	if err != nil || cc.Port != 5432 {
		t.Errorf("default port: %v %v", cc, err)
	}
	cc, _, err = buildConnConfig(dbprobe.ConnectionConfig{Host: "h", Port: 65535})
	if err != nil || cc.Port != 65535 {
		t.Errorf("max port: %v %v", cc, err)
	}
}

func TestReconnectClosesOldAndKeepsModeOnFailure(t *testing.T) {
	old := &fakeSession{}
	a := &Adapter{s: old, mode: dbprobe.ModeLab}
	err := a.Connect(context.Background(), dbprobe.ConnectionConfig{Host: "127.0.0.1", Port: 1, Database: "d", User: "u",
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
	if b.mode != dbprobe.ModeLab {
		t.Error("mode mutated by invalid config")
	}
}

func TestTimeoutMarksAdapterBroken(t *testing.T) {
	f := &fakeSession{queryFn: func(sql string, args []any) ([][]any, error) {
		if strings.Contains(sql, "clock_timestamp") {
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
	if len(f.calls) != n {
		t.Fatal("SQL issued on broken adapter")
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
	if f.calls[len(f.calls)-1].sql != "ROLLBACK" {
		t.Fatalf("no rollback: %+v", f.calls)
	}
	for _, c := range f.calls {
		if !c.hasDeadline {
			t.Errorf("seed stmt %q without deadline", c.sql)
		}
	}
	f2 := &fakeSession{}
	b := &Adapter{s: f2, mode: dbprobe.ModeLab}
	if _, err := b.Cleanup(context.Background(), dbprobe.Fixture{ID: "ab12"}); err != nil {
		t.Fatal(err)
	}
	if len(f2.calls) == 0 {
		t.Fatal("no cleanup SQL")
	}
	for _, c := range f2.calls {
		if !c.hasDeadline {
			t.Errorf("cleanup stmt %q without deadline", c.sql)
		}
	}
}

const (
	leakPW   = "hunter2"
	leakHost = "db-internal-01.corp.example"
	leakUser = "svc_dbsim_probe"
)

func leakyErr() error {
	return fmt.Errorf("failed to connect to `host=%s user=%s database=x`: password=%s dsn postgres://%s:%s@%s/db?sslmode=disable dial tcp %s:5432: refused",
		leakHost, leakUser, leakPW, leakUser, leakPW, leakHost, leakHost)
}

func assertNoLeak(t *testing.T, what, s string) {
	t.Helper()
	for _, bad := range []string{leakPW, leakHost, leakUser, "postgres://"} {
		if strings.Contains(s, bad) {
			t.Errorf("%s leaks %q: %s", what, bad, s)
		}
	}
}

func newLeakAdapter(f *fakeSession) *Adapter {
	return &Adapter{s: f, mode: dbprobe.ModeClient, secrets: secretsFor(dbprobe.ConnectionConfig{Host: leakHost, User: leakUser, Password: leakPW})}
}

func TestErrorsFromDriverAreRedactedOnEveryPath(t *testing.T) {
	// Non-PG driver error on the probe query, returned through RunProbe.
	f := &fakeSession{queryFn: func(sql string, args []any) ([][]any, error) {
		if strings.Contains(sql, "clock_timestamp") {
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

	// Error from the begin step.
	f2 := &fakeSession{execFn: func(sql string) error { return leakyErr() }}
	_, err = newLeakAdapter(f2).RunProbe(context.Background(), def("auth_check"), spec("auth_check", dbprobe.ModeClient, nil))
	if err == nil {
		t.Fatal("expected begin error")
	}
	assertNoLeak(t, "begin error", err.Error())

	// Metadata helpers.
	f3 := &fakeSession{queryFn: func(sql string, args []any) ([][]any, error) {
		if strings.Contains(sql, "clock_timestamp") {
			return [][]any{{nowUTC()}}, nil
		}
		return nil, leakyErr()
	}}
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

	// Seed/Cleanup.
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
	cfg := dbprobe.ConnectionConfig{Engine: "postgresql", Host: leakHost, Port: 5432, Database: "d", User: leakUser, Password: leakPW}
	a := &Adapter{s: &fakeSession{}, mode: dbprobe.ModeClient, secrets: secretsFor(cfg)}
	for name, v := range map[string]any{"cfg": cfg, "&cfg": &cfg, "adapter": *a, "&adapter": a} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			out := fmt.Sprintf(verb, v)
			if strings.Contains(out, leakPW) {
				t.Errorf("%s %s leaks password: %s", name, verb, out)
			}
			if name == "adapter" || name == "&adapter" {
				assertNoLeak(t, name+" "+verb, out)
			}
		}
	}
}

func TestSecretsForSkipsShortIdentifiers(t *testing.T) {
	s := secretsFor(dbprobe.ConnectionConfig{Host: "h", User: "u", Password: "p"})
	if len(s) != 1 || s[0] != "p" {
		t.Fatalf("secrets %v", s)
	}
}

func nowUTC() time.Time { return time.Now().UTC() }
