package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"audspect/agent/dbprobe"
)

// ---- Task 16 check_readonly_identity -------------------------------------

func identSpec(mode dbprobe.ExecMode) dbprobe.DBProbeSpec {
	return spec(dbprobe.ProbeCheckReadOnlyIdentity, mode, nil)
}

func identAdapter(mode dbprobe.ExecMode, answers map[string]func() ([][]any, error)) (*Adapter, *fakeSession) {
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
	return &Adapter{s: f, mode: mode}, f
}

func intRow(v int64) func() ([][]any, error) {
	return func() ([][]any, error) { return [][]any{{v}}, nil }
}

// identAnswers maps the five fixed catalog questions.
func identAnswers(w, d, a, super, param bool, version int64) map[string]func() ([][]any, error) {
	return map[string]func() ([][]any, error){
		"pg_write_all_data":       boolRow(w),
		"has_database_privilege":  boolRow(d),
		"rolcreaterole":           boolRow(a),
		"x.rolsuper AND":          boolRow(super),
		"has_parameter_privilege": boolRow(param),
		"server_version_num":      intRow(version),
	}
}

func TestIdentityCheckAllNoIsAClearReadOnlyIdentity(t *testing.T) {
	for _, mode := range []dbprobe.ExecMode{dbprobe.ModeClient, dbprobe.ModeLab} {
		a, f := identAdapter(mode, identAnswers(false, false, false, false, false, 160004))
		res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeCheckReadOnlyIdentity), identSpec(mode))
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		if res.Denied || res.ErrorClass != "" {
			t.Fatalf("%s: %+v", mode, res)
		}
		if !hasNote(res.Notes, "identity_checks=can_write=no,can_ddl=no,can_admin=no,can_audit=no") {
			t.Fatalf("%s: notes %v", mode, res.Notes)
		}
		if !hasPrefixCall(f, "BEGIN READ ONLY") {
			t.Fatalf("%s: catalog reads must run in a READ ONLY transaction: %v", mode, execSQL(f))
		}
		for _, c := range f.calls {
			up := strings.ToUpper(c.sql)
			if len(c.args) != 0 && !strings.Contains(c.sql, "set_config") {
				t.Errorf("%s: a parameter reached a catalog query: %q", mode, c.sql)
			}
			for _, bad := range []string{"INSERT ", "UPDATE ", "DELETE ", "CREATE ", "DROP ", "ALTER ", "GRANT ", "SET ROLE", "COPY "} {
				if strings.Contains(up, bad) && !strings.Contains(c.sql, "set_config") {
					t.Errorf("%s: statement contains %q: %q", mode, bad, c.sql)
				}
			}
		}
	}
}

func TestIdentityCheckEachCapabilityIsReportedOnItsOwn(t *testing.T) {
	cases := []struct {
		name string
		ans  map[string]func() ([][]any, error)
		want string
	}{
		{"write", identAnswers(true, false, false, false, false, 160004), "identity_checks=can_write=yes,can_ddl=no,can_admin=no,can_audit=no"},
		{"ddl", identAnswers(false, true, false, false, false, 160004), "identity_checks=can_write=no,can_ddl=yes,can_admin=no,can_audit=no"},
		{"admin", identAnswers(false, false, true, false, false, 160004), "identity_checks=can_write=no,can_ddl=no,can_admin=yes,can_audit=no"},
		{"audit via superuser", identAnswers(false, false, false, true, false, 160004), "identity_checks=can_write=no,can_ddl=no,can_admin=no,can_audit=yes"},
		{"audit via parameter privilege", identAnswers(false, false, false, false, true, 160004), "identity_checks=can_write=no,can_ddl=no,can_admin=no,can_audit=yes"},
		// Before PostgreSQL 15 there is no parameter privilege: only a superuser can change audit settings.
		{"pre-15 audit via superuser", identAnswers(false, false, false, true, false, 140010), "identity_checks=can_write=no,can_ddl=no,can_admin=no,can_audit=yes"},
		{"pre-15 clear", identAnswers(false, false, false, false, true, 140010), "identity_checks=can_write=no,can_ddl=no,can_admin=no,can_audit=no"},
	}
	for _, c := range cases {
		a, _ := identAdapter(dbprobe.ModeClient, c.ans)
		res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeCheckReadOnlyIdentity), identSpec(dbprobe.ModeClient))
		if err != nil || !hasNote(res.Notes, c.want) || res.Denied {
			t.Errorf("%s: err=%v notes=%v res=%+v", c.name, err, res.Notes, res)
		}
	}
}

func TestIdentityCheckUnobservableIsNeverNo(t *testing.T) {
	// A failing question is unknown, never "no".
	for _, key := range []string{"pg_write_all_data", "has_database_privilege", "rolcreaterole", "x.rolsuper AND", "has_parameter_privilege", "server_version_num"} {
		ans := identAnswers(false, false, false, false, false, 160004)
		ans[key] = func() ([][]any, error) { return nil, pgPerm("42501") }
		a, _ := identAdapter(dbprobe.ModeClient, ans)
		res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeCheckReadOnlyIdentity), identSpec(dbprobe.ModeClient))
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		if res.ErrorClass != "identity_check_incomplete" || strings.Contains(strings.Join(res.Notes, "|"), "identity_checks=can_write=no,can_ddl=no,can_admin=no,can_audit=no") {
			t.Errorf("%s failing must not read as a clear identity: %+v %v", key, res, res.Notes)
		}
	}
	// Wrong-shaped answer is unknown too.
	ans := identAnswers(false, false, false, false, false, 160004)
	ans["pg_write_all_data"] = func() ([][]any, error) { return nil, nil }
	a, _ := identAdapter(dbprobe.ModeClient, ans)
	res, _ := a.RunProbe(context.Background(), def(dbprobe.ProbeCheckReadOnlyIdentity), identSpec(dbprobe.ModeClient))
	if !hasNote(res.Notes, "identity_checks=can_write=unknown,can_ddl=no,can_admin=no,can_audit=no") || res.ErrorClass != "identity_check_incomplete" {
		t.Fatalf("%+v %v", res, res.Notes)
	}
	// A definite finding beats an unobservable one.
	ans = identAnswers(true, false, false, false, false, 160004)
	ans["rolcreaterole"] = func() ([][]any, error) { return nil, errors.New("boom") }
	a, _ = identAdapter(dbprobe.ModeClient, ans)
	res, _ = a.RunProbe(context.Background(), def(dbprobe.ProbeCheckReadOnlyIdentity), identSpec(dbprobe.ModeClient))
	if res.ErrorClass != "" || !hasNote(res.Notes, "identity_checks=can_write=yes,can_ddl=no,can_admin=unknown,can_audit=no") {
		t.Fatalf("%+v %v", res, res.Notes)
	}
}

func TestIdentityCheckRefusals(t *testing.T) {
	for _, c := range []struct {
		name string
		spec func(s *dbprobe.DBProbeSpec)
	}{
		{"a fixture", func(s *dbprobe.DBProbeSpec) { s.FixtureID = "accounts" }},
		{"a parameter", func(s *dbprobe.DBProbeSpec) { s.Params = map[string]string{"x": "y"} }},
	} {
		a, f := identAdapter(dbprobe.ModeClient, identAnswers(false, false, false, false, false, 160004))
		s := identSpec(dbprobe.ModeClient)
		c.spec(&s)
		if _, err := a.RunProbe(context.Background(), def(dbprobe.ProbeCheckReadOnlyIdentity), s); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
		if len(f.calls) != 0 {
			t.Errorf("%s: SQL issued on a refusal: %v", c.name, execSQL(f))
		}
	}
}
