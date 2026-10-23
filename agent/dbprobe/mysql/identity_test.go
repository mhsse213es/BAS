package mysql

import (
	"context"
	"errors"
	"strings"
	"testing"

	"audspect/agent/dbprobe"
)

// ---- Task 16 check_readonly_identity -------------------------------------

func identSpec(mode dbprobe.ExecMode) dbprobe.DBProbeSpec {
	return spec(dbprobe.ProbeCheckReadOnlyIdentity, mode, nil)
}

func identAdapter(mode dbprobe.ExecMode, answers map[string]func() ([][]any, error)) (*Adapter, *fakeSession) {
	f := &fakeSession{}
	f.queryFn = func(sql string, args []any) ([][]any, error) {
		for frag, fn := range answers {
			if strings.Contains(sql, frag) {
				return fn()
			}
		}
		return nil, errors.New("unexpected query: " + sql)
	}
	return &Adapter{s: f, mode: mode}, f
}

func identRows(spec ...string) func() ([][]any, error) {
	return func() ([][]any, error) {
		var out [][]any
		for _, s := range spec {
			p := strings.SplitN(s, "|", 3)
			out = append(out, []any{[]byte(p[0]), []byte(p[1]), []byte(p[2])})
		}
		return out, nil
	}
}

func identAnswers(role any, rows ...string) map[string]func() ([][]any, error) {
	return map[string]func() ([][]any, error){
		"CURRENT_ROLE":      func() ([][]any, error) { return [][]any{{role}}, nil },
		"SCHEMA_PRIVILEGES": identRows(rows...),
	}
}

func TestIdentityCheckSelectOnlyIsAClearReadOnlyIdentity(t *testing.T) {
	for _, mode := range []dbprobe.ExecMode{dbprobe.ModeClient, dbprobe.ModeLab} {
		a, f := identAdapter(mode, identAnswers([]byte("NONE"), "G||USAGE", "S|app|SELECT", "T|app|SELECT"))
		res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeCheckReadOnlyIdentity), identSpec(mode))
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		if res.Denied || res.ErrorClass != "" ||
			!hasNote(res.Notes, "identity_checks=can_write=no,can_ddl=no,can_admin=no,can_audit=no") {
			t.Fatalf("%s: %+v %v", mode, res, res.Notes)
		}
		if !hasPrefixCall(f, "START TRANSACTION READ ONLY") {
			t.Fatalf("%s: catalog reads must run in a READ ONLY transaction: %v", mode, execSQL(f))
		}
		for _, c := range f.calls {
			up := strings.ToUpper(c.sql)
			if len(c.args) != 0 {
				t.Errorf("%s: a parameter reached a catalog query: %q", mode, c.sql)
			}
			for _, bad := range []string{"INSERT ", "UPDATE ", "DELETE ", "CREATE ", "DROP ", "ALTER ", "GRANT ", "SET GLOBAL", "SET PERSIST", "LOAD "} {
				if strings.Contains(up, bad) {
					t.Errorf("%s: statement contains %q: %q", mode, bad, c.sql)
				}
			}
		}
	}
}

func TestIdentityCheckReportsEachCapability(t *testing.T) {
	cases := []struct {
		name string
		rows []string
		want string
	}{
		{"write", []string{"G||USAGE", "S|app|UPDATE"}, "identity_checks=can_write=yes,can_ddl=no,can_admin=no,can_audit=no"},
		{"ddl", []string{"G||USAGE", "S|app|ALTER"}, "identity_checks=can_write=no,can_ddl=yes,can_admin=no,can_audit=no"},
		{"admin", []string{"G||USAGE", "G||CREATE USER"}, "identity_checks=can_write=no,can_ddl=no,can_admin=yes,can_audit=no"},
		{"audit", []string{"G||USAGE", "G||SYSTEM_VARIABLES_ADMIN"}, "identity_checks=can_write=no,can_ddl=no,can_admin=yes,can_audit=yes"},
		{"mysql schema write", []string{"G||USAGE", "T|mysql|DELETE"}, "identity_checks=can_write=yes,can_ddl=no,can_admin=no,can_audit=yes"},
	}
	for _, c := range cases {
		a, _ := identAdapter(dbprobe.ModeClient, identAnswers([]byte("NONE"), c.rows...))
		res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeCheckReadOnlyIdentity), identSpec(dbprobe.ModeClient))
		if err != nil || !hasNote(res.Notes, c.want) || res.Denied || res.ErrorClass != "" {
			t.Errorf("%s: err=%v res=%+v notes=%v", c.name, err, res, res.Notes)
		}
	}
}

func TestIdentityCheckUnobservableIsNeverNo(t *testing.T) {
	allUnknown := "identity_checks=can_write=unknown,can_ddl=unknown,can_admin=unknown,can_audit=unknown"
	// An active role hides its privileges from information_schema.
	a, _ := identAdapter(dbprobe.ModeClient, identAnswers([]byte("`app_role`@`%`"), "G||USAGE"))
	res, _ := a.RunProbe(context.Background(), def(dbprobe.ProbeCheckReadOnlyIdentity), identSpec(dbprobe.ModeClient))
	if res.ErrorClass != "identity_check_incomplete" || !hasNote(res.Notes, allUnknown) {
		t.Fatalf("active role: %+v %v", res, res.Notes)
	}
	// No grantee row: the match failed.
	a, _ = identAdapter(dbprobe.ModeClient, identAnswers([]byte("NONE")))
	res, _ = a.RunProbe(context.Background(), def(dbprobe.ProbeCheckReadOnlyIdentity), identSpec(dbprobe.ModeClient))
	if res.ErrorClass != "identity_check_incomplete" || !hasNote(res.Notes, allUnknown) {
		t.Fatalf("no rows: %+v %v", res, res.Notes)
	}
	// Privilege query error.
	ans := identAnswers([]byte("NONE"), "G||USAGE")
	ans["SCHEMA_PRIVILEGES"] = func() ([][]any, error) { return nil, myErr(1227, "denied") }
	a, _ = identAdapter(dbprobe.ModeClient, ans)
	res, _ = a.RunProbe(context.Background(), def(dbprobe.ProbeCheckReadOnlyIdentity), identSpec(dbprobe.ModeClient))
	if res.ErrorClass != "identity_check_incomplete" || !hasNote(res.Notes, allUnknown) {
		t.Fatalf("query error: %+v %v", res, res.Notes)
	}
	// Role lookup failing for any reason but 1305 (5.7 has no roles) is unknown.
	ans = identAnswers([]byte("NONE"), "G||USAGE")
	ans["CURRENT_ROLE"] = func() ([][]any, error) { return nil, myErr(1227, "denied") }
	a, _ = identAdapter(dbprobe.ModeClient, ans)
	res, _ = a.RunProbe(context.Background(), def(dbprobe.ProbeCheckReadOnlyIdentity), identSpec(dbprobe.ModeClient))
	if res.ErrorClass != "identity_check_incomplete" || !hasNote(res.Notes, allUnknown) {
		t.Fatalf("role error: %+v %v", res, res.Notes)
	}
	// 5.7: CURRENT_ROLE() does not exist (1305), so no roles exist: usable.
	ans = identAnswers([]byte("NONE"), "G||USAGE", "S|app|SELECT")
	ans["CURRENT_ROLE"] = func() ([][]any, error) { return nil, myErr(1305, "FUNCTION CURRENT_ROLE does not exist") }
	a, _ = identAdapter(dbprobe.ModeClient, ans)
	res, _ = a.RunProbe(context.Background(), def(dbprobe.ProbeCheckReadOnlyIdentity), identSpec(dbprobe.ModeClient))
	if res.ErrorClass != "" || !hasNote(res.Notes, "identity_checks=can_write=no,can_ddl=no,can_admin=no,can_audit=no") {
		t.Fatalf("5.7: %+v %v", res, res.Notes)
	}
	// A truncated privilege list proves nothing.
	var many []string
	for i := 0; i < maxIdentityPrivRows; i++ {
		many = append(many, "T|app|SELECT")
	}
	a, _ = identAdapter(dbprobe.ModeClient, identAnswers([]byte("NONE"), many...))
	res, _ = a.RunProbe(context.Background(), def(dbprobe.ProbeCheckReadOnlyIdentity), identSpec(dbprobe.ModeClient))
	if res.ErrorClass != "identity_check_incomplete" || !hasNote(res.Notes, allUnknown) {
		t.Fatalf("truncated: %+v %v", res, res.Notes)
	}
	// A malformed row (wrong width) is unknown.
	ans = identAnswers([]byte("NONE"))
	ans["SCHEMA_PRIVILEGES"] = func() ([][]any, error) { return [][]any{{[]byte("G")}}, nil }
	a, _ = identAdapter(dbprobe.ModeClient, ans)
	res, _ = a.RunProbe(context.Background(), def(dbprobe.ProbeCheckReadOnlyIdentity), identSpec(dbprobe.ModeClient))
	if res.ErrorClass != "identity_check_incomplete" || !hasNote(res.Notes, allUnknown) {
		t.Fatalf("malformed: %+v %v", res, res.Notes)
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
		a, f := identAdapter(dbprobe.ModeClient, identAnswers([]byte("NONE"), "G||USAGE"))
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
