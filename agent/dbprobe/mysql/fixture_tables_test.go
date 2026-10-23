package mysql

import (
	"context"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"audspect/agent/dbprobe"
	"audspect/agent/dbprobe/fixtures"
)

func tablesFixture(t *testing.T, name, id string) dbprobe.Fixture {
	t.Helper()
	spec, ok := fixtures.Lookup(name)
	if !ok {
		t.Fatalf("no catalog fixture %q", name)
	}
	return dbprobe.Fixture{ID: id, Kind: name, Tables: spec.Tables}
}

// Every statement Seed issues must stay inside the fixture's own schema and
// account, and no cell value may be spliced into SQL text.
func TestSeedTablesStatementsTargetOnlyFixtureSchema(t *testing.T) {
	qualified := regexp.MustCompile("`([^`]+)`\\.`")
	for _, name := range fixtures.Names() {
		f := &fakeSession{}
		a := &Adapter{s: f, mode: dbprobe.ModeLab}
		fx := tablesFixture(t, name, "ab12cd34ef56")
		if err := a.Seed(context.Background(), fx); err != nil {
			t.Fatal(name, err)
		}
		if len(f.calls) < 3 {
			t.Fatalf("%s: too few statements: %d", name, len(f.calls))
		}
		for _, c := range f.calls {
			up := strings.ToUpper(c.sql)
			for _, m := range qualified.FindAllStringSubmatch(c.sql, -1) {
				if m[1] != "dbsim_ab12cd34ef56" {
					t.Errorf("%s: statement references schema %q: %s", name, m[1], c.sql)
				}
			}
			for _, bad := range []string{"mysql.", "information_schema", "performance_schema", "`sys`"} {
				if strings.Contains(c.sql, bad) {
					t.Errorf("%s: statement touches %s: %s", name, bad, c.sql)
				}
			}
			if strings.HasPrefix(up, "CREATE SCHEMA") && !strings.Contains(c.sql, "`dbsim_ab12cd34ef56`") {
				t.Errorf("%s: %s", name, c.sql)
			}
			if strings.HasPrefix(up, "CREATE USER") && !strings.Contains(c.sql, "'dbsim_ab12cd34ef56_ro'@'%'") {
				t.Errorf("%s: %s", name, c.sql)
			}
			if strings.HasPrefix(up, "INSERT") && strings.Contains(c.sql, "'") {
				t.Errorf("%s: INSERT splices a literal: %s", name, c.sql)
			}
		}
	}
}

func TestSeedTablesBindsValuesIncludingNullAndLongText(t *testing.T) {
	f := &fakeSession{}
	a := &Adapter{s: f, mode: dbprobe.ModeLab}
	if err := a.Seed(context.Background(), tablesFixture(t, "edge", "ab12")); err != nil {
		t.Fatal(err)
	}
	var inserts [][]any
	for _, c := range f.calls {
		if strings.HasPrefix(c.sql, "INSERT") {
			inserts = append(inserts, c.args)
		}
	}
	if len(inserts) != 5 {
		t.Fatalf("inserts = %d", len(inserts))
	}
	if inserts[0][2] != nil || inserts[0][3] != nil {
		t.Errorf("NULL cells must be bound as nil: %v", inserts[0])
	}
	if s, _ := inserts[2][3].(string); len(s) != dbprobe.MaxFixtureCellBytes {
		t.Errorf("long cell len = %d", len(s))
	}
}

func TestSeedTablesInvalidSpecSendsNothing(t *testing.T) {
	f := &fakeSession{}
	a := &Adapter{s: f, mode: dbprobe.ModeLab}
	bad := dbprobe.Fixture{ID: "ab12", Tables: []dbprobe.FixtureTable{{Name: "x`; DROP DATABASE mysql", Columns: []dbprobe.FixtureColumn{{Name: "v", Type: "text"}}}}}
	if err := a.Seed(context.Background(), bad); err == nil {
		t.Fatal("invalid identifier must be refused")
	}
	if len(f.calls) != 0 {
		t.Fatalf("calls before refusal: %v", f.calls)
	}
}

func TestInspectFixtureListsObjectsWithBoundNames(t *testing.T) {
	f := &fakeSession{queryFn: func(sql string, args []any) ([][]any, error) {
		switch {
		case strings.Contains(sql, "information_schema.SCHEMATA"):
			return [][]any{{int64(1)}}, nil
		case strings.Contains(sql, "information_schema.TABLES"):
			return [][]any{{[]byte("accounts")}}, nil
		case strings.Contains(sql, "mysql.user"):
			return [][]any{{int64(1)}}, nil
		}
		return nil, nil
	}}
	a := &Adapter{s: f, mode: dbprobe.ModeLab}
	got, err := a.InspectFixture(context.Background(), dbprobe.Fixture{ID: "ab12"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"schema:dbsim_ab12", "table:dbsim_ab12.accounts", "user:dbsim_ab12_ro"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for _, c := range f.calls {
		if strings.Contains(c.sql, "dbsim_") || len(c.args) != 1 {
			t.Errorf("name must be a bound parameter: %s %v", c.sql, c.args)
		}
	}
}

func TestInspectFixtureRefusedOutsideLabAndModeReported(t *testing.T) {
	a := &Adapter{s: &fakeSession{}, mode: dbprobe.ModeClient}
	if _, err := a.InspectFixture(context.Background(), dbprobe.Fixture{ID: "ab12"}); err == nil {
		t.Fatal("inspection refused outside lab mode")
	}
	var _ dbprobe.ModeReporter = a
	var _ dbprobe.FixtureInspector = a
	if a.Mode() != dbprobe.ModeClient {
		t.Fatal("Mode must report the connection mode")
	}
}
