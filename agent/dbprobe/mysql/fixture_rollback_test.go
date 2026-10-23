package mysql

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"audspect/agent/dbprobe"
)

func sqls(f *fakeSession) []string {
	var out []string
	for _, c := range f.calls {
		out = append(out, c.sql)
	}
	return out
}

func anyPrefix(list []string, prefix string) bool {
	for _, s := range list {
		if strings.HasPrefix(strings.ToUpper(s), prefix) {
			return true
		}
	}
	return false
}

func fixtureVariants(t *testing.T) map[string]dbprobe.Fixture {
	return map[string]dbprobe.Fixture{
		"legacy": {ID: "ab12"},
		"tables": tablesFixture(t, "accounts", "ab12"),
	}
}

const (
	dropSchemaAB12 = "DROP SCHEMA IF EXISTS `dbsim_ab12`"
	dropUserAB12   = "DROP USER IF EXISTS 'dbsim_ab12_ro'@'%'"
)

// A pre-existing database makes CREATE SCHEMA fail. Nothing this call created
// exists, so nothing may be dropped: the pre-existing object stays untouched.
func TestSeedFirstCreateFailsDropsNothingAndIsNotCreated(t *testing.T) {
	for name, fx := range fixtureVariants(t) {
		f := &fakeSession{execFn: func(sql string) error {
			if strings.HasPrefix(sql, "CREATE SCHEMA") {
				return errors.New("Error 1007: Can't create database 'dbsim_ab12'; database exists")
			}
			return nil
		}}
		a := &Adapter{s: f, mode: dbprobe.ModeLab}
		err := a.Seed(context.Background(), fx)
		if !errors.Is(err, dbprobe.ErrFixtureNotCreated) {
			t.Fatalf("%s: err = %v, want ErrFixtureNotCreated", name, err)
		}
		got := sqls(f)
		if anyPrefix(got, "DROP") {
			t.Fatalf("%s: a DROP was issued for a pre-existing object: %v", name, got)
		}
		if len(got) != 1 || !strings.HasPrefix(got[0], "CREATE SCHEMA") {
			t.Fatalf("%s: statements = %v", name, got)
		}
	}
}

// Schema created, a later statement fails: exactly the objects this call
// created are dropped, in reverse creation order, and nothing else.
func TestSeedLaterFailureDropsOnlyWhatThisCallCreated(t *testing.T) {
	failOn := func(prefix string) func(sql string) error {
		return func(sql string) error {
			if strings.HasPrefix(sql, prefix) {
				return errors.New("boom")
			}
			return nil
		}
	}
	cases := []struct {
		name   string
		fx     dbprobe.Fixture
		fail   string
		create []string // statements issued before the drops, by prefix
		drops  []string
	}{
		{"schema then table fails", dbprobe.Fixture{ID: "ab12"}, "CREATE TABLE", []string{"CREATE SCHEMA", "CREATE TABLE"}, []string{dropSchemaAB12}},
		{"user create fails", dbprobe.Fixture{ID: "ab12"}, "CREATE USER", []string{"CREATE SCHEMA", "CREATE TABLE", "INSERT", "CREATE USER"}, []string{dropSchemaAB12}},
		{"grant fails after user", dbprobe.Fixture{ID: "ab12"}, "GRANT", []string{"CREATE SCHEMA", "CREATE TABLE", "INSERT", "CREATE USER", "GRANT"}, []string{dropUserAB12, dropSchemaAB12}},
		{"tables variant: grant fails", tablesFixture(t, "empty", "ab12"), "GRANT", nil, []string{dropUserAB12, dropSchemaAB12}},
	}
	for _, c := range cases {
		f := &fakeSession{execFn: failOn(c.fail)}
		a := &Adapter{s: f, mode: dbprobe.ModeLab}
		err := a.Seed(context.Background(), c.fx)
		if !errors.Is(err, dbprobe.ErrFixtureNotCreated) {
			t.Fatalf("%s: rollback succeeded so nothing remains: err = %v", c.name, err)
		}
		got := sqls(f)
		if len(got) < len(c.drops) || !reflect.DeepEqual(got[len(got)-len(c.drops):], c.drops) {
			t.Fatalf("%s: tail of statements = %v, want exactly %v", c.name, got, c.drops)
		}
		for i, p := range c.create {
			if !strings.HasPrefix(got[i], p) {
				t.Errorf("%s: statement %d = %q, want prefix %s", c.name, i, got[i], p)
			}
		}
		for _, s := range got {
			if strings.Contains(s, " LIKE ") || strings.Contains(s, "%'") && !strings.Contains(s, "'@'%'") {
				t.Errorf("%s: pattern in statement: %s", c.name, s)
			}
		}
	}
}

// If a rollback drop fails the state is unknown: no sentinel, caller cleans up.
// A cancelled context drops nothing at all and also is not "not created".
func TestSeedRollbackFailureOrCancelIsNotReportedAsNotCreated(t *testing.T) {
	f := &fakeSession{execFn: func(sql string) error {
		switch {
		case strings.HasPrefix(sql, "CREATE TABLE"):
			return errors.New("boom")
		case strings.HasPrefix(sql, "DROP"):
			return errors.New("drop denied")
		}
		return nil
	}}
	a := &Adapter{s: f, mode: dbprobe.ModeLab}
	err := a.Seed(context.Background(), dbprobe.Fixture{ID: "ab12"})
	if err == nil || errors.Is(err, dbprobe.ErrFixtureNotCreated) {
		t.Fatalf("failed rollback must not claim nothing was created: %v", err)
	}

	f2 := &fakeSession{execFn: func(sql string) error {
		if strings.HasPrefix(sql, "CREATE TABLE") {
			return context.Canceled
		}
		return nil
	}}
	a2 := &Adapter{s: f2, mode: dbprobe.ModeLab}
	err = a2.Seed(context.Background(), dbprobe.Fixture{ID: "ab12"})
	if err == nil || errors.Is(err, dbprobe.ErrFixtureNotCreated) {
		t.Fatalf("cancel: %v", err)
	}
	if anyPrefix(sqls(f2), "DROP") {
		t.Fatalf("no drops are attempted on a cancelled context: %v", sqls(f2))
	}
}

func TestSeedUsesPlainCreatesAndNoPatterns(t *testing.T) {
	for name, fx := range fixtureVariants(t) {
		f := &fakeSession{}
		a := &Adapter{s: f, mode: dbprobe.ModeLab}
		if err := a.Seed(context.Background(), fx); err != nil {
			t.Fatal(err)
		}
		for _, s := range sqls(f) {
			u := strings.ToUpper(s)
			if strings.Contains(u, "IF NOT EXISTS") || strings.Contains(u, " LIKE ") {
				t.Errorf("%s: statement adopts or pattern-matches: %s", name, s)
			}
		}
	}
}
