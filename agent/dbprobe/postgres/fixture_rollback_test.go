package postgres

import (
	"context"
	"errors"
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

// A pre-existing schema makes CREATE SCHEMA fail; nothing is dropped and the
// sentinel says nothing of ours exists. PG DDL is transactional, so the
// failure path is ROLLBACK, never DROP.
func TestSeedFirstCreateFailsDropsNothingAndIsNotCreated(t *testing.T) {
	for name, fx := range fixtureVariants(t) {
		f := &fakeSession{execFn: func(sql string) error {
			if strings.HasPrefix(sql, "CREATE SCHEMA") {
				return errors.New(`schema "dbsim_ab12" already exists`)
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
		if len(got) != 3 || got[0] != "BEGIN" || !strings.HasPrefix(got[1], "CREATE SCHEMA") || got[2] != "ROLLBACK" {
			t.Fatalf("%s: statements = %v", name, got)
		}
	}
}

// A later statement fails: the transaction is rolled back (nothing created by
// this call survives, nothing else is touched), no DROP at all.
func TestSeedLaterStatementFailsRollsBackOnlyNoDrop(t *testing.T) {
	for name, fx := range fixtureVariants(t) {
		f := &fakeSession{execFn: func(sql string) error {
			if strings.HasPrefix(sql, "CREATE ROLE") {
				return errors.New(`role "dbsim_ab12_ro" already exists`)
			}
			return nil
		}}
		a := &Adapter{s: f, mode: dbprobe.ModeLab}
		err := a.Seed(context.Background(), fx)
		if !errors.Is(err, dbprobe.ErrFixtureNotCreated) {
			t.Fatalf("%s: err = %v", name, err)
		}
		got := sqls(f)
		if anyPrefix(got, "DROP") {
			t.Fatalf("%s: DROP issued: %v", name, got)
		}
		if got[len(got)-1] != "ROLLBACK" || got[0] != "BEGIN" {
			t.Fatalf("%s: statements = %v", name, got)
		}
		if anyPrefix(got, "COMMIT") {
			t.Fatalf("%s: committed a failed seed", name)
		}
	}
}

// If the rollback itself fails, or the outcome is unknown (commit failure,
// cancelled context), the state is NOT known to be empty: no sentinel, so the
// caller cleans up.
func TestSeedUnknownStateIsNotReportedAsNotCreated(t *testing.T) {
	cases := map[string]func(sql string) error{
		"rollback fails": func(sql string) error {
			switch {
			case strings.HasPrefix(sql, "CREATE ROLE"):
				return errors.New("boom")
			case sql == "ROLLBACK":
				return errors.New("rollback failed")
			}
			return nil
		},
		"commit fails": func(sql string) error {
			if sql == "COMMIT" {
				return errors.New("commit failed")
			}
			return nil
		},
		"context cancelled": func(sql string) error {
			if strings.HasPrefix(sql, "CREATE SCHEMA") {
				return context.Canceled
			}
			return nil
		},
	}
	for name, fn := range cases {
		f := &fakeSession{execFn: fn}
		a := &Adapter{s: f, mode: dbprobe.ModeLab}
		err := a.Seed(context.Background(), dbprobe.Fixture{ID: "ab12"})
		if err == nil || errors.Is(err, dbprobe.ErrFixtureNotCreated) {
			t.Errorf("%s: err = %v; unknown state must not claim nothing was created", name, err)
		}
	}
}

// Exact-name only: no statement the adapter issues for a fixture uses LIKE or a
// wildcard, and every CREATE is a plain CREATE (no IF NOT EXISTS adoption).
func TestSeedUsesPlainCreatesAndNoPatterns(t *testing.T) {
	for name, fx := range fixtureVariants(t) {
		f := &fakeSession{}
		a := &Adapter{s: f, mode: dbprobe.ModeLab}
		if err := a.Seed(context.Background(), fx); err != nil {
			t.Fatal(err)
		}
		for _, s := range sqls(f) {
			u := strings.ToUpper(s)
			if strings.Contains(u, "IF NOT EXISTS") || strings.Contains(u, " LIKE ") || strings.Contains(u, "%") {
				t.Errorf("%s: statement adopts or pattern-matches: %s", name, s)
			}
		}
	}
}
