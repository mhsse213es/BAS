package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	"audspect/agent/dbprobe"
)

// txnFake models what PostgreSQL does for these statements: BEGIN takes a snapshot,
// statements change the pending state, COMMIT publishes it, ROLLBACK discards it. An
// unrecognised statement is accepted and has no effect. failOn makes a matching
// statement return an error, to simulate a refused step.
type txnFake struct {
	committed map[string]bool
	pending   map[string]bool
	inTxn     bool
	begins    int
	commits   int
	rollbacks int
	failOn    string
}

func newTxnFake() *txnFake { return &txnFake{committed: map[string]bool{}} }

func stripComment(sql string) string {
	if strings.HasPrefix(sql, "/*") {
		if i := strings.Index(sql, "*/"); i >= 0 {
			return strings.TrimSpace(sql[i+2:])
		}
	}
	return strings.TrimSpace(sql)
}

func between(s, from, to string) string {
	s = strings.TrimPrefix(s, from)
	if i := strings.Index(s, to); i >= 0 {
		return s[:i]
	}
	return s
}

func (f *txnFake) state() map[string]bool {
	if f.inTxn {
		return f.pending
	}
	return f.committed
}

func (f *txnFake) Exec(_ context.Context, sql string, _ ...any) error {
	s := stripComment(sql)
	if f.failOn != "" && strings.Contains(s, f.failOn) {
		return errors.New("refused: " + f.failOn)
	}
	switch {
	case strings.HasPrefix(s, "BEGIN"):
		f.begins++
		f.inTxn = true
		f.pending = map[string]bool{}
		for k, v := range f.committed {
			f.pending[k] = v
		}
	case s == "COMMIT":
		if f.inTxn {
			f.committed = f.pending
			f.inTxn = false
			f.commits++
		}
	case s == "ROLLBACK":
		f.inTxn = false
		f.rollbacks++
	case strings.HasPrefix(s, "CREATE TABLE "):
		t := between(s, "CREATE TABLE ", " (")
		if f.state()["table:"+t] {
			return errors.New("relation already exists")
		}
		f.state()["table:"+t] = true
	case strings.HasPrefix(s, "DROP TABLE "):
		t := strings.TrimPrefix(s, "DROP TABLE ")
		if !f.state()["table:"+t] {
			return errors.New("relation does not exist")
		}
		delete(f.state(), "table:"+t)
	case strings.HasPrefix(s, "GRANT SELECT ON "):
		f.state()["grant:"+between(s, "GRANT SELECT ON ", " TO ")] = true
	case strings.HasPrefix(s, "REVOKE SELECT ON "):
		delete(f.state(), "grant:"+between(s, "REVOKE SELECT ON ", " FROM "))
	}
	return nil
}

func (f *txnFake) Query(_ context.Context, _ string, _ int, _ ...any) ([][]any, error) {
	return nil, nil
}

func (f *txnFake) Close(_ context.Context) error { return nil }

func roundtripAdapter(t *testing.T, f *txnFake) *Adapter {
	t.Helper()
	a := &Adapter{s: f, mode: dbprobe.ModeLab}
	if err := a.BindFixture(dbprobe.Fixture{ID: "ab12", Kind: "accounts", Tables: []dbprobe.FixtureTable{{Name: "accounts", Columns: []dbprobe.FixtureColumn{{Name: "id", Type: "int", PK: true}}}}}); err != nil {
		t.Fatal(err)
	}
	return a
}

func runRoundtrip(t *testing.T, a *Adapter, probe string) dbprobe.ProbeResult {
	t.Helper()
	def, ok := dbprobe.LookupProbe(probe)
	if !ok {
		t.Fatal("probe not in catalog")
	}
	sp := spec(probe, dbprobe.ModeLab, nil)
	sp.Marker, sp.FixtureID = "m1", "accounts"
	res, _ := a.RunProbe(context.Background(), def, sp)
	return res
}

// The whole DDL round-trip is one transaction: CREATE and DROP both happen, and the
// commit publishes the net result, which is no table left behind.
func TestDDLRoundtripCommitsOneTransaction(t *testing.T) {
	f := newTxnFake()
	res := runRoundtrip(t, roundtripAdapter(t, f), dbprobe.ProbeAuditDDLRoundtrip)
	if res.ErrorClass != "" {
		t.Fatalf("round-trip failed: %s, notes %v", res.ErrorClass, res.Notes)
	}
	if !strings.Contains(strings.Join(res.Notes, " "), "ddl: created=ok dropped=ok") {
		t.Errorf("notes = %v", res.Notes)
	}
	if f.begins != 1 || f.commits != 1 || f.rollbacks != 0 {
		t.Errorf("want one transaction committed, got begins=%d commits=%d rollbacks=%d", f.begins, f.commits, f.rollbacks)
	}
}

// The role round-trip is one transaction: after the commit, no grant is left behind.
func TestRoleRoundtripCommitsGrantAndRevoke(t *testing.T) {
	f := newTxnFake()
	res := runRoundtrip(t, roundtripAdapter(t, f), dbprobe.ProbeAuditRoleRoundtrip)
	if res.ErrorClass != "" {
		t.Fatalf("round-trip failed: %s, notes %v", res.ErrorClass, res.Notes)
	}
	if !strings.Contains(strings.Join(res.Notes, " "), "role: granted=ok revoked=ok") {
		t.Errorf("notes = %v", res.Notes)
	}
	if f.commits != 1 || f.rollbacks != 0 {
		t.Errorf("want one transaction committed, got commits=%d rollbacks=%d", f.commits, f.rollbacks)
	}
}

// A refused step rolls the whole round-trip back: nothing is published.
func TestRoundtripRollsBackWhenAStepFails(t *testing.T) {
	f := newTxnFake()
	f.failOn = "REVOKE SELECT"
	res := runRoundtrip(t, roundtripAdapter(t, f), dbprobe.ProbeAuditRoleRoundtrip)
	if res.ErrorClass != "role_revoke_failed" {
		t.Fatalf("want role_revoke_failed, got %q", res.ErrorClass)
	}
	if f.commits != 0 || f.rollbacks != 1 {
		t.Errorf("a failed round-trip must roll back, got commits=%d rollbacks=%d", f.commits, f.rollbacks)
	}
	if len(f.committed) != 0 {
		t.Errorf("nothing may be published after a failure, committed state = %v", f.committed)
	}
}
