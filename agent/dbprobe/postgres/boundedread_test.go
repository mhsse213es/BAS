package postgres

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"audspect/agent/dbprobe"
)

const testFixtureID = "abc123def456"

func accountsFixture() dbprobe.Fixture {
	return dbprobe.Fixture{ID: testFixtureID, Kind: "accounts", Tables: []dbprobe.FixtureTable{{
		Name:    "accounts",
		Columns: []dbprobe.FixtureColumn{{Name: "id", Type: dbprobe.FixtureColInt, PK: true}, {Name: "synthetic", Type: dbprobe.FixtureColText}},
	}, {
		Name:    "ledger",
		Columns: []dbprobe.FixtureColumn{{Name: "id", Type: dbprobe.FixtureColInt, PK: true}},
	}}}
}

func fixtureSpecFor(probe string, mode dbprobe.ExecMode, table string, maxRows int) dbprobe.DBProbeSpec {
	s := spec(probe, mode, map[string]string{"table": table})
	s.FixtureID = "accounts"
	s.Limits.MaxRows = maxRows
	return s
}

// labReadAdapter returns a lab adapter with the accounts fixture bound and a
// fake session answering the clock query and then rows (nil = no rows).
func labReadAdapter(t *testing.T, rows [][]any) (*Adapter, *fakeSession) {
	t.Helper()
	f := &fakeSession{queryFn: func(sql string, args []any) ([][]any, error) {
		if strings.Contains(sql, "clock_timestamp") {
			return [][]any{{time.Unix(1700000000, 0).UTC()}}, nil
		}
		return rows, nil
	}}
	a := &Adapter{s: f, mode: dbprobe.ModeLab}
	if err := a.BindFixture(accountsFixture()); err != nil {
		t.Fatal(err)
	}
	return a, f
}

func findCall(t *testing.T, f *fakeSession, prefix string) fakeCall {
	t.Helper()
	for _, c := range f.calls {
		if strings.HasPrefix(c.sql, prefix) {
			return c
		}
	}
	t.Fatalf("no call starting with %q in %+v", prefix, f.calls)
	return fakeCall{}
}

func TestSuspiciousReadProbeIsNamedAndFixedSQL(t *testing.T) {
	a, f := labReadAdapter(t, mkRows(3, 1, "BAS-SIM-SYNTHETIC"))
	res, err := a.RunProbe(context.Background(), def("suspicious_read"), fixtureSpecFor("suspicious_read", dbprobe.ModeLab, "accounts", 100))
	if err != nil {
		t.Fatal(err)
	}
	if res.RowsRead != 3 || res.Denied || res.ErrorClass != "" {
		t.Fatalf("result %+v", res)
	}
	c := findCall(t, f, "/* dbsim:dbsim-abc123 */ SELECT * FROM")
	const want = `/* dbsim:dbsim-abc123 */ SELECT * FROM "dbsim_abc123def456"."accounts" LIMIT $1`
	if c.sql != want {
		t.Fatalf("sql\n got %s\nwant %s", c.sql, want)
	}
	// suspicious_read is read_only: capped at SuspiciousReadMaxRows even with a 100-row limit, +1 sentinel, bound.
	if len(c.args) != 1 || c.args[0] != dbprobe.SuspiciousReadMaxRows+1 {
		t.Fatalf("args %v want [%d]", c.args, dbprobe.SuspiciousReadMaxRows+1)
	}
	if f.calls[0].sql != "BEGIN READ ONLY" || f.calls[len(f.calls)-1].sql != "ROLLBACK" {
		t.Fatalf("not wrapped in a READ ONLY transaction: %+v", f.calls)
	}
	for _, c := range f.calls {
		if !c.hasDeadline {
			t.Errorf("call without a deadline: %q", c.sql)
		}
	}
	if !hasNote(res.Notes, "shape=wide_select") {
		t.Errorf("shape category missing: %v", res.Notes)
	}
}

func hasNote(notes []string, want string) bool {
	for _, n := range notes {
		if n == want {
			return true
		}
	}
	return false
}

func mkRows(n int, cells ...any) [][]any {
	out := make([][]any, n)
	for i := range out {
		out[i] = append([]any(nil), cells...)
	}
	return out
}

func TestBoundedSyntheticReadCapsRowsInSQLAndCode(t *testing.T) {
	// A server that ignores LIMIT and returns 9 rows must still be cut to the cap.
	a, f := labReadAdapter(t, mkRows(9, 1, "x"))
	res, err := a.RunProbe(context.Background(), def("bounded_synthetic_read"), fixtureSpecFor("bounded_synthetic_read", dbprobe.ModeLab, "accounts", 5))
	if err != nil {
		t.Fatal(err)
	}
	c := findCall(t, f, "/* dbsim:dbsim-abc123 */ SELECT * FROM")
	if len(c.args) != 1 || c.args[0] != 6 {
		t.Fatalf("LIMIT arg %v want [6] (cap 5 + sentinel)", c.args)
	}
	if res.RowsRead != 5 {
		t.Fatalf("code cap not applied: RowsRead=%d", res.RowsRead)
	}
	if !hasNote(res.Notes, "truncated=true") || !hasNote(res.Notes, "shape=bulk_select_capped") || !hasNote(res.Notes, "rows_read=5") {
		t.Fatalf("notes %v", res.Notes)
	}
	if res.ErrorClass != "" {
		t.Fatalf("a truncated bulk read is an observation, not an error: %q", res.ErrorClass)
	}
	// Still a SELECT in a READ ONLY transaction although the class is bounded_synthetic.
	if f.calls[0].sql != "BEGIN READ ONLY" {
		t.Fatalf("first stmt %q", f.calls[0].sql)
	}
}

func TestBoundedSyntheticReadRefusedInClientMode(t *testing.T) {
	for _, c := range []struct{ conn, spec dbprobe.ExecMode }{
		{dbprobe.ModeClient, dbprobe.ModeClient}, {dbprobe.ModeClient, dbprobe.ModeLab}, {dbprobe.ModeLab, dbprobe.ModeClient},
	} {
		f := &fakeSession{}
		a := &Adapter{s: f, mode: c.conn}
		_ = a.BindFixture(accountsFixture())
		_, err := a.RunProbe(context.Background(), def("bounded_synthetic_read"), fixtureSpecFor("bounded_synthetic_read", c.spec, "accounts", 5))
		if err == nil || len(f.calls) != 0 {
			t.Errorf("conn=%s spec=%s: err=%v calls=%d (must refuse before any SQL)", c.conn, c.spec, err, len(f.calls))
		}
	}
}

func TestBoundedSyntheticReadRequiresActiveFixtureTable(t *testing.T) {
	// No active fixture.
	f := &fakeSession{}
	a := &Adapter{s: f, mode: dbprobe.ModeLab}
	if _, err := a.RunProbe(context.Background(), def("bounded_synthetic_read"), fixtureSpecFor("bounded_synthetic_read", dbprobe.ModeLab, "accounts", 5)); err == nil || len(f.calls) != 0 {
		t.Fatalf("no active fixture: err=%v calls=%d", err, len(f.calls))
	}
	// Table not in the fixture, schema-qualified, quoted, injection-shaped.
	for _, tbl := range []string{"missing", "dbsim_abc123def456.accounts", "public.accounts", `"accounts"`, "accounts; DROP TABLE accounts", "ACCOUNTS", "accounts.ledger"} {
		a, f := labReadAdapter(t, nil)
		if _, err := a.RunProbe(context.Background(), def("bounded_synthetic_read"), fixtureSpecFor("bounded_synthetic_read", dbprobe.ModeLab, tbl, 5)); err == nil || len(f.calls) != 0 {
			t.Errorf("table %q: err=%v calls=%d (must fail closed before any SQL)", tbl, err, len(f.calls))
		}
	}
	// Spec fixture name must match the bound fixture's kind.
	a2, f2 := labReadAdapter(t, nil)
	s := fixtureSpecFor("bounded_synthetic_read", dbprobe.ModeLab, "accounts", 5)
	s.FixtureID = "classified-pii"
	if _, err := a2.RunProbe(context.Background(), def("bounded_synthetic_read"), s); err == nil || len(f2.calls) != 0 {
		t.Fatalf("fixture kind mismatch: err=%v calls=%d", err, len(f2.calls))
	}
	// Unbinding returns to fail-closed.
	a3, f3 := labReadAdapter(t, nil)
	a3.UnbindFixture()
	if _, err := a3.RunProbe(context.Background(), def("suspicious_read"), fixtureSpecFor("suspicious_read", dbprobe.ModeLab, "accounts", 5)); err == nil || len(f3.calls) != 0 {
		t.Fatalf("after unbind: err=%v calls=%d", err, len(f3.calls))
	}
	// A spec without a fixture id is refused by ValidateSpec.
	a4, f4 := labReadAdapter(t, nil)
	s4 := fixtureSpecFor("suspicious_read", dbprobe.ModeLab, "accounts", 5)
	s4.FixtureID = ""
	if _, err := a4.RunProbe(context.Background(), def("suspicious_read"), s4); err == nil || len(f4.calls) != 0 {
		t.Fatalf("no fixture id: err=%v calls=%d", err, len(f4.calls))
	}
}

func TestFixtureTableResolvesToActiveSchemaNotParam(t *testing.T) {
	a, f := labReadAdapter(t, nil)
	if _, err := a.RunProbe(context.Background(), def("bounded_synthetic_read"), fixtureSpecFor("bounded_synthetic_read", dbprobe.ModeLab, "ledger", 5)); err != nil {
		t.Fatal(err)
	}
	c := findCall(t, f, "/* dbsim:dbsim-abc123 */ SELECT * FROM")
	if !strings.Contains(c.sql, `"dbsim_`+testFixtureID+`"."ledger"`) {
		t.Fatalf("not resolved to the active fixture schema: %s", c.sql)
	}
	// Nothing was substituted textually: no placeholder syntax, one bound arg.
	if strings.ContainsAny(c.sql, "{}%") || len(c.args) != 1 {
		t.Fatalf("placeholder or extra arg in %q %v", c.sql, c.args)
	}
	// Rebinding to another fixture id moves the read to that schema (the schema is never a param).
	other := accountsFixture()
	other.ID = "0123456789ab"
	if err := a.BindFixture(other); err != nil {
		t.Fatal(err)
	}
	f.calls = nil
	if _, err := a.RunProbe(context.Background(), def("bounded_synthetic_read"), fixtureSpecFor("bounded_synthetic_read", dbprobe.ModeLab, "accounts", 5)); err != nil {
		t.Fatal(err)
	}
	if c := findCall(t, f, "/* dbsim:dbsim-abc123 */ SELECT * FROM"); !strings.Contains(c.sql, `"dbsim_0123456789ab"."accounts"`) {
		t.Fatalf("second fixture: %s", c.sql)
	}
}

func TestBulkReadResultCarriesNoRowContents(t *testing.T) {
	const secret = "BAS-SIM-ROW-CONTENT-77aa"
	a, _ := labReadAdapter(t, [][]any{{1, secret}, {2, []byte(secret)}, {3, nil}})
	res, err := a.RunProbe(context.Background(), def("bounded_synthetic_read"), fixtureSpecFor("bounded_synthetic_read", dbprobe.ModeLab, "accounts", 10))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(res)
	if strings.Contains(string(b), secret) || strings.Contains(string(b), "ROW-CONTENT") {
		t.Fatalf("row content in result: %s", b)
	}
	if res.RowsRead != 3 {
		t.Fatalf("RowsRead %d", res.RowsRead)
	}
}

func TestBoundaryRowCounts(t *testing.T) {
	const cap = 5
	huge := strings.Repeat("h", 4096)
	cases := []struct {
		name      string
		rows      [][]any
		wantRows  int
		wantTrunc string
	}{
		{"empty table", nil, 0, "truncated=false"},
		{"one row", mkRows(1, 1, "a"), 1, "truncated=false"},
		{"cap", mkRows(cap, 1, "a"), cap, "truncated=false"},
		{"cap+1", mkRows(cap+1, 1, "a"), cap, "truncated=true"},
		{"NULL cells", [][]any{{nil, nil}, {1, nil}}, 2, "truncated=false"},
		{"huge values", mkRows(cap, 1, huge), cap, "truncated=false"},
	}
	for _, c := range cases {
		a, _ := labReadAdapter(t, c.rows)
		res, err := a.RunProbe(context.Background(), def("bounded_synthetic_read"), fixtureSpecFor("bounded_synthetic_read", dbprobe.ModeLab, "accounts", cap))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if res.RowsRead != c.wantRows || !hasNote(res.Notes, c.wantTrunc) || res.ErrorClass != "" {
			t.Errorf("%s: RowsRead=%d notes=%v class=%q", c.name, res.RowsRead, res.Notes, res.ErrorClass)
		}
	}
	// MaxRows 0 is refused before any SQL (ValidateSpec); the cap can never be zero.
	f := &fakeSession{}
	a := &Adapter{s: f, mode: dbprobe.ModeLab}
	_ = a.BindFixture(accountsFixture())
	if _, err := a.RunProbe(context.Background(), def("bounded_synthetic_read"), fixtureSpecFor("bounded_synthetic_read", dbprobe.ModeLab, "accounts", 0)); err == nil || len(f.calls) != 0 {
		t.Fatalf("MaxRows 0: err=%v calls=%d", err, len(f.calls))
	}
	// The byte cap truncates large reads on a row boundary.
	a2, _ := labReadAdapter(t, mkRows(300, 1, huge))
	res, err := a2.RunProbe(context.Background(), def("bounded_synthetic_read"), fixtureSpecFor("bounded_synthetic_read", dbprobe.ModeLab, "accounts", 1000))
	if err != nil {
		t.Fatal(err)
	}
	if !hasNote(res.Notes, "truncated=true") || res.RowsRead >= 300 || res.RowsRead*4104 > dbprobe.MaxReadBytes {
		t.Fatalf("byte cap not applied: rows=%d notes=%v", res.RowsRead, res.Notes)
	}
}

func TestFixtureReadDeniedIsObservation(t *testing.T) {
	f := &fakeSession{queryFn: func(sql string, args []any) ([][]any, error) {
		if strings.Contains(sql, "clock_timestamp") {
			return [][]any{{time.Now()}}, nil
		}
		return nil, &pgconn.PgError{Code: "42501", Message: "permission denied for table accounts"}
	}}
	a := &Adapter{s: f, mode: dbprobe.ModeLab}
	_ = a.BindFixture(accountsFixture())
	res, err := a.RunProbe(context.Background(), def("suspicious_read"), fixtureSpecFor("suspicious_read", dbprobe.ModeLab, "accounts", 5))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Denied || res.ErrorClass != "permission_denied" || res.RowsRead != 0 {
		t.Fatalf("result %+v", res)
	}
}

func TestFixtureReadProbesAreOffered(t *testing.T) {
	c := New().Capabilities()
	for _, id := range []string{"suspicious_read", "bounded_synthetic_read"} {
		found := false
		for _, p := range c.ProbeIDs {
			if p == id {
				found = true
			}
		}
		if !found {
			t.Errorf("adapter does not offer %s: %v", id, c.ProbeIDs)
		}
	}
	var _ dbprobe.FixtureBinder = New()
}
