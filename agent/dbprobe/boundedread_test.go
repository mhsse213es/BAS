package dbprobe

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

func fixtureWith(tables ...string) Fixture {
	f := Fixture{ID: "abc123def456", Kind: "accounts"}
	for _, n := range tables {
		f.Tables = append(f.Tables, FixtureTable{Name: n, Columns: []FixtureColumn{{Name: "id", Type: FixtureColInt, PK: true}}})
	}
	return f
}

func TestFixtureAwareProbesAreCatalogedWithClasses(t *testing.T) {
	sr, ok := LookupProbe("suspicious_read")
	if !ok || sr.Class != ClassBoundedSynthetic || sr.FixtureParam != "table" {
		t.Fatalf("suspicious_read: %+v ok=%v", sr, ok)
	}
	bb, ok := LookupProbe("bounded_synthetic_read")
	if !ok || bb.Class != ClassBoundedSynthetic || bb.FixtureParam != "table" {
		t.Fatalf("bounded_synthetic_read: %+v ok=%v", bb, ok)
	}
	for _, d := range []ProbeDef{sr, bb} {
		if len(d.ParamSchema) != 1 || d.ParamSchema["table"] != ParamString {
			t.Errorf("%s must take exactly one string param, the fixture table name: %v", d.ID, d.ParamSchema)
		}
	}
	// The pre-existing probes are not fixture-aware.
	for _, id := range []string{"read_roles", "read_grants", "auth_check", "read_audit_config", "read_restricted_table"} {
		if d, _ := LookupProbe(id); d.FixtureParam != "" {
			t.Errorf("%s must not be fixture-aware", id)
		}
	}
}

func fixtureSpec(probe string, mode ExecMode) DBProbeSpec {
	s := validSpec()
	s.ProbeID = probe
	s.Mode = mode
	s.FixtureID = "accounts"
	s.Params = map[string]string{"table": "accounts"}
	return s
}

func TestBoundedSyntheticReadRefusedInClientMode(t *testing.T) {
	def, _ := LookupProbe("bounded_synthetic_read")
	all := Policy{ClientEnabled: true, LabMutationAllowed: true}
	if err := CheckSpec(fixtureSpec("bounded_synthetic_read", ModeClient), def, "7001", "7001", all); err == nil {
		t.Fatal("client mode must refuse the bounded_synthetic probe")
	}
	if err := CheckSpec(fixtureSpec("bounded_synthetic_read", ModeLab), def, "7001", "7001", Policy{}); err == nil {
		t.Fatal("lab mode without the agent-local mutation allowance must refuse it")
	}
	if err := CheckSpec(fixtureSpec("bounded_synthetic_read", ModeLab), def, "7001", "7001", Policy{LabMutationAllowed: true}); err != nil {
		t.Fatalf("lab mode with allowance must pass the gate: %v", err)
	}
	// suspicious_read seeds a fixture too: same class, same gating (R-AI).
	sdef, _ := LookupProbe("suspicious_read")
	if err := CheckSpec(fixtureSpec("suspicious_read", ModeClient), sdef, "7001", "7001", all); err == nil {
		t.Fatal("client mode must refuse suspicious_read")
	}
	if err := CheckSpec(fixtureSpec("suspicious_read", ModeLab), sdef, "7001", "7001", Policy{}); err == nil {
		t.Fatal("suspicious_read seeds a fixture and needs the agent-local lab-mutation allowance")
	}
	if err := CheckSpec(fixtureSpec("suspicious_read", ModeLab), sdef, "7001", "7001", Policy{LabMutationAllowed: true}); err != nil {
		t.Fatalf("lab + allowance must pass: %v", err)
	}
}

// R-AI: any step that names a fixture mutates the lab database (the run seeds
// it), whatever the probe's own class is.
func TestAnyFixtureStepIsGatedAsMutation(t *testing.T) {
	catalog["t_ro_fixture"] = ProbeDef{ID: "t_ro_fixture", Class: ClassReadOnly, Engines: bothEngines, ParamSchema: map[string]ParamKind{}}
	t.Cleanup(func() { delete(catalog, "t_ro_fixture") })
	for _, id := range []string{"t_ro_fixture", "read_roles"} {
		def, _ := LookupProbe(id)
		s := validSpec()
		s.ProbeID, s.Mode, s.FixtureID = id, ModeLab, "accounts"
		if err := CheckSpec(s, def, "7001", "7001", Policy{}); err == nil {
			t.Errorf("%s + fixture in lab mode without allowance accepted", id)
		}
		if err := CheckSpec(s, def, "7001", "7001", Policy{LabMutationAllowed: true}); err != nil {
			t.Errorf("%s + fixture + allowance refused: %v", id, err)
		}
		s.Mode = ModeClient
		if err := CheckSpec(s, def, "7001", "7001", Policy{ClientEnabled: true, LabMutationAllowed: true}); err == nil {
			t.Errorf("%s + fixture in client mode accepted", id)
		}
		// Without a fixture a read_only probe is unchanged.
		s.FixtureID, s.Mode = "", ModeLab
		if err := CheckSpec(s, def, "7001", "7001", Policy{}); err != nil {
			t.Errorf("%s without fixture must be unchanged: %v", id, err)
		}
	}
}

// The orchestrator's dbbuild emits exactly this spec JSON for DB-05 / DB-09
// (see orchestrator/internal/dbsim/dbbuild TestFixtureReadStepsMatchAgentShape,
// which decodes it strictly against the shared golden keys); the agent must
// accept it field for field.
func TestBuilderShapedFixtureReadSpecsAreAccepted(t *testing.T) {
	for _, c := range []struct {
		probe, fixture, table string
		maxRows               int
	}{
		{"suspicious_read", "classified-pii", "customers_pii", 10},
		{"bounded_synthetic_read", "accounts", "accounts", 5},
	} {
		raw := `{"engine":"postgresql","probeId":"` + c.probe + `","targetId":"lab-db","host":"10.20.30.40","port":5432,` +
			`"database":"appdb","tlsMode":"require","expectedIdentity":"7312345678901234567","credentialRef":"dbcred:lab-pg",` +
			`"runId":"bas-dbsim-run:0123456789abcdef","marker":"bas-dbsim:0123456789abcdef01234567","fixtureId":"` + c.fixture + `",` +
			`"mode":"lab","limits":{"maxRows":` + strconv.Itoa(c.maxRows) + `,"timeoutSec":30,"maxConns":1},"params":{"table":"` + c.table + `"}}`
		var s DBProbeSpec
		dec := json.NewDecoder(strings.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&s); err != nil {
			t.Fatalf("%s: %v", c.probe, err)
		}
		if err := ValidateSpec(s); err != nil {
			t.Errorf("%s: agent refuses the builder-shaped spec: %v", c.probe, err)
		}
	}
}

func TestFixtureAwareProbeRequiresFixtureIDInSpec(t *testing.T) {
	for _, p := range []string{"suspicious_read", "bounded_synthetic_read"} {
		s := fixtureSpec(p, ModeLab)
		if err := ValidateSpec(s); err != nil {
			t.Fatalf("%s: valid spec rejected: %v", p, err)
		}
		s.FixtureID = ""
		if err := ValidateSpec(s); err == nil {
			t.Fatalf("%s: a fixture-aware probe without a fixtureId must be refused", p)
		}
	}
	// Fixture-aware probes are lab-only even at the spec-validation layer.
	cs := fixtureSpec("suspicious_read", ModeClient)
	if err := ValidateSpec(cs); err == nil {
		t.Fatal("a client-mode fixture-aware spec must be refused")
	}
	// The table param is required by the schema.
	s2 := fixtureSpec("suspicious_read", ModeLab)
	s2.Params = map[string]string{"schema": "x"}
	if err := ValidateSpec(s2); err == nil {
		t.Fatal("undeclared param accepted")
	}
}

func TestBoundedSyntheticReadRequiresActiveFixtureTable(t *testing.T) {
	var af ActiveFixture
	if _, _, err := af.Resolve("accounts"); err == nil {
		t.Fatal("no active fixture must fail closed")
	}
	if err := af.BindFixture(fixtureWith("accounts", "ledger")); err != nil {
		t.Fatal(err)
	}
	fx, tbl, err := af.Resolve("accounts")
	if err != nil || tbl.Name != "accounts" || fx.ID != "abc123def456" {
		t.Fatalf("resolve: %+v %+v %v", fx, tbl, err)
	}
	for _, bad := range []string{"", "nope", "ACCOUNTS", "accounts ", "dbsim_abc123def456.accounts", "other.accounts", "accounts; DROP", "`accounts`", `"accounts"`, "accounts.ledger"} {
		if _, _, err := af.Resolve(bad); err == nil {
			t.Errorf("table %q must not resolve against the fixture", bad)
		}
	}
	af.UnbindFixture()
	if _, _, err := af.Resolve("accounts"); err == nil {
		t.Fatal("unbound fixture must fail closed")
	}
	// A fixture whose declared tables are invalid is never bound.
	bad := fixtureWith("accounts")
	bad.Tables[0].Name = "x; drop"
	if err := af.BindFixture(bad); err == nil {
		t.Fatal("an invalid fixture was bound")
	}
	if _, _, err := af.Resolve("accounts"); err == nil {
		t.Fatal("a failed bind must leave nothing bound")
	}
}

func TestBindFixtureCopiesTheFixture(t *testing.T) {
	var af ActiveFixture
	f := fixtureWith("accounts")
	if err := af.BindFixture(f); err != nil {
		t.Fatal(err)
	}
	f.Tables[0].Name = "mutated"
	if _, _, err := af.Resolve("accounts"); err != nil {
		t.Fatalf("caller mutation leaked into the bound fixture: %v", err)
	}
}

func TestFixtureReadRowCap(t *testing.T) {
	cases := []struct {
		probe string
		max   int
		want  int
	}{
		{"bounded_synthetic_read", 1, 1},
		{"bounded_synthetic_read", 10, 10},
		{"bounded_synthetic_read", MaxRowsCap, MaxRowsCap},
		{"suspicious_read", 1, 1},
		{"suspicious_read", SuspiciousReadMaxRows, SuspiciousReadMaxRows},
		{"suspicious_read", SuspiciousReadMaxRows + 1, SuspiciousReadMaxRows},
		{"suspicious_read", 100000, SuspiciousReadMaxRows},
	}
	for _, c := range cases {
		if got := FixtureReadRowCap(c.probe, c.max); got != c.want {
			t.Errorf("FixtureReadRowCap(%s,%d)=%d want %d", c.probe, c.max, got, c.want)
		}
	}
}

func mkRows(n int, cells ...any) [][]any {
	out := make([][]any, n)
	for i := range out {
		out[i] = append([]any(nil), cells...)
	}
	return out
}

func TestBoundaryRowCounts(t *testing.T) {
	const cap = 5
	cases := []struct {
		name      string
		rows      [][]any
		wantRows  int
		wantTrunc bool
	}{
		{"empty table", nil, 0, false},
		{"one row", mkRows(1, "a"), 1, false},
		{"cap-1", mkRows(cap-1, "a"), cap - 1, false},
		{"exactly cap", mkRows(cap, "a"), cap, false},
		{"cap+1 (sentinel row)", mkRows(cap+1, "a"), cap, true},
		{"more than cap+1 never over-counts", mkRows(cap+10, "a"), cap, true},
	}
	for _, c := range cases {
		s := SummarizeBoundedRead(c.rows, cap, MaxReadBytes)
		if s.Rows != c.wantRows || s.Truncated != c.wantTrunc {
			t.Errorf("%s: %+v want rows=%d truncated=%v", c.name, s, c.wantRows, c.wantTrunc)
		}
	}
	// A cap of zero reads nothing and never claims a row.
	if s := SummarizeBoundedRead(mkRows(3, "a"), 0, MaxReadBytes); s.Rows != 0 || !s.Truncated {
		t.Errorf("cap 0 over data: %+v", s)
	}
	if s := SummarizeBoundedRead(nil, 0, MaxReadBytes); s.Rows != 0 || s.Truncated {
		t.Errorf("cap 0 over empty: %+v", s)
	}
}

func TestBoundaryNullsAndHugeValues(t *testing.T) {
	// NULL cells (nil) and empty strings count zero bytes and do not panic.
	s := SummarizeBoundedRead([][]any{{nil, nil}, {"", ""}}, 10, MaxReadBytes)
	if s.Rows != 2 || s.Bytes != 0 || s.Truncated {
		t.Fatalf("nulls: %+v", s)
	}
	// The 4096-byte edge value: counted exactly, in text and []byte form.
	huge := strings.Repeat("x", 4096)
	s = SummarizeBoundedRead([][]any{{1, huge}, {2, []byte(huge)}}, 10, MaxReadBytes)
	if s.Rows != 2 || s.Bytes != 2*4096+16 || s.Truncated {
		t.Fatalf("huge: %+v", s)
	}
	// The byte cap truncates on a row boundary and never counts the row that would exceed it.
	rows := mkRows(10, huge)
	s = SummarizeBoundedRead(rows, 10, 3*4096+100)
	if s.Rows != 3 || !s.Truncated || s.Bytes != 3*4096 {
		t.Fatalf("byte cap: %+v", s)
	}
	// A single row larger than the byte cap yields zero rows, truncated.
	s = SummarizeBoundedRead(mkRows(1, huge), 10, 100)
	if s.Rows != 0 || !s.Truncated || s.Bytes != 0 {
		t.Fatalf("oversized first row: %+v", s)
	}
}

func TestBulkReadResultCarriesNoRowContents(t *testing.T) {
	const secret = "BAS-SIM-SECRET-CONTENT-9d3f"
	s := SummarizeBoundedRead([][]any{{1, secret}, {2, []byte(secret)}}, 10, MaxReadBytes)
	notes := s.Notes("wide_select", 12*time.Millisecond)
	b, err := json.Marshal(struct {
		S BoundedReadSummary
		N []string
	}{s, notes})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), secret) || strings.Contains(string(b), "SECRET") {
		t.Fatalf("row content reached the summary: %s", b)
	}
	want := []string{"shape=wide_select", "rows_read=2", "truncated=false", "duration_ms=12"}
	for _, w := range want {
		found := false
		for _, n := range notes {
			if n == w {
				found = true
			}
		}
		if !found {
			t.Errorf("notes %v missing %q", notes, w)
		}
	}
	var bytesNote bool
	for _, n := range notes {
		if strings.HasPrefix(n, "bytes_read=") {
			bytesNote = true
		}
	}
	if !bytesNote {
		t.Errorf("notes %v missing bytes_read", notes)
	}
}
