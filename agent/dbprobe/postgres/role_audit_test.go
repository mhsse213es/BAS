package postgres

import (
	"context"
	"strings"
	"testing"

	"audspect/agent/dbprobe"
)

// DB-04-06: one GRANT SELECT and one REVOKE SELECT on the fixture's accounts table
// for the fixture read role, both tagged with the marker. The REVOKE restores the
// grant state the run started with.
func TestAuditRoleRoundtripGrantsAndRevokesOnFixtureTable(t *testing.T) {
	f := &fakeSession{}
	a := &Adapter{s: f, mode: dbprobe.ModeLab}
	if err := a.BindFixture(dbprobe.Fixture{ID: "ab12", Kind: "accounts", Tables: []dbprobe.FixtureTable{{Name: "accounts", Columns: []dbprobe.FixtureColumn{{Name: "id", Type: "int", PK: true}}}}}); err != nil {
		t.Fatal(err)
	}
	def, ok := dbprobe.LookupProbe(dbprobe.ProbeAuditRoleRoundtrip)
	if !ok {
		t.Fatal("probe not in catalog")
	}
	sp := spec("audit_role_roundtrip", dbprobe.ModeLab, nil)
	sp.Marker, sp.FixtureID = "m1", "accounts"
	if _, err := a.RunProbe(context.Background(), def, sp); err != nil {
		t.Fatalf("run: %v", err)
	}
	var stmts []string
	for _, c := range f.calls {
		if strings.Contains(c.sql, "accounts") && (strings.Contains(c.sql, "GRANT") || strings.Contains(c.sql, "REVOKE")) {
			stmts = append(stmts, c.sql)
		}
	}
	if len(stmts) != 2 {
		t.Fatalf("want one GRANT and one REVOKE, got %d: %v", len(stmts), stmts)
	}
	if !strings.HasPrefix(stmts[0], "/* dbsim:m1 */") || !strings.HasPrefix(stmts[0], "/* dbsim:m1 */ GRANT SELECT ON \"dbsim_ab12\".\"accounts\" TO \"dbsim_ab12_ro\"") {
		t.Errorf("grant not marker-tagged on the fixture table: %q", stmts[0])
	}
	if !strings.HasPrefix(stmts[1], "/* dbsim:m1 */") || !strings.Contains(stmts[1], "REVOKE SELECT ON \"dbsim_ab12\".\"accounts\" FROM \"dbsim_ab12_ro\"") {
		t.Errorf("revoke not marker-tagged on the fixture table: %q", stmts[1])
	}
}
