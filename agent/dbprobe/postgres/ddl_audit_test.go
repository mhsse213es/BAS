package postgres

import (
	"context"
	"strings"
	"testing"

	"audspect/agent/dbprobe"
)

// DB-04-08: one CREATE TABLE and one DROP TABLE, both tagged with the run's
// marker, inside the run's own fixture schema. Both statements must reach the
// session in that order.
func TestAuditDDLRoundtripTagsCreateAndDropInFixtureSchema(t *testing.T) {
	f := &fakeSession{}
	a := &Adapter{s: f, mode: dbprobe.ModeLab}
	if err := a.BindFixture(dbprobe.Fixture{ID: "ab12", Kind: "accounts", Tables: []dbprobe.FixtureTable{{Name: "accounts", Columns: []dbprobe.FixtureColumn{{Name: "id", Type: "int", PK: true}}}}}); err != nil {
		t.Fatal(err)
	}
	def, ok := dbprobe.LookupProbe(dbprobe.ProbeAuditDDLRoundtrip)
	if !ok {
		t.Fatal("probe not in catalog")
	}
	sp := spec(dbprobe.ProbeAuditDDLRoundtrip, dbprobe.ModeLab, nil)
	sp.Marker, sp.FixtureID = "m1", "accounts"
	if _, err := a.RunProbe(context.Background(), def, sp); err != nil {
		t.Fatalf("run: %v", err)
	}
	var stmts []string
	for _, c := range f.calls {
		if strings.Contains(c.sql, "dbsim_ddl_probe") {
			stmts = append(stmts, c.sql)
		}
	}
	if len(stmts) != 2 {
		t.Fatalf("want CREATE and DROP of the probe table, got %d: %v", len(stmts), stmts)
	}
	if !strings.HasPrefix(stmts[0], "/* dbsim:m1 */") || !strings.Contains(stmts[0], `CREATE TABLE "dbsim_ab12"."dbsim_ddl_probe"`) {
		t.Errorf("create not marker-tagged in the fixture schema: %q", stmts[0])
	}
	if !strings.HasPrefix(stmts[1], "/* dbsim:m1 */") || !strings.Contains(stmts[1], `DROP TABLE "dbsim_ab12"."dbsim_ddl_probe"`) {
		t.Errorf("drop not marker-tagged in the fixture schema: %q", stmts[1])
	}
}
