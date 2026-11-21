package postgres

import (
	"context"
	"strings"
	"testing"

	"audspect/agent/dbprobe"
)

// DB-04-05: one marker-tagged privileged call, SELECT pg_reload_conf(), in the lab. The
// call must reach the session with the marker and succeed.
func TestAuditReloadConfTagsPrivilegedCall(t *testing.T) {
	f := &fakeSession{}
	a := &Adapter{s: f, mode: dbprobe.ModeLab}
	if err := a.BindFixture(dbprobe.Fixture{ID: "ab12", Kind: "accounts", Tables: []dbprobe.FixtureTable{{Name: "accounts", Columns: []dbprobe.FixtureColumn{{Name: "id", Type: "int", PK: true}}}}}); err != nil {
		t.Fatal(err)
	}
	def, ok := dbprobe.LookupProbe(dbprobe.ProbeAuditReloadConf)
	if !ok {
		t.Fatal("probe not in catalog")
	}
	sp := spec(dbprobe.ProbeAuditReloadConf, dbprobe.ModeLab, nil)
	sp.Marker, sp.FixtureID = "m1", "accounts"
	res, err := a.RunProbe(context.Background(), def, sp)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.ErrorClass != "" {
		t.Fatalf("error class %q, notes %v", res.ErrorClass, res.Notes)
	}
	var found bool
	for _, c := range f.calls {
		if strings.HasPrefix(c.sql, "/* dbsim:m1 */") && strings.Contains(c.sql, "SELECT pg_reload_conf()") {
			found = true
		}
	}
	if !found {
		t.Errorf("no marker-tagged pg_reload_conf call in %v", f.calls)
	}
	if !strings.Contains(strings.Join(res.Notes, " "), "reload: called=ok") {
		t.Errorf("notes = %v", res.Notes)
	}
}
