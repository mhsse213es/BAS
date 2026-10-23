//go:build dbsim_integration

package postgres

import (
	"context"
	"testing"

	"audspect/agent/dbprobe"
	"audspect/agent/dbprobe/fixtures"
)

// Live fixture lifecycle against a THROWAWAY database (DBSIM_PG_DSN, see
// integration_test.go): every catalog fixture is seeded through
// fixtures.WithFixture, the objects are observed via InspectFixture while the
// fixture exists, and VerifyClean must report nothing afterwards.
func TestPGFixtureLifecycleLive(t *testing.T) {
	for _, name := range fixtures.Names() {
		t.Run(name, func(t *testing.T) {
			a := liveAdapter(t, dbprobe.ModeLab)
			spec, _ := fixtures.Lookup(name)
			var during []string
			var fxID string
			res, err := fixtures.WithFixture(context.Background(), a, spec, func(fx dbprobe.Fixture) error {
				fxID = fx.ID
				objs, err := a.InspectFixture(context.Background(), fx)
				during = objs
				return err
			})
			if err != nil || len(res.Residual) != 0 {
				t.Fatalf("lifecycle: res=%+v err=%v", res, err)
			}
			want := 1 + len(spec.Tables) + 1 // schema + tables + role
			if len(during) != want {
				t.Errorf("objects during run = %v, want %d", during, want)
			}
			after, err := a.InspectFixture(context.Background(), dbprobe.Fixture{ID: fxID})
			if err != nil || len(after) != 0 {
				t.Fatalf("after cleanup: %v %v", after, err)
			}
		})
	}
}

// Row counts, NULLs and the 4 KB value must round-trip through bound parameters.
func TestPGFixtureEdgeDataRoundTripsLive(t *testing.T) {
	a := liveAdapter(t, dbprobe.ModeLab)
	spec, _ := fixtures.Lookup("edge")
	_, err := fixtures.WithFixture(context.Background(), a, spec, func(fx dbprobe.Fixture) error {
		schema := fixtures.SchemaName(fx.ID)
		rows, err := a.s.Query(context.Background(), `SELECT count(*), count(note), max(length(payload)) FROM "`+schema+`"."edge_cases"`, 1)
		if err != nil || len(rows) != 1 {
			t.Fatalf("query: %v %v", rows, err)
		}
		t.Logf("edge counts: %v", rows[0])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
