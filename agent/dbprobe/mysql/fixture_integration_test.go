//go:build dbsim_integration

package mysql

import (
	"context"
	"testing"

	"audspect/agent/dbprobe"
	"audspect/agent/dbprobe/fixtures"
)

// Live fixture lifecycle against a THROWAWAY MySQL 5.7.8+/8.x server
// (DBSIM_MYSQL_*, see integration_test.go): every catalog fixture is seeded
// through fixtures.WithFixture, observed via InspectFixture, and VerifyClean
// must report nothing afterwards.
func TestMySQLFixtureLifecycleLive(t *testing.T) {
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
			want := 1 + len(spec.Tables) + 1 // schema + tables + user
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

// NULLs and the 4 KB / unicode values must round-trip through bound parameters.
func TestMySQLFixtureEdgeDataRoundTripsLive(t *testing.T) {
	a := liveAdapter(t, dbprobe.ModeLab)
	spec, _ := fixtures.Lookup("edge")
	_, err := fixtures.WithFixture(context.Background(), a, spec, func(fx dbprobe.Fixture) error {
		schema := fixtures.SchemaName(fx.ID)
		rows, err := a.s.Query(context.Background(), "SELECT COUNT(*), COUNT(note), MAX(CHAR_LENGTH(payload)) FROM `"+schema+"`.`edge_cases`", 1)
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
