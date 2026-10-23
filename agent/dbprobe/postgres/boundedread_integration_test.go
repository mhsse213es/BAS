//go:build dbsim_integration

package postgres

import (
	"context"
	"fmt"
	"testing"

	"audspect/agent/dbprobe"
	"audspect/agent/dbprobe/fixtures"
)

// WRITTEN, NOT EXECUTED on the build host (no database). Live check of the two
// fixture read probes against a throwaway lab database: every catalog fixture
// table is seeded through fixtures.WithFixture, bound as the active fixture, and
// read through RunProbe. RowsRead must equal min(declared rows, cap) and the
// truncation note must agree with it; the fixture must still be cleaned up.
func TestPGFixtureReadProbesLive(t *testing.T) {
	for _, name := range fixtures.Names() {
		spec, _ := fixtures.Lookup(name)
		for _, tbl := range spec.Tables {
			for _, probe := range []string{dbprobe.ProbeSuspiciousRead, dbprobe.ProbeBoundedSyntheticRead} {
				for _, maxRows := range []int{1, 5, 1000} {
					t.Run(fmt.Sprintf("%s/%s/%s/max%d", name, tbl.Name, probe, maxRows), func(t *testing.T) {
						a := liveAdapter(t, dbprobe.ModeLab)
						res, err := fixtures.WithFixture(context.Background(), a, spec, func(fx dbprobe.Fixture) error {
							if err := a.BindFixture(fx); err != nil {
								return err
							}
							defer a.UnbindFixture()
							pr, perr := a.RunProbe(context.Background(), def(probe), liveReadSpec(probe, name, tbl.Name, maxRows))
							if perr != nil {
								return perr
							}
							rowCap := dbprobe.FixtureReadRowCap(probe, maxRows)
							want, trunc := len(tbl.Rows), false
							if want > rowCap {
								want, trunc = rowCap, true
							}
							// The edge table can also stop on the byte cap; the row
							// expectation is not asserted for it.
							if name != "edge" && pr.RowsRead != want {
								t.Errorf("RowsRead=%d want %d (notes %v)", pr.RowsRead, want, pr.Notes)
							}
							got := false
							for _, n := range pr.Notes {
								if n == "truncated=true" {
									got = true
								}
							}
							if name != "edge" && got != trunc {
								t.Errorf("truncated=%v want %v (notes %v)", got, trunc, pr.Notes)
							}
							return nil
						})
						if err != nil || len(res.Residual) != 0 {
							t.Fatalf("lifecycle: res=%+v err=%v", res, err)
						}
					})
				}
			}
		}
	}
}

func liveReadSpec(probe, fixture, table string, maxRows int) dbprobe.DBProbeSpec {
	s := spec(probe, dbprobe.ModeLab, map[string]string{"table": table})
	s.FixtureID = fixture
	s.Limits.MaxRows = maxRows
	return s
}
