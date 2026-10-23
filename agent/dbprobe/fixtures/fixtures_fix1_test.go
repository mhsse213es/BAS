package fixtures

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"audspect/agent/dbprobe"
)

// A Seed that reports ErrFixtureNotCreated means nothing of ours exists: no
// Cleanup (and so no DROP) may follow, and it is not a safety incident.
func TestWithFixtureNotCreatedSkipsCleanupEntirely(t *testing.T) {
	ad := labAd()
	ad.seedErr = fmt.Errorf("create failed: %w", dbprobe.ErrFixtureNotCreated)
	called := false
	res, err := WithFixture(context.Background(), ad, mustSpec(t, "accounts"), func(dbprobe.Fixture) error { called = true; return nil })
	if called {
		t.Fatal("fn must not run")
	}
	if !errors.Is(err, dbprobe.ErrFixtureNotCreated) {
		t.Fatalf("seed error must surface: %v", err)
	}
	var inc *ErrSafetyIncident
	if errors.As(err, &inc) {
		t.Fatal("a fixture that was never created is not a safety incident")
	}
	if got := strings.Join(ad.calls, ","); got != "inspect,seed" {
		t.Fatalf("calls = %s: no Cleanup/verify may run when nothing was created", got)
	}
	if len(res.Residual) != 0 || len(res.Removed) != 0 || res.Error != "" {
		t.Fatalf("result must be empty: %+v", res)
	}
}

// Seed succeeded but the objects are invisible to the lab account: cleanup
// cannot be verified, so fail closed and never run the probe.
func TestWithFixtureInvisibleAfterSeedIsSafetyIncidentEvenIfDropSucceeds(t *testing.T) {
	ad := labAd()
	ad.invisible = true
	called := false
	res, err := WithFixture(context.Background(), ad, mustSpec(t, "accounts"), func(dbprobe.Fixture) error { called = true; return nil })
	if called {
		t.Fatal("the probe must not run against an unverifiable fixture")
	}
	var inc *ErrSafetyIncident
	if !errors.As(err, &inc) {
		t.Fatalf("expected ErrSafetyIncident, got %v", err)
	}
	if inc.Status != StatusFailed {
		t.Fatalf("status = %q, want failed", inc.Status)
	}
	if !strings.Contains(inc.Error(), "fixture not visible to inspection; cleanup cannot be verified") {
		t.Fatalf("incident text: %v", inc)
	}
	if !strings.Contains(strings.Join(ad.calls, ","), "cleanup") {
		t.Fatal("cleanup must still run (exact-name drops of what this call created)")
	}
	_ = res
}

func TestSeedInvisibleAfterSeedReturnsFixtureAndError(t *testing.T) {
	ad := labAd()
	ad.invisible = true
	fx, err := Seed(context.Background(), ad, mustSpec(t, "empty"))
	if err == nil || fx.ID == "" {
		t.Fatalf("want fixture id + error so the caller can clean up; fx=%+v err=%v", fx, err)
	}
	ad2 := labAd()
	ad2.inspectErr = nil
	fx2, err2 := Seed(context.Background(), ad2, mustSpec(t, "empty"))
	if err2 != nil || fx2.ID == "" {
		t.Fatalf("visible fixture must seed normally: %v", err2)
	}
}

// The visibility check reads the schema among the inspected objects; an
// inspection error after Seed is equally unverifiable.
func TestWithFixtureInspectErrorAfterSeedIsSafetyIncident(t *testing.T) {
	ad := &inspectFailsAfterSeed{fakeAd: labAd()}
	called := false
	_, err := WithFixture(context.Background(), ad, mustSpec(t, "accounts"), func(dbprobe.Fixture) error { called = true; return nil })
	var inc *ErrSafetyIncident
	if called || !errors.As(err, &inc) {
		t.Fatalf("called=%v err=%v", called, err)
	}
}

// inspectFailsAfterSeed errors on every inspection once Seed has run.
type inspectFailsAfterSeed struct{ *fakeAd }

func (f *inspectFailsAfterSeed) InspectFixture(ctx context.Context, fx dbprobe.Fixture) ([]string, error) {
	f.mu.Lock()
	seeded := len(f.seeded.ID) > 0
	f.mu.Unlock()
	if seeded {
		f.rec("inspect")
		return nil, errors.New("inspect denied")
	}
	return f.fakeAd.InspectFixture(ctx, fx)
}

// ---- PAN detection with separators ----

var rePANish = regexp.MustCompile(`[0-9](?:[ -]?[0-9]){12,}`)

// panRuns returns every 13+ digit sequence in s after removing single space or
// dash separators between digits ("4111 1111 1111 1111", "4111-1111-...").
func panRuns(s string) []string {
	var out []string
	for _, m := range rePANish.FindAllString(s, -1) {
		out = append(out, strings.NewReplacer(" ", "", "-", "").Replace(m))
	}
	return out
}

func TestPANDetectorSeesSeparatedDigits(t *testing.T) {
	for _, in := range []string{"4111 1111 1111 1111", "4111-1111-1111-1111", "x 4111111111111111 y", "3782 822463 10005"} {
		got := panRuns(in)
		if len(got) != 1 || len(got[0]) < 13 {
			t.Errorf("%q: runs = %v", in, got)
		}
	}
	if got := panRuns("000-12-3456 +1-555-0101 BAS-SIM-ACCT-0001"); len(got) != 0 {
		t.Errorf("short groups must not be flagged: %v", got)
	}
}

func TestNoSeparatedPANsInCatalog(t *testing.T) {
	for _, name := range Names() {
		spec, _ := Lookup(name)
		for _, tb := range spec.Tables {
			for ri, row := range tb.Rows {
				for _, cell := range row {
					for _, run := range panRuns(cellStrings(cell)) {
						if !pansAllowed[run] {
							t.Errorf("%s.%s row %d: separated digit run %q is not an allow-listed published test number", name, tb.Name, ri, run)
						}
					}
				}
			}
		}
	}
}

// The `empty` fixture has no rows to carry a per-row marker. Its marker is
// structural: the table has the same `synthetic` column as every other table
// and lives in the dedicated dbsim_<id> schema; there is no data to mark.
func TestEmptyFixtureMarkerIsStructural(t *testing.T) {
	spec, _ := Lookup("empty")
	var cols []string
	for _, c := range spec.Tables[0].Columns {
		cols = append(cols, c.Name)
	}
	if !reflect.DeepEqual(cols[:2], []string{"id", "synthetic"}) {
		t.Fatalf("columns = %v", cols)
	}
	if len(spec.Tables[0].Rows) != 0 {
		t.Fatal("empty fixture must stay empty")
	}
}
