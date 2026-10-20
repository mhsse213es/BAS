package killchain

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestProofLevel_OnlyEvidenceSetsTheLevel(t *testing.T) {
	cases := []struct {
		name  string
		proof Proof
		want  Maturity
	}{
		{"catalogued only", Proof{CatalogEntry: true}, MaturityCataloged},
		{"fixture", Proof{CatalogEntry: true, FixtureTestID: "t1"}, MaturityFixtureTested},
		{"adapter", Proof{CatalogEntry: true, FixtureTestID: "t1", AdapterTestID: "a1"}, MaturityAdapterTested},
		{"lab", Proof{CatalogEntry: true, FixtureTestID: "t1", AdapterTestID: "a1", LabRunID: "lab-9"}, MaturityLabValidated},
		{"live", Proof{CatalogEntry: true, FixtureTestID: "t1", AdapterTestID: "a1", LabRunID: "lab-9", LiveRunID: "live-2"}, MaturityLiveValidated},
		// A live run without the lower evidence does not lift the scenario.
		{"live without lab", Proof{CatalogEntry: true, FixtureTestID: "t1", AdapterTestID: "a1", LiveRunID: "live-2"}, MaturityAdapterTested},
		{"lab without adapter", Proof{CatalogEntry: true, FixtureTestID: "t1", LabRunID: "lab-9"}, MaturityFixtureTested},
		{"no catalog entry", Proof{FixtureTestID: "t1"}, MaturityCataloged},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.proof.Level(); got != c.want {
				t.Fatalf("level = %s, want %s", got, c.want)
			}
		})
	}
}

func TestMaturityLabelsAreTheFiveRequiredNames(t *testing.T) {
	want := []string{"cataloged", "fixture-tested", "adapter-tested", "lab-validated", "live-validated"}
	for i, w := range want {
		if got := Maturity(i).String(); got != w {
			t.Fatalf("level %d = %q, want %q", i, got, w)
		}
	}
}

func sampleEntries() []Entry {
	base := Proof{CatalogEntry: true}
	return []Entry{
		{ScenarioID: "a", Domain: "identity", Platform: "windows", Control: "mfa", Campaign: "c1",
			Proof: Proof{CatalogEntry: true, FixtureTestID: "t"}},
		{ScenarioID: "b", Domain: "identity", Platform: "linux", Control: "mfa", Campaign: "c1", Proof: base},
		{ScenarioID: "c", Domain: "endpoint", Platform: "windows", Control: "edr", Campaign: "c2",
			Proof: Proof{CatalogEntry: true, FixtureTestID: "t", AdapterTestID: "a", LabRunID: "lab"}},
		{ScenarioID: "d", Domain: "endpoint", Platform: "macos", Control: "edr", Campaign: "c2",
			Unsupported: true, Proof: base},
	}
}

func TestBuild_CountsPerLevelAndUnsupportedSeparately(t *testing.T) {
	r := Build(sampleEntries())
	want := Counts{Cataloged: 1, FixtureTested: 1, AdapterTested: 0, LabValidated: 1, Unsupported: 1, Total: 4}
	if r.Overall != want {
		t.Fatalf("overall = %+v, want %+v", r.Overall, want)
	}
}

func TestBuild_EveryDimensionIsReported(t *testing.T) {
	r := Build(sampleEntries())
	if len(r.Domains) != 2 || len(r.Platforms) != 3 || len(r.Controls) != 2 || len(r.Campaigns) != 2 {
		t.Fatalf("dimension tables wrong: domains=%d platforms=%d controls=%d campaigns=%d",
			len(r.Domains), len(r.Platforms), len(r.Controls), len(r.Campaigns))
	}
	for _, rows := range [][]Row{r.Domains, r.Platforms, r.Controls, r.Campaigns} {
		total := 0
		for _, row := range rows {
			total += row.Counts.Total
		}
		if total != r.Overall.Total {
			t.Fatalf("a dimension lost entries: %d vs %d", total, r.Overall.Total)
		}
	}
}

func TestBuild_NoCombinedPercentage(t *testing.T) {
	out, err := json.Marshal(Build(sampleEntries()))
	if err != nil {
		t.Fatal(err)
	}
	s := strings.ToLower(string(out))
	for _, banned := range []string{"percent", "pct", "coverage\":", "ratio"} {
		if strings.Contains(s, banned) {
			t.Fatalf("report contains a combined figure (%q): %s", banned, out)
		}
	}
}

func TestBuild_UnassignedDimensionIsNotDropped(t *testing.T) {
	r := Build([]Entry{{ScenarioID: "x", Proof: Proof{CatalogEntry: true}}})
	if len(r.Domains) != 1 || r.Domains[0].Name != "unassigned" {
		t.Fatalf("domains = %+v", r.Domains)
	}
}

func TestBuild_IsStable(t *testing.T) {
	first := Build(sampleEntries())
	for i := 0; i < 20; i++ {
		if !reflect.DeepEqual(Build(sampleEntries()), first) {
			t.Fatalf("report changed on run %d", i)
		}
	}
}

func TestRegressions_DetectsFallAndLoss(t *testing.T) {
	before := []Entry{
		{ScenarioID: "a", Proof: Proof{CatalogEntry: true, FixtureTestID: "t", AdapterTestID: "x"}},
		{ScenarioID: "b", Proof: Proof{CatalogEntry: true, FixtureTestID: "t"}},
		{ScenarioID: "c", Proof: Proof{CatalogEntry: true}},
	}
	after := []Entry{
		{ScenarioID: "a", Proof: Proof{CatalogEntry: true, FixtureTestID: "t"}},
		{ScenarioID: "b", Proof: Proof{CatalogEntry: true, FixtureTestID: "t"}},
	}
	got := Regressions(before, after)
	want := []string{"a: fell from adapter-tested to fixture-tested", "c: removed from coverage"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("regressions = %v, want %v", got, want)
	}
}

func TestRegressions_NewlyUnsupportedIsReported(t *testing.T) {
	before := []Entry{{ScenarioID: "a", Proof: Proof{CatalogEntry: true}}}
	after := []Entry{{ScenarioID: "a", Unsupported: true, Proof: Proof{CatalogEntry: true}}}
	if got := Regressions(before, after); len(got) != 1 || !strings.Contains(got[0], "now unsupported") {
		t.Fatalf("regressions = %v", got)
	}
}

func TestRegressions_ImprovementIsNotARegression(t *testing.T) {
	before := []Entry{{ScenarioID: "a", Proof: Proof{CatalogEntry: true}}}
	after := []Entry{{ScenarioID: "a", Proof: Proof{CatalogEntry: true, FixtureTestID: "t"}}}
	if got := Regressions(before, after); len(got) != 0 {
		t.Fatalf("an improvement was reported: %v", got)
	}
}
