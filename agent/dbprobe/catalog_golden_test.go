package dbprobe

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

type catalogRow struct {
	ID      string            `json:"id"`
	Class   string            `json:"class"`
	Engines []string          `json:"engines"`
	Params  map[string]string `json:"params"`
	// FixtureParam names the param holding a fixture table name; set only on
	// fixture-aware probes (omitted otherwise so older rows are unchanged).
	FixtureParam string `json:"fixtureParam,omitempty"`
	// RequiredFixture / FixedTable: the one catalog fixture a probe needs and the
	// fixed table it reads (Task 14); omitted otherwise.
	RequiredFixture string `json:"requiredFixture,omitempty"`
	FixedTable      string `json:"fixedTable,omitempty"`
	// LabOnly: refused outside lab mode and needs lab approvals though read_only
	// (Task 15); omitted otherwise.
	LabOnly bool `json:"labOnly,omitempty"`
}

func TestCatalogMatchesGolden(t *testing.T) {
	rows := []catalogRow{}
	for _, id := range ProbeIDs() {
		d, _ := LookupProbe(id)
		p := map[string]string{}
		for k, v := range d.ParamSchema {
			p[k] = string(v)
		}
		rows = append(rows, catalogRow{ID: d.ID, Class: string(d.Class), Engines: d.Engines, Params: p, FixtureParam: d.FixtureParam,
			RequiredFixture: d.RequiredFixture, FixedTable: d.FixedTable, LabOnly: d.LabOnly})
	}
	got, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/probe_catalog.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("catalog drift:\n got %s\nwant %s", got, want)
	}
}
