package dbsim

import (
	"bytes"
	"encoding/json"
	"os"
	"sort"
	"testing"
)

const agentDir = "../../../agent/dbprobe"
const agentCatalogGoldenPath = agentDir + "/testdata/probe_catalog.golden.json"

type catalogRow struct {
	ID      string            `json:"id"`
	Class   string            `json:"class"`
	Engines []string          `json:"engines"`
	Params  map[string]string `json:"params"`
	// FixtureParam is set only on fixture-aware probes (omitted otherwise).
	FixtureParam string `json:"fixtureParam,omitempty"`
}

func marshalRegistry() ([]byte, error) {
	ids := make([]string, 0, len(probeRegistry))
	for id := range probeRegistry {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rows := []catalogRow{}
	for _, id := range ids {
		e := probeRegistry[id]
		p := map[string]string{}
		for k, v := range e.ParamSchema {
			p[k] = v
		}
		rows = append(rows, catalogRow{ID: e.ID, Class: string(e.Class), Engines: e.Engines, Params: p, FixtureParam: e.FixtureParam})
	}
	return json.Marshal(rows)
}

func TestProbeRegistryMatchesGolden(t *testing.T) {
	got, err := marshalRegistry()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/probe_catalog.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("registry drift:\n got %s\nwant %s", got, want)
	}
}

func TestCatalogGoldenIdenticalAcrossModules(t *testing.T) {
	if _, err := os.Stat(agentDir); err != nil {
		if os.IsNotExist(err) {
			t.Skipf("agent directory absent: %v", err)
		}
		t.Fatal(err)
	}
	agent, err := os.ReadFile(agentCatalogGoldenPath)
	if err != nil {
		t.Fatal(err)
	}
	orch, err := os.ReadFile("testdata/probe_catalog.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(agent, orch) {
		t.Fatal("probe catalog goldens diverged between agent/dbprobe and orchestrator/internal/dbsim")
	}
}
