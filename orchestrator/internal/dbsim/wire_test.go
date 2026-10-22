package dbsim

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

const goldenPath = "testdata/dbprobe_spec.golden.json"
const agentGoldenPath = "../../../agent/protocol/testdata/dbprobe_spec.golden.json"

func mirrorGoldenSpec() DBProbeSpec {
	return DBProbeSpec{
		Engine: "postgresql", ProbeID: "read_restricted_table", TargetID: "tgt-pg-01",
		CredentialRef: "cred-ro-pg", RunID: "run-123", Marker: "BAS-DBSIM-abc123",
		FixtureID: "fx-1", Mode: ModeLab,
		Limits: Limits{MaxRows: 100, TimeoutSec: 30, MaxConns: 1},
		Params: map[string]string{"table": "bas_fixture_cards"},
	}
}

func TestMirrorSpecGoldenRoundTrip(t *testing.T) {
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(mirrorGoldenSpec())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("marshal drift:\n got %s\nwant %s", got, want)
	}
	var back DBProbeSpec
	if err := json.Unmarshal(want, &back); err != nil {
		t.Fatal(err)
	}
	again, _ := json.Marshal(back)
	if !bytes.Equal(again, want) {
		t.Fatalf("round trip drift:\n got %s\nwant %s", again, want)
	}
}

func TestGoldenFilesIdenticalAcrossModules(t *testing.T) {
	agent, err := os.ReadFile(agentGoldenPath)
	if err != nil {
		t.Skipf("agent golden not present (%v); expected in production image", err)
	}
	orch, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(agent, orch) {
		t.Fatalf("golden files diverged between agent/protocol and orchestrator/internal/dbsim")
	}
}

func TestProbeRegistry(t *testing.T) {
	ids := []string{"read_roles", "read_grants", "auth_check", "read_restricted_table"}
	for _, id := range ids {
		e, ok := LookupProbeEntry(id)
		if !ok || e.ID != id || e.Class == "" || len(e.Engines) == 0 {
			t.Errorf("probe %s bad entry: %+v ok=%v", id, e, ok)
		}
	}
	if _, ok := LookupProbeEntry("nope"); ok {
		t.Error("unknown probe found")
	}
}
