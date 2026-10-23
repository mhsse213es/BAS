package dbsim

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"
)

const goldenPath = "testdata/dbprobe_spec.golden.json"
const agentGoldenPath = "../../../agent/protocol/testdata/dbprobe_spec.golden.json"

func mirrorGoldenSpec() DBProbeSpec {
	return DBProbeSpec{
		Engine: "postgresql", ProbeID: "read_restricted_table", TargetID: "tgt-pg-01",
		Host: "db.lab.internal", Port: 5432, Database: "bas_lab", TLSMode: "verify-full",
		ExpectedIdentity: "7312345678901234567", CredentialRef: "dbcred:cred-ro-pg", RunID: "run-123", Marker: "BAS-DBSIM-abc123",
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

const resultGoldenPath = "testdata/dbprobe_result.golden.json"
const agentResultGoldenPath = "../../../agent/protocol/testdata/dbprobe_result.golden.json"

func mirrorGoldenResult() DBProbeResult {
	t0 := time.Date(2026, 10, 22, 9, 30, 0, 0, time.UTC)
	return DBProbeResult{
		RowsRead: 2, DBTime: t0, AgentTime: t0.Add(250 * time.Millisecond),
		Notes:       []string{"audit_config: partial"},
		AuditStatus: AuditFound,
		AuditEvents: []DBProbeAuditEvent{{
			Time: t0.Add(time.Second), Principal: "svc_dbsim_probe",
			Statement: "/* dbsim:BAS-DBSIM-abc123 */ SELECT rolname FROM pg_roles", Source: "dbsim_audit.pg_log",
		}},
		CleanupStatus: CleanupResidual, SafetyIncident: true,
	}
}

func TestMirrorResultGoldenRoundTrip(t *testing.T) {
	want, err := os.ReadFile(resultGoldenPath)
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(mirrorGoldenResult())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("marshal drift:\n got %s\nwant %s", got, want)
	}
	var back DBProbeResult
	if err := json.Unmarshal(want, &back); err != nil {
		t.Fatal(err)
	}
	again, _ := json.Marshal(back)
	if !bytes.Equal(again, want) {
		t.Fatalf("round trip drift:\n got %s\nwant %s", again, want)
	}
}

func TestResultGoldenIdenticalAcrossModules(t *testing.T) {
	agent, err := os.ReadFile(agentResultGoldenPath)
	if err != nil {
		t.Skipf("agent result golden not present (%v); expected in production image", err)
	}
	orch, err := os.ReadFile(resultGoldenPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(agent, orch) {
		t.Fatal("result golden files diverged between agent/protocol and orchestrator/internal/dbsim")
	}
}

func TestAuditStatusValuesMatchAgent(t *testing.T) {
	got := []string{AuditUnsupported, AuditAbsent, AuditFound, AuditIncomplete, AuditError}
	want := []string{"unsupported", "absent", "found", "incomplete", "error"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("status %d: %q want %q", i, got[i], want[i])
		}
	}
}

func TestProbeRegistry(t *testing.T) {
	ids := []string{"read_roles", "read_grants", "auth_check", "read_restricted_table", "read_audit_config", "suspicious_read", "bounded_synthetic_read"}
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
