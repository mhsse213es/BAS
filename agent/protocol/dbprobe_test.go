package protocol

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func goldenResult() DBProbeResult {
	t0 := time.Date(2026, 10, 22, 9, 30, 0, 0, time.UTC)
	return DBProbeResult{
		Denied: false, RowsRead: 2, ErrorClass: "", DBTime: t0, AgentTime: t0.Add(250 * time.Millisecond),
		Notes:       []string{"audit_config: partial"},
		AuditStatus: DBAuditFound,
		AuditEvents: []DBProbeAuditEvent{{
			Time: t0.Add(time.Second), Principal: "svc_dbsim_probe",
			Statement: "/* dbsim:BAS-DBSIM-abc123 */ SELECT rolname FROM pg_roles", Source: "dbsim_audit.pg_log",
		}},
	}
}

func TestDBProbeResultGoldenRoundTrip(t *testing.T) {
	want, err := os.ReadFile("testdata/dbprobe_result.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(goldenResult())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("marshal drift:\n got %s\nwant %s", got, want)
	}
	var back DBProbeResult
	if err := json.Unmarshal(want, &back); err != nil {
		t.Fatal(err)
	}
	again, _ := json.Marshal(back)
	if string(again) != string(want) {
		t.Fatalf("round trip drift:\n got %s\nwant %s", again, want)
	}
}

func TestDBProbeResultAuditFieldsOmittedWhenEmpty(t *testing.T) {
	b, _ := json.Marshal(DBProbeResult{})
	if hasKey(b, "auditStatus") || hasKey(b, "auditEvents") {
		t.Fatalf("empty audit fields must be omitted: %s", b)
	}
}

func TestDBAuditStatusValues(t *testing.T) {
	got := []string{DBAuditUnsupported, DBAuditAbsent, DBAuditFound, DBAuditIncomplete, DBAuditError}
	want := []string{"unsupported", "absent", "found", "incomplete", "error"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("status %d: %q want %q", i, got[i], want[i])
		}
	}
}

func goldenSpec() DBProbeSpec {
	return DBProbeSpec{
		Engine: "postgresql", ProbeID: "read_restricted_table", TargetID: "tgt-pg-01",
		Host: "db.lab.internal", Port: 5432, Database: "bas_lab", TLSMode: "verify-full",
		ExpectedIdentity: "7312345678901234567", CredentialRef: "dbcred:cred-ro-pg", RunID: "run-123", Marker: "BAS-DBSIM-abc123",
		FixtureID: "fx-1", Mode: DBModeLab,
		Limits: DBProbeLimits{MaxRows: 100, TimeoutSec: 30, MaxConns: 1},
		Params: map[string]string{"table": "bas_fixture_cards"},
	}
}

func TestDBProbeSpecGoldenRoundTrip(t *testing.T) {
	want, err := os.ReadFile("testdata/dbprobe_spec.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(goldenSpec())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("marshal drift:\n got %s\nwant %s", got, want)
	}
	var back DBProbeSpec
	if err := json.Unmarshal(want, &back); err != nil {
		t.Fatal(err)
	}
	again, _ := json.Marshal(back)
	if string(again) != string(want) {
		t.Fatalf("round trip drift:\n got %s\nwant %s", again, want)
	}
}

func hasKey(b []byte, k string) bool {
	var m map[string]json.RawMessage
	_ = json.Unmarshal(b, &m)
	_, ok := m[k]
	return ok
}

func TestScenarioStepCarriesDBProbe(t *testing.T) {
	spec := goldenSpec()
	b, err := json.Marshal(ScenarioStep{TaskID: "t1", Executor: "dbprobe", DBProbe: &spec})
	if err != nil {
		t.Fatal(err)
	}
	var back ScenarioStep
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.DBProbe == nil || back.DBProbe.ProbeID != "read_restricted_table" {
		t.Fatalf("DBProbe lost: %+v", back.DBProbe)
	}
	b2, _ := json.Marshal(ScenarioStep{TaskID: "t1"})
	if hasKey(b2, "dbProbe") {
		t.Fatalf("dbProbe must be omitted when nil: %s", b2)
	}
}

func TestExecResultCarriesDBProbeResult(t *testing.T) {
	b, _ := json.Marshal(ExecResult{TaskID: "t1", DBProbe: &DBProbeResult{Denied: true, ErrorClass: "permission_denied"}})
	var back ExecResult
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.DBProbe == nil || !back.DBProbe.Denied {
		t.Fatalf("DBProbe result lost: %s", b)
	}
	b2, _ := json.Marshal(ExecResult{TaskID: "t1"})
	if hasKey(b2, "dbProbe") {
		t.Fatalf("dbProbe must be omitted when nil: %s", b2)
	}
}
