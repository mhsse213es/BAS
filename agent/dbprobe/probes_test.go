package dbprobe

import (
	"encoding/json"
	"math"
	"testing"
)

func validSpec() DBProbeSpec {
	return DBProbeSpec{
		Engine: "postgresql", ProbeID: "read_roles", TargetID: "t", Host: "db.example", Port: 5432, ExpectedIdentity: "id-1", CredentialRef: "c",
		RunID: "r", Marker: "m", Mode: ModeLab,
		Limits: Limits{MaxRows: 10, TimeoutSec: 5, MaxConns: 1},
	}
}

func TestDBProbeSpecRoundTripsJSON(t *testing.T) {
	s := validSpec()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var back DBProbeSpec
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.ProbeID != s.ProbeID || back.Limits != s.Limits || back.Mode != ModeLab {
		t.Fatalf("round trip mismatch: %+v", back)
	}
}

func TestLookupProbeUnknownIDNotFound(t *testing.T) {
	if _, ok := LookupProbe("drop_everything"); ok {
		t.Fatal("unknown probe id must not be found")
	}
	if _, ok := LookupProbe("read_roles"); !ok {
		t.Fatal("read_roles must exist")
	}
}

func TestEveryProbeDeclaresClassAndEngines(t *testing.T) {
	ids := ProbeIDs()
	if len(ids) != 13 {
		t.Fatalf("want 13 probes, got %v", ids)
	}
	for _, id := range ids {
		d, ok := LookupProbe(id)
		if !ok || d.ID != id {
			t.Fatalf("probe %s lookup mismatch", id)
		}
		if d.Class == "" || len(d.Engines) == 0 {
			t.Errorf("probe %s missing class/engines", id)
		}
	}
}

func TestParamSchemaRejectsUndeclaredParam(t *testing.T) {
	s := validSpec()
	s.Params = map[string]string{"sql": "select 1"}
	if err := ValidateSpec(s); err == nil {
		t.Fatal("undeclared param must be rejected")
	}
	s.Params = nil
	if err := ValidateSpec(s); err != nil {
		t.Fatalf("valid spec rejected: %v", err)
	}
}

func TestValidateSpecRejectsBadInputs(t *testing.T) {
	cases := map[string]func(*DBProbeSpec){
		"unknown probe": func(s *DBProbeSpec) { s.ProbeID = "nope" },
		"bad engine":    func(s *DBProbeSpec) { s.Engine = "oracle" },
		"zero rows":     func(s *DBProbeSpec) { s.Limits.MaxRows = 0 },
		"zero timeout":  func(s *DBProbeSpec) { s.Limits.TimeoutSec = 0 },
		"zero conns":    func(s *DBProbeSpec) { s.Limits.MaxConns = 0 },
		"bad mode":      func(s *DBProbeSpec) { s.Mode = "weird" },
		"huge rows":     func(s *DBProbeSpec) { s.Limits.MaxRows = math.MaxInt },
		"rows over cap": func(s *DBProbeSpec) { s.Limits.MaxRows = MaxRowsCap + 1 },
		"huge timeout":  func(s *DBProbeSpec) { s.Limits.TimeoutSec = math.MaxInt },
		"timeout cap":   func(s *DBProbeSpec) { s.Limits.TimeoutSec = MaxTimeoutSecCap + 1 },
		"conns cap":     func(s *DBProbeSpec) { s.Limits.MaxConns = MaxConnsCap + 1 },
		"empty host":    func(s *DBProbeSpec) { s.Host = "" },
		"negative port": func(s *DBProbeSpec) { s.Port = -1 },
		"port too big":  func(s *DBProbeSpec) { s.Port = 65536 },
		"no identity":   func(s *DBProbeSpec) { s.ExpectedIdentity = "" },
	}
	for name, mut := range cases {
		s := validSpec()
		mut(&s)
		if ValidateSpec(s) == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
