package dbsim

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateStoredRunTable(t *testing.T) {
	ok := []byte(`{}`)
	cases := []struct {
		name                         string
		sid, ver, tid, eng, rid, res string
		rep                          []byte
		bad                          bool
	}{
		{"valid", "DB-01", "1", "t", "postgresql", "r", "PASS", ok, false},
		{"skipped ok", "DB-01", "1", "t", "mysql", "r", "SKIPPED", ok, false},
		{"empty scenario", "", "1", "t", "e", "r", "PASS", ok, true},
		{"empty version", "s", "", "t", "e", "r", "PASS", ok, true},
		{"empty target", "s", "1", "", "e", "r", "PASS", ok, true},
		{"empty engine", "s", "1", "t", "", "r", "PASS", ok, true},
		{"empty run", "s", "1", "t", "e", "", "PASS", ok, true},
		{"unknown result", "s", "1", "t", "e", "r", "BLOCKED", ok, true},
		{"lowercase result", "s", "1", "t", "e", "r", "pass", ok, true},
		{"bad json", "s", "1", "t", "e", "r", "PASS", []byte(`{`), true},
		{"nil json", "s", "1", "t", "e", "r", "PASS", nil, true},
	}
	for _, c := range cases {
		err := ValidateStoredRun(c.sid, c.ver, c.tid, c.eng, c.rid, c.res, c.rep)
		if (err != nil) != c.bad || (err != nil && !errors.Is(err, ErrRunInvalid)) {
			t.Errorf("%s: err=%v", c.name, err)
		}
	}
}

func TestRunsSchemaSQLColumnsAndIndex(t *testing.T) {
	ddl := strings.Join(RunsSchemaSQL, "\n")
	for _, w := range []string{"dbsim_runs", "scenario_id      text        NOT NULL", "scenario_version", "target_id", "engine", "run_id", "report           jsonb",
		"created_at", "CHECK (result IN ('PASS', 'FAIL', 'ERROR', 'SKIPPED'))",
		"CREATE INDEX IF NOT EXISTS dbsim_runs_scenario_idx ON dbsim_runs (scenario_id, created_at DESC)"} {
		if !strings.Contains(ddl, w) {
			t.Errorf("DDL missing %q", w)
		}
	}
}
