package dbsim

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ErrRunInvalid means a stored-run record failed validation.
var ErrRunInvalid = errors.New("dbsim run invalid")

// ValidateStoredRun is the pure (DB-free) validation behind
// db.DBSimRun.validate, kept here so it is testable without the Docker
// TestMain the internal/db package requires.
func ValidateStoredRun(scenarioID, version, targetID, engine, runID, result string, report []byte) error {
	switch {
	case scenarioID == "":
		return fmt.Errorf("%w: scenario id is empty", ErrRunInvalid)
	case version == "":
		return fmt.Errorf("%w: scenario version is empty", ErrRunInvalid)
	case targetID == "":
		return fmt.Errorf("%w: target id is empty", ErrRunInvalid)
	case engine == "":
		return fmt.Errorf("%w: engine is empty", ErrRunInvalid)
	case runID == "":
		return fmt.Errorf("%w: run id is empty", ErrRunInvalid)
	case !RunResult(result).Valid():
		return fmt.Errorf("%w: result %q is not a grade", ErrRunInvalid, result)
	case !json.Valid(report):
		return fmt.Errorf("%w: report is not valid JSON", ErrRunInvalid)
	}
	return nil
}

// RunsSchemaSQL is the DDL for dbsim_runs (statements executed in order).
var RunsSchemaSQL = []string{
	`CREATE TABLE IF NOT EXISTS dbsim_runs (
			id               text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			scenario_id      text        NOT NULL,
			scenario_version text        NOT NULL,
			target_id        text        NOT NULL,
			engine           text        NOT NULL,
			run_id           text        NOT NULL,
			result           text        NOT NULL CHECK (result IN ('PASS', 'FAIL', 'ERROR', 'SKIPPED')),
			report           jsonb       NOT NULL,
			created_at       timestamptz NOT NULL DEFAULT NOW(),
			UNIQUE (run_id, scenario_id)
		)`,
	`CREATE INDEX IF NOT EXISTS dbsim_runs_scenario_idx ON dbsim_runs (scenario_id, created_at DESC)`,
}
