package mysql

import (
	"errors"
	"fmt"

	"audspect/agent/dbprobe"
)

// sqlFixtureRead is the one statement both fixture read probes run. The only
// variable parts are the two identifiers (the schema derived from the active
// fixture id, and a table name that must equal one of that fixture's own
// declared tables), each validated and backtick-quoted; the row bound is a
// parameter.
const sqlFixtureRead = "SELECT * FROM %s LIMIT ?"

// fixtureReadStmt resolves a fixture-aware probe against the active fixture
// and returns the statement, its bound args and the row cap. It runs no SQL and
// fails closed when the adapter is not in lab mode, no fixture is active, the
// table is not part of it, or the spec names a different fixture than the one
// bound.
func (a *Adapter) fixtureReadStmt(def dbprobe.ProbeDef, spec dbprobe.DBProbeSpec, mode dbprobe.ExecMode) (string, []any, int, error) {
	if mode != dbprobe.ModeLab {
		return "", nil, 0, fmt.Errorf("dbprobe/mysql: fixture-aware probe %q refused outside lab mode", def.ID)
	}
	fx, tbl, err := a.Resolve(spec.Params[def.FixtureParam])
	if err != nil {
		return "", nil, 0, fmt.Errorf("dbprobe/mysql: %w", err)
	}
	if spec.FixtureID != fx.Kind {
		return "", nil, 0, errors.New("dbprobe/mysql: spec fixture does not match the active fixture")
	}
	schema, _, err := fixtureNames(fx.ID)
	if err != nil {
		return "", nil, 0, err
	}
	q, err := quoteTable(schema + "." + tbl.Name)
	if err != nil {
		return "", nil, 0, err
	}
	rowCap := dbprobe.FixtureReadRowCap(def.ID, spec.Limits.MaxRows)
	return fmt.Sprintf(sqlFixtureRead, q), []any{rowCap + 1}, rowCap, nil
}
