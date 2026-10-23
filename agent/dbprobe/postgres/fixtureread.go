package postgres

import (
	"errors"
	"fmt"

	"audspect/agent/dbprobe"
)

// sqlFixtureRead is the one statement both fixture read probes run. The only
// variable parts are the two identifiers (the schema derived from the active
// fixture id, and a table name that must equal one of that fixture's own
// declared tables), each validated and quoted; the row bound is a parameter.
const sqlFixtureRead = "SELECT * FROM %s LIMIT $1"

// fixtureReadStmt resolves a fixture-aware probe against the active fixture
// and returns the statement, its bound args and the row cap. It runs no SQL and
// fails closed (before any connection use) when the adapter is not in lab mode,
// no fixture is active, the table is not part of it, or the spec names a
// different fixture than the one bound.
func (a *Adapter) fixtureReadStmt(def dbprobe.ProbeDef, spec dbprobe.DBProbeSpec, mode dbprobe.ExecMode) (string, []any, int, error) {
	if mode != dbprobe.ModeLab {
		return "", nil, 0, fmt.Errorf("dbprobe/postgres: fixture-aware probe %q refused outside lab mode", def.ID)
	}
	fx, tbl, err := a.Resolve(dbprobe.FixtureTableFor(def, spec))
	if err != nil {
		return "", nil, 0, fmt.Errorf("dbprobe/postgres: %w", err)
	}
	if def.RequiredFixture != "" && fx.Kind != def.RequiredFixture {
		return "", nil, 0, errors.New("dbprobe/postgres: the active fixture is not the one this probe requires")
	}
	if spec.FixtureID != fx.Kind {
		return "", nil, 0, errors.New("dbprobe/postgres: spec fixture does not match the active fixture")
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
