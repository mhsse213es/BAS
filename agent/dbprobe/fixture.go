package dbprobe

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"unicode/utf8"
)

// Synthetic fixture data model. A fixture is a handful of small tables whose
// content is declared as data (never as SQL text). Adapters turn it into DDL
// with their own identifier quoting and bind every value as a parameter.

// Bounds applied by ValidateFixtureTables (and so by Seed and by the adapters).
const (
	MaxFixtureTables    = 8
	MaxFixtureColumns   = 16
	MaxFixtureRows      = 100 // per table
	MaxFixtureTotalRows = 300
	MaxFixtureCellBytes = 4096
)

// Column types a fixture may declare.
const (
	FixtureColInt  = "int"
	FixtureColText = "text"
)

// FixtureColumn declares one column. PK is allowed on int columns only.
type FixtureColumn struct {
	Name string `json:"name"`
	Type string `json:"type"`
	PK   bool   `json:"pk,omitempty"`
}

// FixtureTable is one synthetic table. Row cells are nil (NULL), string or
// int/int64, matching the column type.
type FixtureTable struct {
	Name    string          `json:"name"`
	Columns []FixtureColumn `json:"columns"`
	Rows    [][]any         `json:"rows,omitempty"`
}

var fixtureIdent = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)

// ValidateFixtureTables enforces identifier shape, column types and the size
// bounds. It is the single implementation shared by fixtures.Seed and both
// adapters.
func ValidateFixtureTables(tables []FixtureTable) error {
	if len(tables) > MaxFixtureTables {
		return fmt.Errorf("dbprobe: fixture has %d tables (max %d)", len(tables), MaxFixtureTables)
	}
	seen := map[string]bool{}
	total := 0
	for _, t := range tables {
		if !fixtureIdent.MatchString(t.Name) || seen[t.Name] {
			return errors.New("dbprobe: invalid or duplicate fixture table name")
		}
		seen[t.Name] = true
		if len(t.Columns) == 0 || len(t.Columns) > MaxFixtureColumns {
			return fmt.Errorf("dbprobe: fixture table %q must have 1..%d columns", t.Name, MaxFixtureColumns)
		}
		cols := map[string]bool{}
		for _, c := range t.Columns {
			if !fixtureIdent.MatchString(c.Name) || cols[c.Name] {
				return fmt.Errorf("dbprobe: invalid or duplicate column name in fixture table %q", t.Name)
			}
			cols[c.Name] = true
			if c.Type != FixtureColInt && c.Type != FixtureColText {
				return fmt.Errorf("dbprobe: unsupported column type in fixture table %q", t.Name)
			}
			if c.PK && c.Type != FixtureColInt {
				return fmt.Errorf("dbprobe: primary key must be an int column in fixture table %q", t.Name)
			}
		}
		if len(t.Rows) > MaxFixtureRows {
			return fmt.Errorf("dbprobe: fixture table %q has %d rows (max %d)", t.Name, len(t.Rows), MaxFixtureRows)
		}
		total += len(t.Rows)
		if total > MaxFixtureTotalRows {
			return fmt.Errorf("dbprobe: fixture exceeds %d total rows", MaxFixtureTotalRows)
		}
		for ri, row := range t.Rows {
			if len(row) != len(t.Columns) {
				return fmt.Errorf("dbprobe: fixture table %q row %d has %d cells, want %d", t.Name, ri, len(row), len(t.Columns))
			}
			for ci, cell := range row {
				if err := validateCell(t.Columns[ci], cell); err != nil {
					return fmt.Errorf("dbprobe: fixture table %q row %d: %w", t.Name, ri, err)
				}
			}
		}
	}
	return nil
}

func validateCell(c FixtureColumn, cell any) error {
	if cell == nil {
		if c.PK {
			return errors.New("NULL in primary key column")
		}
		return nil
	}
	switch c.Type {
	case FixtureColInt:
		switch cell.(type) {
		case int, int64:
			return nil
		}
		return errors.New("int column holds a non-int value")
	default:
		s, ok := cell.(string)
		if !ok {
			return errors.New("text column holds a non-string value")
		}
		if len(s) > MaxFixtureCellBytes {
			return fmt.Errorf("cell exceeds %d bytes", MaxFixtureCellBytes)
		}
		if !utf8.ValidString(s) {
			return errors.New("cell is not valid UTF-8")
		}
		for _, r := range s {
			if r == 0 {
				return errors.New("cell contains NUL")
			}
		}
	}
	return nil
}

// FixtureCellArg converts a validated cell to a driver argument.
func FixtureCellArg(cell any) any {
	if i, ok := cell.(int); ok {
		return int64(i)
	}
	return cell
}

// ErrFixtureNotCreated is wrapped by an adapter's Seed error when nothing of
// this call's fixture exists afterwards: the first CREATE failed (for example
// the name already exists), or everything this call created was rolled back and
// that was confirmed. The caller must then skip Cleanup entirely, so no DROP is
// ever issued for an object this call did not create. Adapters must NOT wrap it
// when the resulting state is unknown (context cancelled, rollback failed,
// commit outcome unknown).
var ErrFixtureNotCreated = errors.New("dbprobe: fixture not created")

// ModeReporter is implemented by adapters that can state their connection mode;
// fixtures.Seed uses it to refuse non-lab adapters before any SQL.
type ModeReporter interface {
	Mode() ExecMode
}

// FixtureInspector lists the objects that exist for a fixture (its schema,
// tables, and role/user) so Seed can record pre-test state and VerifyClean can
// prove teardown. Entries look like "schema:dbsim_x", "table:dbsim_x.t",
// "role:dbsim_x_ro".
type FixtureInspector interface {
	InspectFixture(ctx context.Context, f Fixture) ([]string, error)
}
