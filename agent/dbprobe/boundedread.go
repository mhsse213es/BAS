package dbprobe

import (
	"errors"
	"fmt"
	"strconv"
	"time"
)

// Probe ids of the two fixture-aware read probes (DB-05, DB-09).
const (
	ProbeSuspiciousRead       = "suspicious_read"
	ProbeBoundedSyntheticRead = "bounded_synthetic_read"
)

// Bounds of the fixture read probes.
const (
	// SuspiciousReadMaxRows is the hard row cap of suspicious_read: it is a
	// read_only probe, so no spec limit can turn it into a bulk read.
	SuspiciousReadMaxRows = 25
	// MaxReadBytes caps the cell bytes a fixture read accounts for (1 MiB). The
	// read stops counting on a row boundary once the next row would exceed it
	// and reports truncated. Fixture tables are further bounded by the fixture
	// limits (100 rows x 16 columns x 4096 bytes), so what the driver buffers is
	// bounded independently of this cap.
	MaxReadBytes = 1 << 20
)

// Read shapes reported in the result (observed query shape category).
const (
	ShapeWideSelect = "wide_select"        // unfiltered all-column read, small cap (suspicious_read)
	ShapeBulkSelect = "bulk_select_capped" // unfiltered all-column read up to the row cap (bounded_synthetic_read)
)

// ReadShape returns the query shape category of a fixture read probe.
func ReadShape(probeID string) string {
	if probeID == ProbeBoundedSyntheticRead {
		return ShapeBulkSelect
	}
	return ShapeWideSelect
}

// FixtureReadRowCap is the number of rows a fixture read probe may return: the
// spec limit, and for suspicious_read never more than SuspiciousReadMaxRows.
// Both adapters ask the database for cap+1 rows (a bound LIMIT parameter) so a
// truncation is detected, and keep at most cap.
func FixtureReadRowCap(probeID string, maxRows int) int {
	if probeID == ProbeSuspiciousRead && maxRows > SuspiciousReadMaxRows {
		return SuspiciousReadMaxRows
	}
	return maxRows
}

// BoundedReadSummary is everything a fixture read reports about the data it
// read: counts only, never a value.
type BoundedReadSummary struct {
	Rows      int  // rows counted (never more than the row cap)
	Bytes     int  // cell bytes of the counted rows
	Truncated bool // more data existed than the row or byte cap allowed
}

// SummarizeBoundedRead counts rows and cell bytes and applies both caps. rows
// may contain the one sentinel row beyond rowCap. The cell values are measured
// and discarded; nothing here retains or returns them.
func SummarizeBoundedRead(rows [][]any, rowCap, byteCap int) BoundedReadSummary {
	var s BoundedReadSummary
	for _, r := range rows {
		if s.Rows >= rowCap {
			s.Truncated = true
			break
		}
		n := 0
		for _, c := range r {
			n += cellBytes(c)
		}
		if s.Bytes+n > byteCap {
			s.Truncated = true
			break
		}
		s.Rows++
		s.Bytes += n
	}
	return s
}

func cellBytes(v any) int {
	switch t := v.(type) {
	case nil:
		return 0
	case string:
		return len(t)
	case []byte:
		return len(t)
	case bool:
		return 1
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return 8
	case time.Time:
		return 8
	default:
		return len(fmt.Sprint(t))
	}
}

// Notes renders the summary as stable key=value notes (no wire field is added).
func (s BoundedReadSummary) Notes(shape string, d time.Duration) []string {
	return []string{
		"shape=" + shape,
		"rows_read=" + strconv.Itoa(s.Rows),
		"bytes_read=" + strconv.Itoa(s.Bytes),
		"truncated=" + strconv.FormatBool(s.Truncated),
		"duration_ms=" + strconv.FormatInt(d.Milliseconds(), 10),
	}
}

// FixtureBinder is implemented by adapters whose fixture-aware probes need the
// run's active fixture. The executor binds it after a successful Seed and
// unbinds it before Cleanup.
type FixtureBinder interface {
	BindFixture(f Fixture) error
	UnbindFixture()
}

// ActiveFixture holds the fixture a fixture-aware probe may address. Adapters
// embed it. The zero value has no fixture, and Resolve then fails closed.
type ActiveFixture struct {
	f *Fixture
}

// BindFixture records a copy of f as the active fixture. The fixture's declared
// tables are re-validated (identifier shape, bounds); an invalid fixture is not
// bound and any previously bound fixture is dropped.
func (a *ActiveFixture) BindFixture(f Fixture) error {
	a.f = nil
	if f.ID == "" {
		return errors.New("dbprobe: cannot bind a fixture without an id")
	}
	if len(f.Tables) == 0 {
		return errors.New("dbprobe: cannot bind a fixture without tables")
	}
	if err := ValidateFixtureTables(f.Tables); err != nil {
		return err
	}
	c := f
	c.Tables = make([]FixtureTable, len(f.Tables))
	for i, t := range f.Tables {
		c.Tables[i] = FixtureTable{Name: t.Name, Columns: append([]FixtureColumn(nil), t.Columns...)}
	}
	a.f = &c
	return nil
}

// UnbindFixture clears the active fixture.
func (a *ActiveFixture) UnbindFixture() { a.f = nil }

// Resolve returns the active fixture and the declared table whose name equals
// name exactly. A schema-qualified, quoted, differently cased or unknown name
// never matches, so a param can only pick one of the fixture's own tables; the
// schema is always derived from the fixture id by the adapter, never taken from
// a param.
func (a *ActiveFixture) Resolve(name string) (Fixture, FixtureTable, error) {
	if a == nil || a.f == nil {
		return Fixture{}, FixtureTable{}, errors.New("dbprobe: no active fixture: a fixture-aware probe needs a seeded fixture")
	}
	for _, t := range a.f.Tables {
		if t.Name == name {
			return *a.f, t, nil
		}
	}
	return Fixture{}, FixtureTable{}, errors.New("dbprobe: table is not part of the active fixture")
}
