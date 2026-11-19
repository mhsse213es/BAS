package postgres

import (
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"audspect/agent/dbprobe"
)

// A restricted fixture table is created but never granted to the probe role, so
// reading it must be denied by the database (DB-03).
func TestPostgresRestrictedFixtureTableIsNeverGranted(t *testing.T) {
	tables := []dbprobe.FixtureTable{
		{Name: "open", Columns: []dbprobe.FixtureColumn{{Name: "id", Type: dbprobe.FixtureColInt, PK: true}}},
		{Name: "locked", Restricted: true, Columns: []dbprobe.FixtureColumn{{Name: "id", Type: dbprobe.FixtureColInt, PK: true}}},
	}
	stmts := tableFixtureStmts("dbsim_x", "dbsim_x_ro", tables)
	var grantedOpen, grantedLocked, createdLocked bool
	for _, st := range stmts {
		if strings.HasPrefix(st.sql, "GRANT SELECT ON") {
			if strings.Contains(st.sql, `"open"`) {
				grantedOpen = true
			}
			if strings.Contains(st.sql, `"locked"`) {
				grantedLocked = true
			}
		}
		if strings.HasPrefix(st.sql, "CREATE TABLE") && strings.Contains(st.sql, `"locked"`) {
			createdLocked = true
		}
	}
	if !grantedOpen {
		t.Error("the ordinary fixture table must still be granted")
	}
	if grantedLocked {
		t.Error("a restricted fixture table was granted to the probe role")
	}
	if !createdLocked {
		t.Error("a restricted fixture table must still be created")
	}
}

// A restricted table is owned by a per-run owner role the seeding login cannot read
// through, and the login is only a member of the roles it needs (DB-03).
func TestPostgresRestrictedFixtureTableIsOwnedByRunOwnerRole(t *testing.T) {
	tables := []dbprobe.FixtureTable{
		{Name: "open", Columns: []dbprobe.FixtureColumn{{Name: "id", Type: dbprobe.FixtureColInt, PK: true}}},
		{Name: "locked", Restricted: true, Columns: []dbprobe.FixtureColumn{{Name: "id", Type: dbprobe.FixtureColInt, PK: true}}},
	}
	schema, role := "dbsim_x", "dbsim_x_ro"
	owner := ownerRoleFor(schema)
	qo := pgx.Identifier{owner}.Sanitize()
	stmts := tableFixtureStmts(schema, role, tables)
	var createdOwner, alteredLocked, alteredOpen bool
	for _, st := range stmts {
		if st.sql == "CREATE ROLE "+qo+" NOLOGIN" {
			createdOwner = true
		}
		if strings.HasPrefix(st.sql, "ALTER TABLE") && strings.Contains(st.sql, `"locked"`) && strings.Contains(st.sql, "OWNER TO "+qo) {
			alteredLocked = true
		}
		if strings.HasPrefix(st.sql, "ALTER TABLE") && strings.Contains(st.sql, `"open"`) {
			alteredOpen = true
		}
	}
	if !createdOwner || !alteredLocked {
		t.Errorf("restricted table must be owned by the run owner role (created=%v owned=%v)", createdOwner, alteredLocked)
	}
	if alteredOpen {
		t.Error("an ordinary table must keep the seeding login as owner")
	}
}

// A fixture without restricted tables gets no owner role, so existing fixtures are
// seeded exactly as before.
func TestPostgresFixtureWithoutRestrictedTablesHasNoOwnerRole(t *testing.T) {
	tables := []dbprobe.FixtureTable{{Name: "open", Columns: []dbprobe.FixtureColumn{{Name: "id", Type: dbprobe.FixtureColInt, PK: true}}}}
	for _, st := range tableFixtureStmts("dbsim_x", "dbsim_x_ro", tables) {
		if strings.Contains(st.sql, "_own") || strings.Contains(st.sql, "OWNER TO") {
			t.Errorf("unexpected owner statement for an unrestricted fixture: %s", st.sql)
		}
	}
}
