package mysql

import (
	"strings"
	"testing"

	"audspect/agent/dbprobe"
)

// A restricted fixture table is created but never granted to the probe account,
// so reading it must be denied by the database (DB-03).
func TestMySQLRestrictedFixtureTableIsNeverGranted(t *testing.T) {
	tables := []dbprobe.FixtureTable{
		{Name: "open", Columns: []dbprobe.FixtureColumn{{Name: "id", Type: dbprobe.FixtureColInt, PK: true}}},
		{Name: "locked", Restricted: true, Columns: []dbprobe.FixtureColumn{{Name: "id", Type: dbprobe.FixtureColInt, PK: true}}},
	}
	stmts, err := tableFixtureSQL("dbsim_x", "dbsim_x_ro", tables)
	if err != nil {
		t.Fatal(err)
	}
	var grantedOpen, grantedLocked, createdLocked bool
	for _, st := range stmts {
		if strings.HasPrefix(st.sql, "GRANT SELECT ON") {
			if strings.Contains(st.sql, "`open`") {
				grantedOpen = true
			}
			if strings.Contains(st.sql, "`locked`") {
				grantedLocked = true
			}
		}
		if strings.HasPrefix(st.sql, "CREATE TABLE") && strings.Contains(st.sql, "`locked`") {
			createdLocked = true
		}
	}
	if !grantedOpen {
		t.Error("the ordinary fixture table must still be granted")
	}
	if grantedLocked {
		t.Error("a restricted fixture table was granted to the probe account")
	}
	if !createdLocked {
		t.Error("a restricted fixture table must still be created")
	}
}
