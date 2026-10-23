package fixtures

import (
	"strings"
	"testing"

	"audspect/agent/dbprobe"
)

// try_write_fixture / try_disable_audit name their fixtures by constant and the
// write statements by fixed column list; pin both to the real catalog.
func TestTask15ProbeFixtureConstantsMatchTheCatalog(t *testing.T) {
	if dbprobe.WriteFixtureKind != KindAccounts || dbprobe.AuditTamperFixtureKind != KindEmpty {
		t.Fatalf("kind constants drifted: %q %q", dbprobe.WriteFixtureKind, dbprobe.AuditTamperFixtureKind)
	}
	s, ok := Lookup(dbprobe.WriteFixtureKind)
	if !ok {
		t.Fatal("write fixture missing")
	}
	var cols []string
	rowIDs := map[int]bool{}
	for _, tb := range s.Tables {
		if tb.Name != dbprobe.WriteFixtureTable {
			continue
		}
		for _, c := range tb.Columns {
			cols = append(cols, c.Name)
		}
		for _, r := range tb.Rows {
			if id, ok := r[0].(int); ok {
				rowIDs[id] = true
			}
		}
	}
	if got := strings.Join(cols, ","); got != "id,synthetic,account_ref,display_name,email,balance_cents" {
		t.Fatalf("accounts columns drifted from the fixed write statements: %q", got)
	}
	// The UPDATE and DELETE target existing rows (so a success is observable) and
	// the INSERT id does not collide with one.
	if !rowIDs[1] || !rowIDs[2] || rowIDs[9001] {
		t.Fatalf("accounts row ids drifted from the fixed write statements: %v", rowIDs)
	}
}
