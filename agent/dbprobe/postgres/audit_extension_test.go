package postgres

import (
	"strings"
	"testing"
)

// DB-04-01 (audit configuration inspection) also requires the pgaudit extension
// to be installed, not only its settings. The settings query reports that as a
// pgaudit_extension row, and auditConfigNotes passes it through.
func TestAuditConfigReportsPgauditExtension(t *testing.T) {
	if !strings.Contains(sqlAuditSettings, "pgaudit_extension") {
		t.Fatal("settings query does not report the pgaudit extension")
	}
	found := false
	for _, k := range auditConfigKeys {
		if k == "pgaudit_extension" {
			found = true
		}
	}
	if !found {
		t.Fatal("pgaudit_extension is not a reported audit configuration key")
	}
	notes := auditConfigNotes([][]any{{"pgaudit_extension", "present"}}, []any{false, false})
	if !containsNote(notes, "pgaudit_extension=present") {
		t.Fatalf("notes = %v, want pgaudit_extension=present", notes)
	}
	notes = auditConfigNotes(nil, []any{false, false})
	if !containsNote(notes, "pgaudit_extension=absent") {
		t.Fatalf("notes = %v, want pgaudit_extension=absent", notes)
	}
}

func containsNote(notes []string, want string) bool {
	for _, n := range notes {
		if n == want {
			return true
		}
	}
	return false
}
