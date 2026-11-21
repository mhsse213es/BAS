package postgres

import "testing"

// DB-04-02: pgaudit only records when it is loaded through shared_preload_libraries.
// An installed extension with a met policy but no preload is inert, so coverage
// must not be "covered".
func TestPgauditNotPreloadedCapsCoverageAtPartial(t *testing.T) {
	settings := [][]any{
		{"log_statement", "none"},
		{"pgaudit.log", "read,write,ddl,role"},
		{"pgaudit_extension", "present"},
		{"shared_preload_libraries", "absent"},
	}
	notes := auditConfigNotes(settings, []any{true, true})
	if !containsNote(notes, "pgaudit_loaded=no") {
		t.Fatalf("notes = %v, want pgaudit_loaded=no", notes)
	}
	if !containsNote(notes, "audit_config: partial") {
		t.Fatalf("notes = %v, want audit_config: partial when pgaudit is not preloaded", notes)
	}
}

func TestPgauditPreloadedAllowsCovered(t *testing.T) {
	settings := [][]any{
		{"log_statement", "all"},
		{"pgaudit.log", "read,write,ddl,role"},
		{"pgaudit_extension", "present"},
		{"shared_preload_libraries", "auto_explain, pgaudit"},
	}
	notes := auditConfigNotes(settings, []any{true, true})
	if !containsNote(notes, "pgaudit_loaded=yes") {
		t.Fatalf("notes = %v, want pgaudit_loaded=yes", notes)
	}
	if !containsNote(notes, "audit_config: covered") {
		t.Fatalf("notes = %v, want audit_config: covered", notes)
	}
}

func TestPreloadListMatchesPgauditExactly(t *testing.T) {
	if preloadHasPgaudit("pgaudit_x,auto_explain") || !preloadHasPgaudit(" auto_explain , pgaudit ") {
		t.Fatal("preload list must match the pgaudit name exactly")
	}
}

// The probe role may be denied shared_preload_libraries (PostgreSQL requires
// pg_read_all_settings). An unreadable setting is not the same as an absent one: it
// must report unknown, never a confirmed "no", and coverage must not be covered.
func TestUnreadablePreloadReportsUnknownNotAbsent(t *testing.T) {
	settings := [][]any{
		{"log_statement", "all"},
		{"pgaudit.log", "read,write,ddl,role"},
		{"pgaudit_extension", "present"},
	}
	notes := auditConfigNotes(settings, []any{true, true})
	if !containsNote(notes, "pgaudit_loaded=unknown") {
		t.Fatalf("notes = %v, want pgaudit_loaded=unknown for an unreadable preload", notes)
	}
	if containsNote(notes, "audit_config: covered") {
		t.Fatalf("notes = %v, an unverifiable preload must not be covered", notes)
	}
}
