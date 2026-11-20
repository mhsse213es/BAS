package postgres

import "testing"

// DB-04-02: pgaudit.log must enable write, ddl and role (the stated policy). A
// missing extension or an unmet policy caps coverage at partial.
func TestPgauditPolicyRequiresWriteDDLRole(t *testing.T) {
	cases := map[string]bool{
		"write,ddl,role":       true,
		"read,write,ddl,role":  true,
		"all":                  true,
		"read":                 false,
		"write,ddl":            false,
		"write,ddl,role,-role": false,
		"":                     false,
		"none":                 false,
	}
	for v, want := range cases {
		if got := pgauditPolicyMet(v); got != want {
			t.Errorf("pgauditPolicyMet(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestAuditCoverageRequiresExtensionAndPolicy(t *testing.T) {
	if got := pgAuditCoverage("all", "", true, false, false); got != "partial" {
		t.Error("no pgaudit extension must cap coverage at partial:", got)
	}
	if got := pgAuditCoverage("none", "read,write,ddl,role", true, true, true); got != "covered" {
		t.Error("extension + met policy + readable view is covered:", got)
	}
	if got := pgAuditCoverage("none", "read", true, true, false); got != "partial" {
		t.Error("unmet policy must cap coverage at partial:", got)
	}
}

func TestAuditConfigNotesReportPolicy(t *testing.T) {
	notes := auditConfigNotes([][]any{
		{"pgaudit.log", "read,write,ddl,role"}, {"pgaudit_extension", "present"},
	}, []any{true, true})
	if !containsNote(notes, "pgaudit_policy=met") {
		t.Fatalf("notes = %v, want pgaudit_policy=met", notes)
	}
	notes = auditConfigNotes([][]any{
		{"pgaudit.log", "read"}, {"pgaudit_extension", "present"},
	}, []any{true, true})
	if !containsNote(notes, "pgaudit_policy=not_met") {
		t.Fatalf("notes = %v, want pgaudit_policy=not_met", notes)
	}
	notes = auditConfigNotes(nil, []any{false, false})
	if !containsNote(notes, "pgaudit_policy=absent") {
		t.Fatalf("notes = %v, want pgaudit_policy=absent", notes)
	}
}
