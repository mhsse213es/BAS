package api

import (
	"strings"
	"testing"
	"time"
)

func TestScheduleDue(t *testing.T) {
	// Wed 2026-09-23 08:00 UTC (weekday 3).
	now := time.Date(2026, 9, 23, 8, 0, 0, 0, time.UTC)
	yesterday := now.Add(-24 * time.Hour)

	cases := []struct {
		name string
		s    ReportSchedule
		want bool
	}{
		{"daily due, not run today", ReportSchedule{Frequency: "daily", HourUTC: 6, LastRunAt: &yesterday}, true},
		{"daily before hour", ReportSchedule{Frequency: "daily", HourUTC: 9}, false},
		{"daily already ran today", ReportSchedule{Frequency: "daily", HourUTC: 6, LastRunAt: &now}, false},
		{"weekly right day", ReportSchedule{Frequency: "weekly", HourUTC: 6, DayOfWeek: 3, LastRunAt: &yesterday}, true},
		{"weekly wrong day", ReportSchedule{Frequency: "weekly", HourUTC: 6, DayOfWeek: 1}, false},
		{"monthly right day", ReportSchedule{Frequency: "monthly", HourUTC: 6, DayOfMonth: 23, LastRunAt: &yesterday}, true},
		{"monthly wrong day", ReportSchedule{Frequency: "monthly", HourUTC: 6, DayOfMonth: 1}, false},
		{"first run ever (nil last)", ReportSchedule{Frequency: "daily", HourUTC: 6}, true},
	}
	for _, c := range cases {
		if got := scheduleDue(c.s, now); got != c.want {
			t.Errorf("%s: scheduleDue=%v want %v", c.name, got, c.want)
		}
	}
}

func TestValidateSchedule(t *testing.T) {
	bad := []ReportSchedule{
		{ReportType: "bogus", ScopeID: "a", Recipients: "x@y.com", Frequency: "daily"},
		{ReportType: "compliance", ScopeID: "a", Recipients: "x@y.com", Frequency: "daily"}, // no framework
		{ReportType: "board", Recipients: "x@y.com", Frequency: "daily"},                    // no scope
		{ReportType: "board", ScopeID: "a", Frequency: "daily"},                             // no recipients
		{ReportType: "board", ScopeID: "a", Recipients: "x@y.com", Frequency: "hourly"},     // bad freq
		{ReportType: "board", ScopeID: "a", Recipients: "x@y.com", Frequency: "daily", HourUTC: 25},
	}
	for i, s := range bad {
		s := s
		if msg := validateSchedule(&s); msg == "" {
			t.Errorf("case %d: expected validation error, got none", i)
		}
	}
	ok := ReportSchedule{ReportType: "board", ScopeID: "WIN-01", Recipients: "a@b.com", Frequency: "daily", HourUTC: 6}
	if msg := validateSchedule(&ok); msg != "" {
		t.Errorf("valid schedule rejected: %s", msg)
	}
	if ok.Format != "pdf" || ok.ScopeKind != "agent" {
		t.Errorf("defaults not applied: %+v", ok)
	}
}

func TestSplitRecipients(t *testing.T) {
	got := splitRecipients("a@b.com, c@d.com;e@f.com  bad-no-at\n g@h.com")
	want := []string{"a@b.com", "c@d.com", "e@f.com", "g@h.com"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("recipient %d: got %s want %s", i, got[i], want[i])
		}
	}
}

func TestBuildReportMIME(t *testing.T) {
	attach := []byte("%PDF-1.4 fake pdf bytes")
	msg := buildReportMIME("bas@corp.example", "Audspect", []string{"ciso@bank.example"},
		"Weekly Scorecard", "Attached is your report.", "report.pdf", "application/pdf", attach)

	for _, want := range []string{
		"From: Audspect <bas@corp.example>",
		"To: ciso@bank.example",
		"Subject: Weekly Scorecard",
		"MIME-Version: 1.0",
		"multipart/mixed; boundary=bas_",
		"Content-Type: text/plain; charset=UTF-8",
		"Attached is your report.",
		`Content-Type: application/pdf; name="report.pdf"`,
		"Content-Transfer-Encoding: base64",
		`Content-Disposition: attachment; filename="report.pdf"`,
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("MIME missing %q", want)
		}
	}
	// The message must be a well-formed multipart with a closing boundary.
	if strings.Count(msg, "bas_") < 3 { // opening decl + 2 part delimiters + close
		t.Error("expected multiple boundary occurrences")
	}
	if !strings.Contains(msg, "--\r\n") {
		t.Error("missing closing boundary")
	}
}
