package carbanakledger

import (
	"testing"
	"time"
)

func testWindow(t *testing.T) Window {
	t.Helper()
	w, err := DefaultWindow()
	if err != nil {
		t.Fatalf("DefaultWindow: %v", err)
	}
	return w
}

func ist(t *testing.T, s string) time.Time {
	t.Helper()
	loc, err := time.LoadLocation("Asia/Kolkata")
	if err != nil {
		t.Fatalf("location: %v", err)
	}
	tm, err := time.ParseInLocation("2006-01-02 15:04:05", s, loc)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return tm
}

func TestEvaluate(t *testing.T) {
	w := testWindow(t)
	inside := ist(t, "2026-11-16 10:00:00") // Monday, inside window
	outside := ist(t, "2026-11-16 20:00:00")

	cases := []struct {
		name     string
		action   Action
		want     Decision
		wantRule string
	}{
		{
			name:     "self approval rejected",
			action:   Action{Kind: "approve", Actor: "op1", Approver: "op1", ApproverRole: true, At: inside},
			want:     Rejected,
			wantRule: "maker_checker_self_approval",
		},
		{
			name:     "approver without approver role rejected",
			action:   Action{Kind: "approve", Actor: "op1", Approver: "op2", ApproverRole: false, At: inside},
			want:     Rejected,
			wantRule: "approver_role_missing",
		},
		{
			name:     "beneficiary change without second approver rejected",
			action:   Action{Kind: "beneficiary", Actor: "op1", SecondApproverPresent: false, At: inside},
			want:     Rejected,
			wantRule: "beneficiary_second_approver_missing",
		},
		{
			name:     "beneficiary change with second approver approved",
			action:   Action{Kind: "beneficiary", Actor: "op1", SecondApproverPresent: true, SameHostAsSession: true, At: inside},
			want:     Approved,
		},
		{
			name:     "amount over limit flagged",
			action:   Action{Kind: "transfer", Actor: "op1", Amount: 200, Limit: 100, SameHostAsSession: true, At: inside},
			want:     Flagged,
			wantRule: "amount_over_limit",
		},
		{
			name:     "limit change without privileged role rejected",
			action:   Action{Kind: "limit", Actor: "op1", PrivilegedRole: false, At: inside},
			want:     Rejected,
			wantRule: "limit_change_unprivileged",
		},
		{
			name:     "transfer outside window flagged",
			action:   Action{Kind: "transfer", Actor: "op1", Amount: 10, Limit: 100, SameHostAsSession: true, At: outside},
			want:     Flagged,
			wantRule: "outside_operating_window",
		},
		{
			name:     "session reuse from another host flagged",
			action:   Action{Kind: "transfer", Actor: "op1", Amount: 10, Limit: 100, SameHostAsSession: false, At: inside},
			want:     Flagged,
			wantRule: "session_anomaly",
		},
		{
			name:     "expired session flagged",
			action:   Action{Kind: "transfer", Actor: "op1", Amount: 10, Limit: 100, SameHostAsSession: true, SessionExpired: true, At: inside},
			want:     Flagged,
			wantRule: "session_anomaly",
		},
		{
			name:     "ordinary in-window transfer approved",
			action:   Action{Kind: "transfer", Actor: "op1", Amount: 10, Limit: 100, SameHostAsSession: true, At: inside},
			want:     Approved,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, rule := Evaluate(tc.action, w)
			if got != tc.want {
				t.Fatalf("decision = %q, want %q (rule %q)", got, tc.want, rule)
			}
			if rule != tc.wantRule {
				t.Fatalf("rule_fired = %q, want %q", rule, tc.wantRule)
			}
		})
	}
}

func TestWindowBoundaries(t *testing.T) {
	w := testWindow(t)
	cases := []struct {
		at     string
		inside bool
	}{
		{"2026-11-16 08:59:59", false}, // Monday, just before 09:00
		{"2026-11-16 09:00:00", true},  // Monday, 09:00 inclusive
		{"2026-11-16 17:59:59", true},  // Monday, just before 18:00
		{"2026-11-16 18:00:00", false}, // Monday, 18:00 exclusive
		{"2026-11-21 10:00:00", false}, // Saturday
		{"2026-11-22 10:00:00", false}, // Sunday
	}
	for _, tc := range cases {
		if got := w.Inside(ist(t, tc.at)); got != tc.inside {
			t.Errorf("Inside(%s) = %v, want %v", tc.at, got, tc.inside)
		}
	}
}

func TestWindowIsConfigurable(t *testing.T) {
	loc, err := time.LoadLocation("UTC")
	if err != nil {
		t.Fatal(err)
	}
	w := Window{Location: loc, StartHour: 0, EndHour: 24, Weekdays: []time.Weekday{time.Saturday}}
	if !w.Inside(time.Date(2026, 11, 21, 3, 0, 0, 0, loc)) {
		t.Fatal("a Saturday 03:00 UTC should be inside a custom window that includes Saturday")
	}
}
