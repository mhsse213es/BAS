package scenario

import (
	"testing"

	"github.com/audspect/bas/internal/models"
)

func TestFraudVerdictTable(t *testing.T) {
	cases := []struct {
		name     string
		rec      models.FraudControl
		want     string
		wantWhat string
	}{
		{
			name:     "ledger not called is skipped",
			rec:      models.FraudControl{ExpectedControl: "prevent", LedgerCalled: false},
			want:     "SKIPPED",
			wantWhat: "ledger not called",
		},
		{
			name: "prevent with rejected passes",
			rec:  models.FraudControl{ExpectedControl: "prevent", LedgerCalled: true, LedgerDecision: "rejected"},
			want: "PASS",
		},
		{
			name: "prevent with approved fails",
			rec:  models.FraudControl{ExpectedControl: "prevent", LedgerCalled: true, LedgerDecision: "approved"},
			want: "FAIL",
		},
		{
			name: "detect with flagged passes",
			rec:  models.FraudControl{ExpectedControl: "detect", LedgerCalled: true, LedgerDecision: "flagged"},
			want: "PASS",
		},
		{
			name: "detect with approved and no alert fails",
			rec:  models.FraudControl{ExpectedControl: "detect", LedgerCalled: true, LedgerDecision: "approved", AlertPresent: false},
			want: "FAIL",
		},
		{
			name: "detect with approved but alert present passes",
			rec:  models.FraudControl{ExpectedControl: "detect", LedgerCalled: true, LedgerDecision: "approved", AlertPresent: true},
			want: "PASS",
		},
		{
			name: "verify with intact audit passes",
			rec:  models.FraudControl{ExpectedControl: "verify", LedgerCalled: true, AuditIntact: true},
			want: "PASS",
		},
		{
			name:     "evidence-only step is skipped as not a control test",
			rec:      models.FraudControl{ExpectedControl: "evidence", LedgerCalled: true, LedgerDecision: "approved"},
			want:     "SKIPPED",
			wantWhat: "evidence only, not a control test",
		},
		{
			name: "verify with tampered audit fails",
			rec:  models.FraudControl{ExpectedControl: "verify", LedgerCalled: true, AuditIntact: false},
			want: "FAIL",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verdict, reason := FraudVerdict(tc.rec)
			if verdict != tc.want {
				t.Fatalf("verdict = %q, want %q", verdict, tc.want)
			}
			if tc.wantWhat != "" && reason != tc.wantWhat {
				t.Fatalf("reason = %q, want %q", reason, tc.wantWhat)
			}
		})
	}
}

func TestCombinedVerdict(t *testing.T) {
	cases := []struct {
		endpoint, fraud, want string
	}{
		{"PASS", "PASS", "PASS"},
		{"PASS", "FAIL", "FAIL"},
		{"FAIL", "PASS", "FAIL"},
		{"FAIL", "FAIL", "FAIL"},
		// An endpoint block with no ledger call must not read as overall PASS.
		{"PASS", "SKIPPED", "SKIPPED"},
		{"SKIPPED", "PASS", "SKIPPED"},
	}
	for _, tc := range cases {
		if got := CombinedVerdict(tc.endpoint, tc.fraud); got != tc.want {
			t.Errorf("CombinedVerdict(%s,%s) = %s, want %s", tc.endpoint, tc.fraud, got, tc.want)
		}
	}
}

func TestParseFraudControlFromOutput(t *testing.T) {
	out := "Starting fraud step\n" +
		`BAS-FRAUD-CONTROL {"step":"8b","expected_control":"prevent","ledger_called":true,"ledger_decision":"rejected","rule_fired":"beneficiary_second_approver_missing","audit_hash":"abc"}` +
		"\nDone\n"
	rec, ok := ParseFraudControl(out)
	if !ok {
		t.Fatal("marker not parsed")
	}
	if rec.Step != "8b" || rec.ExpectedControl != "prevent" || !rec.LedgerCalled {
		t.Fatalf("fields wrong: %+v", rec)
	}
	if rec.Verdict != "PASS" {
		t.Fatalf("verdict = %q, want PASS", rec.Verdict)
	}
}

func TestParseFraudControlAbsent(t *testing.T) {
	if _, ok := ParseFraudControl("no marker here"); ok {
		t.Fatal("parsed a marker from output that has none")
	}
}
