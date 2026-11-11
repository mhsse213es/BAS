package segprobe

import (
	"testing"
	"time"
)

func TestEvaluate_ProhibitedConnectionSucceeds_IsFail(t *testing.T) {
	ev := Evidence{ProbeResult: ProbeResult{Outcome: OutcomeConnected}, FirewallAvailable: true}
	got, _ := Evaluate(ExpectDeny, ev)
	if got != FAIL {
		t.Fatalf("got %s, want FAIL", got)
	}
}

func TestEvaluate_FirewallBlockConfirmed_IsPass(t *testing.T) {
	ev := Evidence{
		ProbeResult:       ProbeResult{Outcome: OutcomeTimeout},
		Events:            []FirewallEvent{{RuleID: "SEG-DENY-001", Action: "DROP"}},
		FirewallAvailable: true,
	}
	got, _ := Evaluate(ExpectDeny, ev)
	if got != PASS {
		t.Fatalf("got %s, want PASS", got)
	}
}

func TestEvaluate_TimeoutWithoutEvidence_IsUnknown(t *testing.T) {
	ev := Evidence{ProbeResult: ProbeResult{Outcome: OutcomeTimeout}, FirewallAvailable: true}
	got, _ := Evaluate(ExpectDeny, ev)
	if got != UNKNOWN {
		t.Fatalf("got %s, want UNKNOWN", got)
	}
}

func TestEvaluate_RefusedWithoutEvidence_IsUnknown(t *testing.T) {
	ev := Evidence{ProbeResult: ProbeResult{Outcome: OutcomeRefused}, FirewallAvailable: true}
	got, _ := Evaluate(ExpectDeny, ev)
	if got != UNKNOWN {
		t.Fatalf("got %s, want UNKNOWN", got)
	}
}

func TestEvaluate_DestinationUnavailable_IsError(t *testing.T) {
	ev := Evidence{ProbeResult: ProbeResult{Outcome: OutcomeDestinationUnavailable}, FirewallAvailable: true}
	got, _ := Evaluate(ExpectDeny, ev)
	if got != ERROR {
		t.Fatalf("got %s, want ERROR", got)
	}
}

func TestEvaluate_AuthorizedConnectionSucceeds_IsPass(t *testing.T) {
	ev := Evidence{
		ProbeResult:       ProbeResult{Outcome: OutcomeConnected, Start: time.Unix(10, 0)},
		Events:            []FirewallEvent{{RuleID: "SEG-ALLOW-001", Action: "ACCEPT"}},
		FirewallAvailable: true,
	}
	got, _ := Evaluate(ExpectAllow, ev)
	if got != PASS {
		t.Fatalf("got %s, want PASS", got)
	}
}

func TestEvaluate_AllowRefused_IsError(t *testing.T) {
	ev := Evidence{ProbeResult: ProbeResult{Outcome: OutcomeRefused}, FirewallAvailable: true}
	got, _ := Evaluate(ExpectAllow, ev)
	if got != ERROR {
		t.Fatalf("got %s, want ERROR", got)
	}
}

func TestEvaluate_FirewallLogUnavailable_IsUnknown(t *testing.T) {
	ev := Evidence{ProbeResult: ProbeResult{Outcome: OutcomeConnected}, FirewallAvailable: false}
	got, _ := Evaluate(ExpectAllow, ev)
	if got != UNKNOWN {
		t.Fatalf("got %s, want UNKNOWN", got)
	}
}
