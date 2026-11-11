package segprobe

import "time"

type Expect string

const (
	ExpectAllow Expect = "allow"
	ExpectDeny  Expect = "deny"
)

type Outcome string

const (
	OutcomeConnected              Outcome = "connected"
	OutcomeRefused                Outcome = "refused"
	OutcomeTimeout                Outcome = "timeout"
	OutcomeProbeUnavailable       Outcome = "probe_unavailable"
	OutcomeDestinationUnavailable Outcome = "destination_unavailable"
)

type Verdict string

const (
	PASS    Verdict = "PASS"
	FAIL    Verdict = "FAIL"
	UNKNOWN Verdict = "UNKNOWN"
	ERROR   Verdict = "ERROR"
)

type ProbeResult struct {
	Outcome Outcome
	Start   time.Time
	End     time.Time
}

type FirewallEvent struct {
	Time    time.Time
	RuleID  string
	Action  string
	SrcIP   string
	DstIP   string
	DstPort int
	Proto   string
}

type Evidence struct {
	ProbeResult       ProbeResult
	Events            []FirewallEvent
	FirewallAvailable bool
}

func hasAction(events []FirewallEvent, actions ...string) bool {
	for _, e := range events {
		for _, a := range actions {
			if e.Action == a {
				return true
			}
		}
	}
	return false
}

// Evaluate returns the verdict for one probe. A PASS always requires firewall
// evidence; a missing firewall log is UNKNOWN, never PASS.
func Evaluate(expect Expect, ev Evidence) (Verdict, string) {
	switch ev.ProbeResult.Outcome {
	case OutcomeProbeUnavailable, OutcomeDestinationUnavailable:
		return ERROR, "destination or probe unavailable"
	}
	if !ev.FirewallAvailable {
		return UNKNOWN, "firewall logging unavailable"
	}
	if expect == ExpectAllow {
		if ev.ProbeResult.Outcome != OutcomeConnected {
			return ERROR, "positive control failed"
		}
		if hasAction(ev.Events, "ACCEPT") {
			return PASS, "authorized connection with firewall accept evidence"
		}
		return UNKNOWN, "connected without firewall accept evidence"
	}
	if ev.ProbeResult.Outcome == OutcomeConnected {
		return FAIL, "prohibited connection succeeded"
	}
	if hasAction(ev.Events, "DROP", "REJECT") {
		return PASS, "blocked with firewall evidence"
	}
	return UNKNOWN, "no attributable enforcement evidence"
}
