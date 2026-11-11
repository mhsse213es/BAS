package segprobe

import (
	"testing"
	"time"
)

func TestMatchEvidence_ExcludesOtherTuples(t *testing.T) {
	start := time.Unix(100, 0)
	req := ProbeRequest{SrcIP: "172.30.1.10", DstIP: "172.30.2.10", DstPort: 8443, Proto: "tcp"}
	res := ProbeResult{Start: start, End: start.Add(time.Second)}
	events := []FirewallEvent{
		{Time: start, SrcIP: "172.30.1.10", DstIP: "172.30.2.10", DstPort: 8443, Proto: "tcp", RuleID: "A"},
		{Time: start, SrcIP: "172.30.1.99", DstIP: "172.30.2.10", DstPort: 8443, Proto: "tcp", RuleID: "B"},
		{Time: start, SrcIP: "172.30.1.10", DstIP: "172.30.2.10", DstPort: 5432, Proto: "tcp", RuleID: "C"},
	}
	got := MatchEvidence(req, res, events, time.Second)
	if len(got) != 1 || got[0].RuleID != "A" {
		t.Fatalf("got %+v, want only RuleID A", got)
	}
}

func TestMatchEvidence_ExcludesOutsideWindow(t *testing.T) {
	start := time.Unix(100, 0)
	req := ProbeRequest{SrcIP: "172.30.1.10", DstIP: "172.30.2.10", DstPort: 8443, Proto: "tcp"}
	res := ProbeResult{Start: start, End: start.Add(time.Second)}
	events := []FirewallEvent{{Time: start.Add(time.Minute), SrcIP: "172.30.1.10", DstIP: "172.30.2.10", DstPort: 8443, Proto: "tcp"}}
	if got := MatchEvidence(req, res, events, time.Second); len(got) != 0 {
		t.Fatalf("got %d events, want 0", len(got))
	}
}
