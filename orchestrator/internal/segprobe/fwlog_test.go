package segprobe

import (
	"os"
	"testing"
)

func TestParseFirewallLog_RealCapture(t *testing.T) {
	data, err := os.ReadFile("testdata/fw_sample.log")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	events, err := ParseFirewallLog(data)
	if err != nil {
		t.Fatalf("ParseFirewallLog: %v", err)
	}
	if len(events) != 10 {
		t.Fatalf("got %d events, want 10", len(events))
	}
	var allow *FirewallEvent
	for i := range events {
		if events[i].RuleID == "SEG-ALLOW-DB-1" {
			allow = &events[i]
		}
	}
	if allow == nil {
		t.Fatal("no SEG-ALLOW-DB-1 event")
	}
	if allow.Action != "ACCEPT" || allow.SrcIP != "172.31.50.20" || allow.DstIP != "172.31.60.10" ||
		allow.DstPort != 5432 || allow.Proto != "tcp" || allow.Time.IsZero() {
		t.Fatalf("unexpected event %+v", *allow)
	}
}

func TestParseFirewallLog_RecordWithoutPrefixIsError(t *testing.T) {
	bad := "===>PACKET BOUNDARY\nip.saddr.str=172.31.50.20\nip.daddr.str=172.31.60.10\nip.protocol=6\ntcp.dport=5432\noob.time.sec=1794377048\n"
	if _, err := ParseFirewallLog([]byte(bad)); err == nil {
		t.Fatal("want error for a record with no prefix")
	}
}

func TestParseFirewallLog_EmptyIsNoEvents(t *testing.T) {
	events, err := ParseFirewallLog([]byte(""))
	if err != nil || len(events) != 0 {
		t.Fatalf("got %d events, err %v; want 0, nil", len(events), err)
	}
}

func TestParseFirewallLog_CatchallHasNoRulePrefixSplitError(t *testing.T) {
	ok := "===>PACKET BOUNDARY\noob.prefix=SEG-CATCHALL|DROP\noob.time.sec=1794377048\nip.saddr.str=172.31.10.10\nip.daddr.str=172.31.60.10\nip.protocol=6\ntcp.dport=5432\n"
	events, err := ParseFirewallLog([]byte(ok))
	if err != nil || len(events) != 1 || events[0].RuleID != "SEG-CATCHALL" || events[0].Action != "DROP" {
		t.Fatalf("got %+v, err %v", events, err)
	}
}

// A non-TCP/UDP packet (ICMP) that reaches the catch-all is not part of any
// probe tuple; it must not make the whole log unreadable.
func TestParseFirewallLog_SkipsNonTransportRecords(t *testing.T) {
	icmp := "===>PACKET BOUNDARY\noob.prefix=SEG-CATCHALL|DROP\noob.time.sec=1794377048\nip.saddr.str=172.31.10.10\nip.daddr.str=172.31.60.10\nip.protocol=1\n"
	events, err := ParseFirewallLog([]byte(icmp))
	if err != nil || len(events) != 0 {
		t.Fatalf("got %d events, err %v; want the ICMP record skipped, no error", len(events), err)
	}
}
