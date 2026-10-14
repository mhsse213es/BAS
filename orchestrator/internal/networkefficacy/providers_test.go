package networkefficacy

import (
	"testing"
	"time"
)

func TestSyntheticFirewallProvider_ReturnsMatchingEvidence(t *testing.T) {
	now := time.Now()
	p := NewSyntheticFirewallProvider([]FirewallEvidence{
		{SourceIP: "10.0.1.5", DestIP: "10.0.2.5", Port: 443, Protocol: "tcp", Action: "block", Timestamp: now, Source: SourceSynthetic},
	})
	flow := Flow{SourceCIDR: "10.0.1.0/24", DestCIDR: "10.0.2.0/24", Port: 443, Protocol: "tcp"}
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	got, err := p.FirewallEvidenceFor(flow, window)
	if err != nil {
		t.Fatalf("FirewallEvidenceFor: %v", err)
	}
	if len(got) != 1 || got[0].Action != "block" {
		t.Fatalf("got %+v, want one block event", got)
	}
}

func TestSyntheticFirewallProvider_NoMatchReturnsEmptyNotError(t *testing.T) {
	now := time.Now()
	p := NewSyntheticFirewallProvider([]FirewallEvidence{
		{SourceIP: "192.168.9.9", DestIP: "192.168.9.10", Port: 22, Action: "permit", Timestamp: now, Source: SourceSynthetic},
	})
	flow := Flow{SourceCIDR: "10.0.1.0/24", DestCIDR: "10.0.2.0/24", Port: 443}
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	got, err := p.FirewallEvidenceFor(flow, window)
	if err != nil {
		t.Fatalf("FirewallEvidenceFor: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %+v, want none", got)
	}
}

func TestSyntheticFirewallProvider_ProtocolMatchingIsCaseInsensitive(t *testing.T) {
	now := time.Now()
	p := NewSyntheticFirewallProvider([]FirewallEvidence{
		{SourceIP: "10.0.1.5", DestIP: "10.0.2.5", Port: 443, Protocol: "TCP", Action: "block", Timestamp: now, Source: SourceSynthetic},
	})
	flow := Flow{SourceCIDR: "10.0.1.0/24", DestCIDR: "10.0.2.0/24", Port: 443, Protocol: "tcp"}
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	got, err := p.FirewallEvidenceFor(flow, window)
	if err != nil {
		t.Fatalf("FirewallEvidenceFor: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %+v, want one match -- protocol matching must be case-insensitive (TCP vs tcp)", got)
	}
}

func TestSyntheticFirewallProvider_OutsideTimeWindowExcluded(t *testing.T) {
	now := time.Now()
	p := NewSyntheticFirewallProvider([]FirewallEvidence{
		{SourceIP: "10.0.1.5", DestIP: "10.0.2.5", Port: 443, Protocol: "tcp", Action: "block", Timestamp: now.Add(-time.Hour), Source: SourceSynthetic},
	})
	flow := Flow{SourceCIDR: "10.0.1.0/24", DestCIDR: "10.0.2.0/24", Port: 443, Protocol: "tcp"}
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	got, err := p.FirewallEvidenceFor(flow, window)
	if err != nil {
		t.Fatalf("FirewallEvidenceFor: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %+v, want none -- the event's timestamp is an hour outside the window", got)
	}
}

func TestSyntheticFirewallProvider_WrongPortExcluded(t *testing.T) {
	now := time.Now()
	p := NewSyntheticFirewallProvider([]FirewallEvidence{
		{SourceIP: "10.0.1.5", DestIP: "10.0.2.5", Port: 22, Protocol: "tcp", Action: "block", Timestamp: now, Source: SourceSynthetic},
	})
	flow := Flow{SourceCIDR: "10.0.1.0/24", DestCIDR: "10.0.2.0/24", Port: 443, Protocol: "tcp"}
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	got, err := p.FirewallEvidenceFor(flow, window)
	if err != nil {
		t.Fatalf("FirewallEvidenceFor: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %+v, want none -- port 22 does not match the flow's port 443", got)
	}
}
