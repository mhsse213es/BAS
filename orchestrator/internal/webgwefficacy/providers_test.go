package webgwefficacy

import (
	"testing"
	"time"
)

func TestFixtureGatewayProvider_ReturnsMatchingEvidence(t *testing.T) {
	now := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: "https://malware.example/payload", User: "alice", Action: "block", Timestamp: now, Source: SourceFixture},
	})
	got, err := provider.GatewayEvidenceFor(HTTPRequestRef{URL: "https://malware.example/payload", User: "alice"}, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("GatewayEvidenceFor: %v", err)
	}
	if len(got) != 1 || got[0].Action != "block" {
		t.Fatalf("got %+v, want one block record", got)
	}
}

func TestFixtureGatewayProvider_NoMatchReturnsEmptyNotError(t *testing.T) {
	now := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: "https://malware.example/payload", Action: "block", Timestamp: now, Source: SourceFixture},
	})
	got, err := provider.GatewayEvidenceFor(HTTPRequestRef{URL: "https://other.example/page"}, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("GatewayEvidenceFor: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %+v, want empty for a non-matching URL", got)
	}
}

func TestFixtureGatewayProvider_UserMatchingIsCaseInsensitive(t *testing.T) {
	now := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: "https://malware.example/payload", User: "Alice", Action: "block", Timestamp: now, Source: SourceFixture},
	})
	got, err := provider.GatewayEvidenceFor(HTTPRequestRef{URL: "https://malware.example/payload", User: "alice"}, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("GatewayEvidenceFor: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %+v, want a case-insensitive user match", got)
	}
}

func TestFixtureGatewayProvider_EmptyReqUserMatchesAny(t *testing.T) {
	now := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: "https://malware.example/payload", User: "alice", Action: "block", Timestamp: now, Source: SourceFixture},
	})
	got, err := provider.GatewayEvidenceFor(HTTPRequestRef{URL: "https://malware.example/payload"}, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("GatewayEvidenceFor: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %+v, want an unconstrained-user request to match any user", got)
	}
}

func TestFixtureGatewayProvider_OutsideTimeWindowExcluded(t *testing.T) {
	now := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: "https://malware.example/payload", Action: "block", Timestamp: now, Source: SourceFixture},
	})
	got, err := provider.GatewayEvidenceFor(HTTPRequestRef{URL: "https://malware.example/payload"}, TimeWindow{Start: now.Add(time.Hour), End: now.Add(2 * time.Hour)})
	if err != nil {
		t.Fatalf("GatewayEvidenceFor: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %+v, want empty -- the record's timestamp falls outside the requested window", got)
	}
}

func TestInWindow_InvertedWindowContainsNothing(t *testing.T) {
	now := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	inverted := TimeWindow{Start: now.Add(time.Hour), End: now.Add(-time.Hour)}
	if inWindow(now, inverted) {
		t.Fatalf("inWindow(%v, %+v) = true, want false -- Start is after End", now, inverted)
	}
}
