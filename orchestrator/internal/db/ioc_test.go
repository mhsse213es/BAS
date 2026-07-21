package db_test

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/ioc"
)

func TestUpsertAndGetRunIOCs_RoundTrip(t *testing.T) {
	ctx := context.Background()
	const runID = "test-run-ioc-roundtrip"
	t.Cleanup(func() {
		_, _ = sharedDB.Pool.Exec(ctx, `DELETE FROM run_iocs WHERE run_id = $1`, runID)
	})

	indicators := []ioc.RunIndicator{
		{
			Type: "ip", Value: "45.33.32.156", Confidence: 95, Source: "stdout",
			OffsetStart: 10, OffsetEnd: 22,
			TechniqueIDs: []string{"T1071"}, SimulationIDs: []string{"T1071::A"},
		},
		{
			Type: "hash", Value: "44d88612fea8a8f36de82e1278abb02f", Algorithm: "md5",
			Confidence: 100, Source: "details", OffsetStart: 0, OffsetEnd: 32,
			TechniqueIDs: []string{"T1105"}, SimulationIDs: []string{"T1105::B"},
		},
	}

	if err := db.UpsertRunIOCs(ctx, sharedDB.Pool, runID, "test-scenario", indicators); err != nil {
		t.Fatalf("UpsertRunIOCs: %v", err)
	}

	got, err := db.GetRunIOCs(ctx, sharedDB.Pool, runID, "", "")
	if err != nil {
		t.Fatalf("GetRunIOCs: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d indicators, want 2: %+v", len(got), got)
	}

	var ip *ioc.RunIndicator
	for i := range got {
		if got[i].Type == "ip" {
			ip = &got[i]
		}
	}
	if ip == nil {
		t.Fatal("no ip indicator returned")
	}
	if ip.Value != "45.33.32.156" || len(ip.TechniqueIDs) != 1 || ip.TechniqueIDs[0] != "T1071" {
		t.Errorf("got %+v", ip)
	}
	if ip.ExtractedAt == nil {
		t.Error("ExtractedAt was not populated on read")
	}
}

func TestUpsertRunIOCs_ResubmissionReplaces(t *testing.T) {
	ctx := context.Background()
	const runID = "test-run-ioc-resubmit"
	t.Cleanup(func() {
		_, _ = sharedDB.Pool.Exec(ctx, `DELETE FROM run_iocs WHERE run_id = $1`, runID)
	})

	first := []ioc.RunIndicator{{Type: "cve", Value: "CVE-2024-0001", Confidence: 100, Source: "details"}}
	if err := db.UpsertRunIOCs(ctx, sharedDB.Pool, runID, "test-scenario", first); err != nil {
		t.Fatalf("first UpsertRunIOCs: %v", err)
	}

	second := []ioc.RunIndicator{{Type: "cve", Value: "CVE-2024-9999", Confidence: 100, Source: "details"}}
	if err := db.UpsertRunIOCs(ctx, sharedDB.Pool, runID, "test-scenario", second); err != nil {
		t.Fatalf("second UpsertRunIOCs: %v", err)
	}

	got, err := db.GetRunIOCs(ctx, sharedDB.Pool, runID, "", "")
	if err != nil {
		t.Fatalf("GetRunIOCs: %v", err)
	}
	if len(got) != 1 || got[0].Value != "CVE-2024-9999" {
		t.Fatalf("got %+v, want only the second submission's row (replace, not append)", got)
	}
}

func TestGetRunIOCs_TypeAndSearchFilters(t *testing.T) {
	ctx := context.Background()
	const runID = "test-run-ioc-filters"
	t.Cleanup(func() {
		_, _ = sharedDB.Pool.Exec(ctx, `DELETE FROM run_iocs WHERE run_id = $1`, runID)
	})

	indicators := []ioc.RunIndicator{
		{Type: "ip", Value: "45.33.32.156", Confidence: 95, Source: "stdout"},
		{Type: "domain", Value: "evil.example.com", Confidence: 80, Source: "stdout"},
	}
	if err := db.UpsertRunIOCs(ctx, sharedDB.Pool, runID, "test-scenario", indicators); err != nil {
		t.Fatalf("UpsertRunIOCs: %v", err)
	}

	byType, err := db.GetRunIOCs(ctx, sharedDB.Pool, runID, "domain", "")
	if err != nil {
		t.Fatalf("GetRunIOCs type filter: %v", err)
	}
	if len(byType) != 1 || byType[0].Type != "domain" {
		t.Fatalf("got %+v, want only the domain indicator", byType)
	}

	bySearch, err := db.GetRunIOCs(ctx, sharedDB.Pool, runID, "", "45.33")
	if err != nil {
		t.Fatalf("GetRunIOCs search filter: %v", err)
	}
	if len(bySearch) != 1 || bySearch[0].Value != "45.33.32.156" {
		t.Fatalf("got %+v, want only the matching ip", bySearch)
	}
}
