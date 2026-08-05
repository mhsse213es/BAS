package db_test

import (
	"context"
	"fmt"
	"testing"
	"time"

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

func TestGetRunIOCsEnriched_NoProviderConfigured(t *testing.T) {
	ctx := context.Background()
	const runID = "test-run-ioc-enriched-noprovider"
	t.Cleanup(func() {
		_, _ = sharedDB.Pool.Exec(ctx, `DELETE FROM run_iocs WHERE run_id = $1`, runID)
	})

	indicators := []ioc.RunIndicator{{Type: "ip", Value: "203.0.113.9", Confidence: 90, Source: "stdout"}}
	if err := db.UpsertRunIOCs(ctx, sharedDB.Pool, runID, "test-scenario", indicators); err != nil {
		t.Fatalf("UpsertRunIOCs: %v", err)
	}

	got, err := db.GetRunIOCsEnriched(ctx, sharedDB.Pool, runID, "", "", "")
	if err != nil {
		t.Fatalf("GetRunIOCsEnriched: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d indicators, want 1", len(got))
	}
	if got[0].Tier != "" {
		t.Errorf("tier = %q, want empty -- no provider configured means no enrichment attempted", got[0].Tier)
	}
}

func TestGetRunIOCsEnriched_ClassifiesTierFromPulseCount(t *testing.T) {
	ctx := context.Background()
	const runID = "test-run-ioc-enriched-tiers"
	const provider = "otx"
	t.Cleanup(func() {
		_, _ = sharedDB.Pool.Exec(ctx, `DELETE FROM run_iocs WHERE run_id = $1`, runID)
		_, _ = sharedDB.Pool.Exec(ctx, `DELETE FROM ioc_enrichment WHERE indicator_value IN ('198.51.100.1','198.51.100.2','198.51.100.3')`)
	})

	indicators := []ioc.RunIndicator{
		{Type: "ip", Value: "198.51.100.1", Confidence: 90, Source: "stdout"}, // malicious-associated (>=3 pulses)
		{Type: "ip", Value: "198.51.100.2", Confidence: 90, Source: "stdout"}, // suspicious (1-2 pulses)
		{Type: "ip", Value: "198.51.100.3", Confidence: 90, Source: "stdout"}, // pending (never successfully looked up)
	}
	if err := db.UpsertRunIOCs(ctx, sharedDB.Pool, runID, "test-scenario", indicators); err != nil {
		t.Fatalf("UpsertRunIOCs: %v", err)
	}

	future := time.Now().Add(24 * time.Hour)
	if err := db.UpsertIOCEnrichmentSuccess(ctx, sharedDB.Pool, "ip", "198.51.100.1", provider,
		&ioc.Result{PulseCount: 5}, 10, future); err != nil {
		t.Fatalf("seed malicious enrichment: %v", err)
	}
	if err := db.UpsertIOCEnrichmentSuccess(ctx, sharedDB.Pool, "ip", "198.51.100.2", provider,
		&ioc.Result{PulseCount: 1}, 10, future); err != nil {
		t.Fatalf("seed suspicious enrichment: %v", err)
	}
	if err := db.UpsertIOCEnrichmentFailure(ctx, sharedDB.Pool, "ip", "198.51.100.3", provider,
		fmt.Errorf("lookup timeout"), future); err != nil {
		t.Fatalf("seed pending (failed) enrichment: %v", err)
	}

	got, err := db.GetRunIOCsEnriched(ctx, sharedDB.Pool, runID, provider, "", "")
	if err != nil {
		t.Fatalf("GetRunIOCsEnriched: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d indicators, want 3", len(got))
	}

	tiers := map[string]string{}
	for _, ind := range got {
		tiers[ind.Value] = ind.Tier
	}
	if tiers["198.51.100.1"] != "malicious-associated" {
		t.Errorf("198.51.100.1 tier = %q, want malicious-associated", tiers["198.51.100.1"])
	}
	if tiers["198.51.100.2"] != "suspicious" {
		t.Errorf("198.51.100.2 tier = %q, want suspicious", tiers["198.51.100.2"])
	}
	if tiers["198.51.100.3"] != "pending" {
		t.Errorf("198.51.100.3 tier = %q, want pending", tiers["198.51.100.3"])
	}
}
