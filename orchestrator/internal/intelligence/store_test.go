package intelligence

import (
	"context"
	"flag"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func TestUpsertCampaign_NameAndDescriptionOverwriteOnConflict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		c := Campaign{
			ID: "evt-1", Name: "Original Name", Description: "first",
			ThreatActorIDs: []string{"APT-TEST"}, TechniqueIDs: []string{"T1059"},
			Source: SourceRef{Provider: "misp", ExternalID: "evt-1", LastUpdated: time.Now(), Confidence: "medium"},
		}
		if err := UpsertCampaign(ctx, pool, c); err != nil {
			t.Fatalf("first UpsertCampaign: %v", err)
		}

		c.Name = "Updated Name"
		c.TechniqueIDs = []string{"T1059", "T1105"}
		if err := UpsertCampaign(ctx, pool, c); err != nil {
			t.Fatalf("second UpsertCampaign: %v", err)
		}

		got, err := ListCampaigns(ctx, pool)
		if err != nil {
			t.Fatalf("ListCampaigns: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d campaigns, want 1 (overwrite, not duplicate)", len(got))
		}
		if got[0].Name != "Updated Name" {
			t.Fatalf("Name = %q, want %q (overwrite must win)", got[0].Name, "Updated Name")
		}
		if len(got[0].TechniqueIDs) != 2 {
			t.Fatalf("TechniqueIDs = %v, want 2 entries", got[0].TechniqueIDs)
		}
	})
}

func TestUpsertCampaign_MergesActorAndTechniqueIDsOnConflict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		first := Campaign{
			ID: "evt-multi-actor", Name: "Multi-Actor Campaign", ThreatActorIDs: []string{"APT29"},
			TechniqueIDs: []string{"T1059"},
			Source:       SourceRef{Provider: "opencti", ExternalID: "campaign--1", LastUpdated: time.Now(), Confidence: "high"},
		}
		if err := UpsertCampaign(ctx, pool, first); err != nil {
			t.Fatalf("first UpsertCampaign: %v", err)
		}

		second := Campaign{
			ID: "evt-multi-actor", Name: "Multi-Actor Campaign", ThreatActorIDs: []string{"Cozy Bear"},
			TechniqueIDs: []string{"T1105"},
			Source:       SourceRef{Provider: "opencti", ExternalID: "campaign--1", LastUpdated: time.Now(), Confidence: "high"},
		}
		if err := UpsertCampaign(ctx, pool, second); err != nil {
			t.Fatalf("second UpsertCampaign: %v", err)
		}

		campaigns, err := ListCampaigns(ctx, pool)
		if err != nil {
			t.Fatalf("ListCampaigns: %v", err)
		}
		var got *Campaign
		for i := range campaigns {
			if campaigns[i].ID == "evt-multi-actor" {
				got = &campaigns[i]
				break
			}
		}
		if got == nil {
			t.Fatal("campaign evt-multi-actor not found after two upserts")
		}
		sort.Strings(got.ThreatActorIDs)
		if len(got.ThreatActorIDs) != 2 || got.ThreatActorIDs[0] != "APT29" || got.ThreatActorIDs[1] != "Cozy Bear" {
			t.Fatalf("ThreatActorIDs = %v, want union [APT29 Cozy Bear], not overwritten to just the second upsert's value", got.ThreatActorIDs)
		}
		sort.Strings(got.TechniqueIDs)
		if len(got.TechniqueIDs) != 2 || got.TechniqueIDs[0] != "T1059" || got.TechniqueIDs[1] != "T1105" {
			t.Fatalf("TechniqueIDs = %v, want union [T1059 T1105], not overwritten", got.TechniqueIDs)
		}
	})
}

func TestUpsertMalware_MergesArraysOnConflict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		first := Malware{
			ID: "emotet", Name: "Emotet", // Aliases deliberately left nil -- exercises UpsertMalware's nonNil coalescing
			TechniqueIDs: []string{"T1059"}, ThreatActorIDs: []string{"APT-A"}, CampaignIDs: []string{"evt-1"},
			Source: SourceRef{Provider: "misp", ExternalID: "evt-1", LastUpdated: time.Now(), Confidence: "medium"},
		}
		if err := UpsertMalware(ctx, pool, first); err != nil {
			t.Fatalf("first UpsertMalware: %v", err)
		}

		second := Malware{
			ID: "emotet", Name: "Emotet",
			TechniqueIDs: []string{"T1059", "T1105"}, ThreatActorIDs: []string{"APT-B"}, CampaignIDs: []string{"evt-2"},
			Source: SourceRef{Provider: "misp", ExternalID: "evt-2", LastUpdated: time.Now(), Confidence: "high"},
		}
		if err := UpsertMalware(ctx, pool, second); err != nil {
			t.Fatalf("second UpsertMalware: %v", err)
		}

		got, err := ListMalware(ctx, pool)
		if err != nil {
			t.Fatalf("ListMalware: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d malware rows, want 1 (merged, not duplicated)", len(got))
		}
		m := got[0]
		sort.Strings(m.TechniqueIDs)
		if len(m.TechniqueIDs) != 2 || m.TechniqueIDs[0] != "T1059" || m.TechniqueIDs[1] != "T1105" {
			t.Errorf("TechniqueIDs = %v, want deduplicated union [T1059 T1105]", m.TechniqueIDs)
		}
		sort.Strings(m.ThreatActorIDs)
		if len(m.ThreatActorIDs) != 2 || m.ThreatActorIDs[0] != "APT-A" || m.ThreatActorIDs[1] != "APT-B" {
			t.Errorf("ThreatActorIDs = %v, want union [APT-A APT-B]", m.ThreatActorIDs)
		}
		sort.Strings(m.CampaignIDs)
		if len(m.CampaignIDs) != 2 || m.CampaignIDs[0] != "evt-1" || m.CampaignIDs[1] != "evt-2" {
			t.Errorf("CampaignIDs = %v, want union [evt-1 evt-2]", m.CampaignIDs)
		}
		if m.Source.Confidence != "high" {
			t.Errorf("Source.Confidence = %q, want %q (most recent upsert wins)", m.Source.Confidence, "high")
		}
	})
}

func TestListCampaigns_Empty_ReturnsEmptyNotNil(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		got, err := ListCampaigns(context.Background(), pool)
		if err != nil {
			t.Fatalf("ListCampaigns: %v", err)
		}
		if got == nil {
			t.Fatal("expected an empty slice, not nil -- callers/JSON encoders shouldn't need a nil guard")
		}
	})
}

func TestUpsertTool_MergesArraysOnConflict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		first := Tool{
			ID: "psexec", Name: "PsExec", // Aliases deliberately left nil -- exercises UpsertTool's nonNil coalescing
			TechniqueIDs: []string{"T1569.002"}, ThreatActorIDs: []string{"BlackTech"}, CampaignIDs: []string{"evt-1"},
			Source: SourceRef{Provider: "opencti", ExternalID: "tool--1", LastUpdated: time.Now(), Confidence: "high"},
		}
		if err := UpsertTool(ctx, pool, first); err != nil {
			t.Fatalf("first UpsertTool: %v", err)
		}

		second := Tool{
			ID: "psexec", Name: "PsExec",
			TechniqueIDs: []string{"T1569.002", "T1136.002"}, ThreatActorIDs: []string{"FIN8"}, CampaignIDs: []string{"evt-2"},
			Source: SourceRef{Provider: "opencti", ExternalID: "tool--1", LastUpdated: time.Now(), Confidence: "high"},
		}
		if err := UpsertTool(ctx, pool, second); err != nil {
			t.Fatalf("second UpsertTool: %v", err)
		}

		got, err := ListTools(ctx, pool)
		if err != nil {
			t.Fatalf("ListTools: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d tool rows, want 1 (merged, not duplicated)", len(got))
		}
		tl := got[0]
		sort.Strings(tl.TechniqueIDs)
		if len(tl.TechniqueIDs) != 2 || tl.TechniqueIDs[0] != "T1136.002" || tl.TechniqueIDs[1] != "T1569.002" {
			t.Errorf("TechniqueIDs = %v, want deduplicated union [T1136.002 T1569.002]", tl.TechniqueIDs)
		}
		sort.Strings(tl.ThreatActorIDs)
		if len(tl.ThreatActorIDs) != 2 || tl.ThreatActorIDs[0] != "BlackTech" || tl.ThreatActorIDs[1] != "FIN8" {
			t.Errorf("ThreatActorIDs = %v, want union [BlackTech FIN8]", tl.ThreatActorIDs)
		}
		sort.Strings(tl.CampaignIDs)
		if len(tl.CampaignIDs) != 2 || tl.CampaignIDs[0] != "evt-1" || tl.CampaignIDs[1] != "evt-2" {
			t.Errorf("CampaignIDs = %v, want union [evt-1 evt-2]", tl.CampaignIDs)
		}
	})
}

func TestListTools_Empty_ReturnsEmptyNotNil(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		got, err := ListTools(context.Background(), pool)
		if err != nil {
			t.Fatalf("ListTools: %v", err)
		}
		if got == nil {
			t.Fatal("expected an empty slice, not nil -- callers/JSON encoders shouldn't need a nil guard")
		}
	})
}
