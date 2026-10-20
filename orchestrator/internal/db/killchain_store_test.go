package db_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/killchain"
)

func killChainDef(id string) killchain.CampaignDef {
	return killchain.CampaignDef{ID: id, Name: "Test chain", Version: 1, Stages: []killchain.StageDef{
		{Key: "initial", ScenarioID: "s-a", Policy: killchain.StagePolicy{ShouldBlock: true, Source: "baseline"}},
		{Key: "exec", ScenarioID: "s-b", Requires: []string{"initial"}},
	}}
}

func TestKillChainSchema_Idempotent(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		for i := 0; i < 2; i++ {
			if err := db.EnsureKillChainSchema(context.Background(), pool); err != nil {
				t.Fatalf("run %d: %v", i, err)
			}
		}
	})
}

func TestKillChainStore_CreateAndLoadRoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		s := db.KillChainStore{Pool: pool}
		def := killChainDef("kc-roundtrip")
		if err := s.CreateCampaign(ctx, def, "user-1"); err != nil {
			t.Fatal(err)
		}
		rec, err := s.Campaign(ctx, "kc-roundtrip")
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(rec.Def, def) {
			t.Fatalf("definition changed in storage:\n got %+v\nwant %+v", rec.Def, def)
		}
		for _, k := range []string{"initial", "exec"} {
			if rec.Stages[k].State != killchain.StatePending {
				t.Fatalf("%s state = %s, want pending", k, rec.Stages[k].State)
			}
		}
	})
}

func TestKillChainStore_StageEvidenceRoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		s := db.KillChainStore{Pool: pool}
		if err := s.CreateCampaign(ctx, killChainDef("kc-evidence"), ""); err != nil {
			t.Fatal(err)
		}
		ev := killchain.StageEvidence{
			CampaignID: "kc-evidence", StageKey: "initial", ExecutionID: "x-1",
			GroundTruth: killchain.GroundTruth{Source: "host", Attempted: killchain.TriYes, Executed: killchain.TriNo},
			Prevention:  killchain.PreventionEvidence{Value: killchain.PreventionBlocked},
			Detection:   killchain.DetectionEvidence{Value: killchain.DetectionDetected, TelemetryHealth: killchain.TelemetryHealthy, WindowComplete: killchain.TriYes},
			Response:    killchain.ResponseEvidence{Value: killchain.ResponseContainedVerified},
			Timestamps:  killchain.Timestamps{ActionAt: time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)},
		}
		want := killchain.StageRecord{Key: "initial", State: killchain.StateCompleted,
			Verdict: killchain.VerdictBlocked, Reasons: []string{"prevention verified"}, ExecutionID: "x-1", Evidence: &ev}
		if err := s.PutStage(ctx, "kc-evidence", want); err != nil {
			t.Fatal(err)
		}
		rec, err := s.Campaign(ctx, "kc-evidence")
		if err != nil {
			t.Fatal(err)
		}
		got := rec.Stages["initial"]
		if got.Verdict != killchain.VerdictBlocked || got.State != killchain.StateCompleted {
			t.Fatalf("stage = %s/%s", got.State, got.Verdict)
		}
		if got.Evidence == nil || !got.Evidence.Timestamps.ActionAt.Equal(ev.Timestamps.ActionAt) {
			t.Fatalf("evidence or timestamps did not round-trip: %+v", got.Evidence)
		}
	})
}

func TestKillChainStore_UnknownCampaignIsNotFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := db.KillChainStore{Pool: pool}.Campaign(context.Background(), "does-not-exist")
		if !errors.Is(err, db.ErrKillChainNotFound) {
			t.Fatalf("err = %v, want ErrKillChainNotFound", err)
		}
	})
}

func TestKillChainStore_DuplicateCampaignIsRefused(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		s := db.KillChainStore{Pool: pool}
		if err := s.CreateCampaign(ctx, killChainDef("kc-dup"), ""); err != nil {
			t.Fatal(err)
		}
		if err := s.CreateCampaign(ctx, killChainDef("kc-dup"), ""); err == nil {
			t.Fatalf("a second campaign with the same id must be refused")
		}
	})
}
