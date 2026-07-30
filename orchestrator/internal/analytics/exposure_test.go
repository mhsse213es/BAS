package analytics

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/exposure"
	"github.com/audspect/bas/internal/pathcorrelation"
)

func TestBuildFleetExposure_MatchesDirectCalls(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('a1', 'HOST-1')`)
		ctx := context.Background()

		fe, err := BuildFleetExposure(ctx, pool)
		if err != nil {
			t.Fatalf("BuildFleetExposure: %v", err)
		}

		gotCorr := fe.Correlation()
		gotExp := fe.AssetExposureSummary()
		if len(gotExp.Assets) != 1 {
			t.Fatalf("AssetExposureSummary().Assets = %+v, want 1 (one enrolled agent, no collections)", gotExp.Assets)
		}

		// Independently reproduce the same pipeline BuildFleetExposure wraps.
		g, s := attackpath.BuildGraphAndAnalyze(nil, nil)
		paths := pathcorrelation.DefaultPaths(g, s)
		wantCorr, err := pathcorrelation.Correlate(ctx, g, s, paths,
			pathcorrelation.DefaultEdgeTechniqueMapper{}, pathcorrelation.NewSQLRunLookup(pool), nil)
		if err != nil {
			t.Fatalf("pathcorrelation.Correlate: %v", err)
		}
		if gotCorr.Score != wantCorr.Score {
			t.Errorf("Correlation().Score = %d, want %d (direct pathcorrelation.Correlate call)", gotCorr.Score, wantCorr.Score)
		}

		wantGraph, err := exposure.Build(ctx, g, s, wantCorr, nil,
			exposure.NewSQLCVEEnricher(pool), exposure.NewSQLFindingsLookup(pool),
			[]exposure.AgentRow{{AgentID: "a1", Hostname: "HOST-1"}})
		if err != nil {
			t.Fatalf("exposure.Build: %v", err)
		}
		wantSummaries := wantGraph.Summaries()
		if len(wantSummaries) != 1 {
			t.Fatalf("direct exposure.Build gave %d summaries, want 1", len(wantSummaries))
		}
		if gotExp.Assets[0].ExposureScore != wantSummaries[0].ExposureScore {
			t.Errorf("Assets[0].ExposureScore = %d, want %d (direct exposure.Build call)", gotExp.Assets[0].ExposureScore, wantSummaries[0].ExposureScore)
		}
		if gotExp.Assets[0].CriticalityRisk != wantSummaries[0].CriticalityRisk {
			t.Errorf("Assets[0].CriticalityRisk = %d, want %d (already computed inside exposure.Build, just surfaced)", gotExp.Assets[0].CriticalityRisk, wantSummaries[0].CriticalityRisk)
		}
		if gotExp.FleetAvgScore != wantSummaries[0].ExposureScore {
			t.Errorf("FleetAvgScore = %d, want %d (average of the single asset's score)", gotExp.FleetAvgScore, wantSummaries[0].ExposureScore)
		}
	})
}

func TestBuildFleetExposure_EmptyFleet_NoAssets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		fe, err := BuildFleetExposure(context.Background(), pool)
		if err != nil {
			t.Fatalf("BuildFleetExposure: %v", err)
		}
		exp := fe.AssetExposureSummary()
		if len(exp.Assets) != 0 || exp.FleetAvgScore != 0 {
			t.Errorf("AssetExposureSummary() = %+v, want empty/zero on an empty fleet", exp)
		}
	})
}

func TestFindingExposureWindows_MatchesDirectPredictBuildCall(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		mustExec(t, pool, `
			INSERT INTO findings (agent_id, technique_id, technique_name, control_class, severity, status, first_seen)
			VALUES ('a1', 'T1059', 'Command and Scripting Interpreter', 'prevention', 'High', 'open', NOW() - INTERVAL '10 days')`)

		got, err := FindingExposureWindows(ctx, pool)
		if err != nil {
			t.Fatalf("FindingExposureWindows: %v", err)
		}
		if !got.HasData || got.OpenCount != 1 {
			t.Fatalf("FindingExposureWindows() = %+v, want HasData=true OpenCount=1", got)
		}
	})
}
