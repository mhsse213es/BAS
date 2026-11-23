package analytics

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func seedSource(t *testing.T, pool *pgxpool.Pool, id string) int64 {
	t.Helper()
	mustExec(t, pool, `INSERT INTO source_instances (id, source_type, display_name, observation_mode) VALUES ($1,'misp',$1,'snapshot')`, id)
	var tv int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO source_trust_versions (source_instance_id, trust_state, changed_by, reason) VALUES ($1,'trusted','user:t','test') RETURNING id`, id).Scan(&tv); err != nil {
		t.Fatalf("seed trust: %v", err)
	}
	return tv
}

func seedSync(t *testing.T, pool *pgxpool.Pool, src, status string) string {
	t.Helper()
	completeness := "complete"
	if status == "failed" {
		completeness = "failed"
	}
	var id string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO source_syncs (source_instance_id, started_at, completed_at, status, completeness, authoritative)
		VALUES ($1, NOW(), NOW(), $2, $3, false) RETURNING id`, src, status, completeness).Scan(&id); err != nil {
		t.Fatalf("seed sync: %v", err)
	}
	return id
}

// seedObservation records one observation; when threatID is set it is linked to
// that threat (a resolved observation).
func seedObservation(t *testing.T, pool *pgxpool.Pool, src, syncID string, tv int64, name, threatID string) {
	t.Helper()
	var obs string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO source_observations (sync_id, source_instance_id, raw_name, record_hash, observed_at, raw, trust_version_id)
		VALUES ($1,$2,$3,'h-'||$3, NOW(), '{}'::jsonb, $4) RETURNING id`, syncID, src, name, tv).Scan(&obs); err != nil {
		t.Fatalf("seed observation: %v", err)
	}
	if threatID != "" {
		mustExec(t, pool, `INSERT INTO threat_sources (threat_id, observation_id, provider, observed_at, record_hash, linked_by)
			VALUES ($1,$2,'misp',NOW(),'h-'||$3,'resolver')`, threatID, obs, name)
	}
}

func TestSourceReliability_SeparatesSyncResolutionAndUsefulness(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedThreatWithActor(t, pool, "sr-t1", "Actor SR 1")
		seedThreatWithActor(t, pool, "sr-t2", "Actor SR 2")
		v := seedPublishedAt(t, pool, "sr-content", time.Hour)
		linkGeneratedFor(t, pool, v, "sr-t1") // t1 reached published content; t2 did not

		// Source A: 2 syncs (1 ok, 1 failed); 3 observations, 2 resolved (t1 and t2).
		tvA := seedSource(t, pool, "sr-a")
		okSync := seedSync(t, pool, "sr-a", "succeeded")
		seedSync(t, pool, "sr-a", "failed")
		seedObservation(t, pool, "sr-a", okSync, tvA, "a1", "sr-t1")
		seedObservation(t, pool, "sr-a", okSync, tvA, "a2", "sr-t2")
		seedObservation(t, pool, "sr-a", okSync, tvA, "a3", "") // unresolved

		// Source B: healthy syncs but nothing it found became content.
		tvB := seedSource(t, pool, "sr-b")
		bSync := seedSync(t, pool, "sr-b", "succeeded")
		seedObservation(t, pool, "sr-b", bSync, tvB, "b1", "sr-t2")

		// Source C: no activity at all.
		seedSource(t, pool, "sr-c")

		got, err := ingestionHealth(context.Background(), pool, time.Now().Add(-24*time.Hour))
		if err != nil {
			t.Fatalf("ingestionHealth: %v", err)
		}
		by := map[string]SourceReliability{}
		for _, s := range got.Sources {
			by[s.SourceInstanceID] = s.Reliability
		}

		a := by["sr-a"]
		if *a.SyncSuccessRate.Value != 0.5 {
			t.Fatalf("A sync success = %+v, want 0.5", a.SyncSuccessRate)
		}
		if a.Observations != 3 || a.ResolvedObservations != 2 || *a.ResolutionRate.Value != 2.0/3.0 {
			t.Fatalf("A resolution = %+v, want 2 of 3", a)
		}
		if a.ThreatsContributed != 2 || a.ThreatsWithPublishedContent != 1 || *a.UsefulnessRate.Value != 0.5 {
			t.Fatalf("A usefulness = %+v, want 1 of 2 threats with published content", a)
		}

		b := by["sr-b"]
		if *b.SyncSuccessRate.Value != 1 || *b.ResolutionRate.Value != 1 {
			t.Fatalf("B = %+v, want perfect sync and resolution", b)
		}
		if b.UsefulnessRate.State != DataMeasured || *b.UsefulnessRate.Value != 0 {
			t.Fatalf("B usefulness = %+v, want a measured 0 (reliable source, no content from it)", b.UsefulnessRate)
		}

		c := by["sr-c"]
		if c.SyncSuccessRate.State != DataNoData || c.ResolutionRate.State != DataNoData || c.UsefulnessRate.State != DataNoData {
			t.Fatalf("C = %+v, want all three NO_DATA (idle source is not 0%%)", c)
		}
	})
}
