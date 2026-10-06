package contentregistry

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

func TestRegisterGenerated_TraceableCandidate(t *testing.T) { // A1
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		seen := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
		if _, err := pool.Exec(ctx, `INSERT INTO threat_actor_profiles (name) VALUES ('RansomHub')`); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO threat_actor_sources (actor_name, source, source_id, name, confidence, last_seen)
			VALUES ('RansomHub','misp','evt-1','RansomHub','high',$1), ('RansomHub','opencti','oc-9','RansomHub','medium',$1)`, seen); err != nil {
			t.Fatal(err)
		}
		r := New(pool, testutil.DevVerifier())
		art := []byte("id: intel-abc\nname: RansomHub — Active Campaign (Intel)\nart_techniques: [T1059.001, T1082]\n")
		vid, created, err := r.RegisterGenerated(ctx, GeneratedCandidate{ContentID: "intel-abc", Artifact: art,
			GenerationKey: "k1", Generation: map[string]any{"generator": "connector/generator"},
			Sources: []SourceRef{{EntityType: "actor", EntityID: "RansomHub", Provider: "misp", ExternalID: "evt-1", Role: "primary"}}})
		if err != nil || !created {
			t.Fatalf("register: %v", err)
		}
		v, _ := r.LoadVersion(ctx, vid)
		if v.Lifecycle != LifecycleDraft || v.Trust != TrustUntrusted || v.Origin != OriginLocal {
			t.Fatalf("candidate state: %+v", v)
		}
		var techs []string
		var gk string
		_ = pool.QueryRow(ctx, `SELECT technique_ids FROM content_versions WHERE id=$1`, vid).Scan(&techs)
		_ = pool.QueryRow(ctx, `SELECT generation_key FROM scenarios WHERE scenario_id='intel-abc'`).Scan(&gk)
		if len(techs) != 2 || gk != "k1" {
			t.Fatalf("techniques=%v gk=%q", techs, gk)
		}
		rows, _ := pool.Query(ctx, `SELECT provider, external_id, confidence_at_generation, first_seen_at_generation, role
			FROM content_version_sources WHERE content_version_id=$1 ORDER BY provider`, vid)
		defer rows.Close()
		got := 0
		for rows.Next() {
			var prov, ext, conf, role string
			var fs *time.Time
			_ = rows.Scan(&prov, &ext, &conf, &fs, &role)
			got++
			if fs == nil || !fs.Equal(seen) {
				t.Errorf("%s first_seen snapshot = %v", prov, fs)
			}
			if prov == "misp" && (ext != "evt-1" || conf != "high" || role != "primary") {
				t.Errorf("misp row: %s %s %s", ext, conf, role)
			}
			if prov == "opencti" && role != "supporting" {
				t.Errorf("opencti must be supporting, got %s", role)
			}
		}
		if got != 2 {
			t.Fatalf("source rows = %d, want 2 (primary + supporting)", got)
		}
		// Snapshot is point-in-time: later source changes do not rewrite it.
		_, _ = pool.Exec(ctx, `UPDATE threat_actor_sources SET confidence='low' WHERE source='misp'`)
		var conf string
		_ = pool.QueryRow(ctx, `SELECT confidence_at_generation FROM content_version_sources WHERE content_version_id=$1 AND provider='misp'`, vid).Scan(&conf)
		if conf != "high" {
			t.Fatalf("snapshot must not follow live source rows, got %s", conf)
		}
	})
}
