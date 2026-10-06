package contentregistry

import (
	"context"
	"errors"
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
		v, err := r.LoadVersion(ctx, vid)
		if err != nil {
			t.Fatal(err)
		}
		if v.Lifecycle != LifecycleDraft || v.Trust != TrustUntrusted || v.Origin != OriginLocal {
			t.Fatalf("candidate state: %+v", v)
		}
		var techs []string
		var gk string
		if err := pool.QueryRow(ctx, `SELECT technique_ids FROM content_versions WHERE id=$1`, vid).Scan(&techs); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT generation_key FROM scenarios WHERE scenario_id='intel-abc'`).Scan(&gk); err != nil {
			t.Fatal(err)
		}
		if len(techs) != 2 || gk != "k1" {
			t.Fatalf("techniques=%v gk=%q", techs, gk)
		}
		rows, err := pool.Query(ctx, `SELECT provider, external_id, confidence_at_generation, first_seen_at_generation, role
			FROM content_version_sources WHERE content_version_id=$1 ORDER BY provider`, vid)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		got := 0
		for rows.Next() {
			var prov, ext, conf, role string
			var fs *time.Time
			if err := rows.Scan(&prov, &ext, &conf, &fs, &role); err != nil {
				t.Fatal(err)
			}
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
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		if got != 2 {
			t.Fatalf("source rows = %d, want 2 (primary + supporting)", got)
		}
		// Snapshot is point-in-time: later source changes do not rewrite it.
		if _, err := pool.Exec(ctx, `UPDATE threat_actor_sources SET confidence='low' WHERE source='misp'`); err != nil {
			t.Fatal(err)
		}
		var conf string
		if err := pool.QueryRow(ctx, `SELECT confidence_at_generation FROM content_version_sources WHERE content_version_id=$1 AND provider='misp'`, vid).Scan(&conf); err != nil {
			t.Fatal(err)
		}
		if conf != "high" {
			t.Fatalf("snapshot must not follow live source rows, got %s", conf)
		}
	})
}

func TestRegisterGenerated_RefusesCustomSourceCollision(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		custom := []byte("id: intel-col\nname: C\nlocal_check: true\n")
		a, err := analyzeArtifact(custom)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := r.createVersion(ctx, newVersion{contentID: "intel-col", origin: OriginLocal, source: SourceCustom,
			artifact: custom, trust: TrustUntrusted, lifecycle: LifecycleDraft, actor: ActorIntake, analysis: a,
			exclusiveLocalSource: true}); err != nil {
			t.Fatal(err)
		}
		_, _, err = r.RegisterGenerated(ctx, GeneratedCandidate{ContentID: "intel-col",
			Artifact:      []byte("id: intel-col\nname: I\nart_techniques: [T1082]\n"),
			GenerationKey: "k"})
		if !errors.Is(err, ErrSourceCollision) {
			t.Fatalf("want ErrSourceCollision, got %v", err)
		}
	})
}

// Final-review I3 (approve UI): the version detail tells an approver what the
// DRAFT will run before approval -- step and ART technique counts.
func TestVersionDetail_ReportsWhatWillRun(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		art := []byte("id: intel-cnt\nname: N\nart_techniques: [T1059.001, T1082, T1083]\nsteps:\n- name: s1\n  technique_id: T1082\n  command: whoami\n")
		vid, _, err := r.RegisterGenerated(ctx, GeneratedCandidate{ContentID: "intel-cnt", Artifact: art})
		if err != nil {
			t.Fatal(err)
		}
		d, err := r.VersionDetail(ctx, vid)
		if err != nil {
			t.Fatal(err)
		}
		if d.StepCount == nil || *d.StepCount != 1 || len(d.ARTTechniques) != 3 || d.ARTTechniques[0] != "T1059.001" {
			t.Fatalf("detail: steps=%v art=%v", d.StepCount, d.ARTTechniques)
		}
	})
}
