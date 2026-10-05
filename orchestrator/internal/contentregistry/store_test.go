package contentregistry

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

const yamlV1 = "id: store-sc\nname: Store\nlocal_check: true\n"
const yamlV2 = "id: store-sc\nname: Store v2\nlocal_check: true\n"

func mustAnalyze(t *testing.T, b string) *analysis {
	t.Helper()
	a, err := analyzeArtifact([]byte(b))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func localDraft(t *testing.T, art string) newVersion {
	return newVersion{contentID: "store-sc", origin: OriginLocal, source: SourceCustom, artifact: []byte(art),
		trust: TrustUntrusted, lifecycle: LifecycleDraft, actor: ActorIntake, analysis: mustAnalyze(t, art)}
}

func TestCreateVersion_IdempotentByHashAndIncrementing(t *testing.T) { // A2/A3 store half
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		id1, created, err := r.createVersion(ctx, localDraft(t, yamlV1))
		if err != nil || !created {
			t.Fatalf("v1: created=%v err=%v", created, err)
		}
		again, created, err := r.createVersion(ctx, localDraft(t, yamlV1))
		if err != nil || created || again != id1 {
			t.Fatalf("same bytes must be a no-op: id=%s created=%v err=%v", again, created, err)
		}
		id2, created, err := r.createVersion(ctx, localDraft(t, yamlV2))
		if err != nil || !created || id2 == id1 {
			t.Fatalf("v2: %v %v", created, err)
		}
		vs, err := r.ListVersions(ctx, "store-sc")
		if err != nil || len(vs) != 2 || vs[0].Number != 2 || vs[1].Number != 1 {
			t.Fatalf("list: %+v err=%v", vs, err)
		}
		v1, err := r.LoadVersion(ctx, id1)
		if err != nil || string(v1.Artifact) != yamlV1 || v1.SHA256 != sha256Hex([]byte(yamlV1)) {
			t.Fatalf("v1 must stay byte-identical: %q err=%v", v1.Artifact, err)
		}
		var events, structural, safety int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM content_version_events WHERE content_version_id=$1`, id1).Scan(&events)
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM content_validations WHERE content_version_id=$1 AND level='STRUCTURAL'`, id1).Scan(&structural)
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM content_safety_verdicts WHERE content_version_id=$1`, id1).Scan(&safety)
		if events != 1 || structural != 1 || safety != 1 {
			t.Fatalf("creation side rows: events=%d structural=%d safety=%d", events, structural, safety)
		}
	})
}

func TestCreateVersion_OriginCollision(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		if _, _, err := r.createVersion(ctx, localDraft(t, yamlV1)); err != nil {
			t.Fatal(err)
		}
		nv := localDraft(t, yamlV2)
		nv.origin, nv.source, nv.lifecycle = OriginVendor, SourceBuiltin, LifecyclePublished
		if _, _, err := r.createVersion(ctx, nv); err != ErrOriginCollision {
			t.Fatalf("want ErrOriginCollision, got %v", err)
		}
	})
}

func TestVersionParse_RestoresSource(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		id, _, err := r.createVersion(ctx, localDraft(t, yamlV1))
		if err != nil {
			t.Fatal(err)
		}
		v, _ := r.LoadVersion(ctx, id)
		sc, err := v.Parse()
		if err != nil || sc.ID != "store-sc" || sc.Source != "custom" {
			t.Fatalf("parse: %+v err=%v", sc, err)
		}
		if _, err := r.LoadVersion(ctx, "00000000-0000-0000-0000-000000000000"); err != ErrVersionNotFound {
			t.Fatalf("missing version: %v", err)
		}
	})
}
