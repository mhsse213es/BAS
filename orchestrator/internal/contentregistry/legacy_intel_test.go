package contentregistry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
	"github.com/audspect/bas/internal/threatidentity"
)

// phase1ID is Phase 1's name-derived intel id, computed independently of
// the implementation under test.
func phase1ID(name string) string {
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(name))))
	return "intel-" + hex.EncodeToString(h[:])[:12]
}

func TestLegacyIntelContent_ClassifiesWithoutTouching(t *testing.T) { // acceptance 13
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		thr := seedThreat(t, pool, "Akira")
		// Phase-1-style content: registered without an owner (createVersion
		// directly, since RegisterGenerated now requires a threat).
		old := phase1ID("Akira")
		art := []byte("id: " + old + "\nname: Akira\nart_techniques: [T1059.001, T1082]\n")
		a, err := analyzeArtifact(art)
		if err != nil {
			t.Fatal(err)
		}
		vid, _, err := r.createVersion(ctx, newVersion{contentID: old, origin: OriginLocal, source: SourceIntel,
			artifact: art, trust: TrustUntrusted, lifecycle: LifecycleDraft, actor: ActorGenerator, analysis: a})
		if err != nil {
			t.Fatal(err)
		}
		// Owned (threat-derived) content is not legacy.
		if _, _, err := r.RegisterGenerated(ctx, GeneratedCandidate{ContentID: threatidentity.ContentID(thr),
			Artifact: []byte("id: " + threatidentity.ContentID(thr) + "\nname: Akira\nart_techniques: [T1059.001, T1082]\n"),
			ThreatID: thr}); err != nil {
			t.Fatal(err)
		}
		items, err := r.LegacyIntelContent(ctx)
		if err != nil || len(items) != 1 {
			t.Fatalf("items=%+v err=%v", items, err)
		}
		it := items[0]
		if it.ContentID != old || it.Action != "superseded" || it.SupersededBy != threatidentity.ContentID(thr) || it.HasHistory {
			t.Fatalf("%+v", it)
		}
		// Approved history flips it to admin_decision_required.
		if err := r.Transition(ctx, vid, LifecyclePublishedLocal, "user:1", "ok"); err != nil {
			t.Fatal(err)
		}
		items, _ = r.LegacyIntelContent(ctx)
		if len(items) != 1 || items[0].Action != "admin_decision_required" || !items[0].HasHistory {
			t.Fatalf("%+v", items)
		}
		var lc string
		_ = pool.QueryRow(ctx, `SELECT lifecycle FROM content_versions WHERE id = $1`, vid).Scan(&lc)
		if lc != string(LifecyclePublishedLocal) {
			t.Fatalf("inventory changed lifecycle to %s", lc)
		}
	})
}

func TestLegacyIntelContent_UnmappedIsUnresolved(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		old := phase1ID("Nobody Known")
		art := []byte("id: " + old + "\nname: X\nart_techniques: [T1059.001, T1082]\n")
		a, err := analyzeArtifact(art)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := r.createVersion(ctx, newVersion{contentID: old, origin: OriginLocal, source: SourceIntel,
			artifact: art, trust: TrustUntrusted, lifecycle: LifecycleDraft, actor: ActorGenerator, analysis: a}); err != nil {
			t.Fatal(err)
		}
		items, err := r.LegacyIntelContent(ctx)
		if err != nil || len(items) != 1 || items[0].Action != "unresolved" || items[0].SupersededBy != "" {
			t.Fatalf("items=%+v err=%v", items, err)
		}
	})
}
