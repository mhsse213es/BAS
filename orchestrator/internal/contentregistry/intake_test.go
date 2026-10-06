package contentregistry

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/testutil"
)

func latest(t *testing.T, r *Registry, id string) Version {
	t.Helper()
	vs, err := r.ListVersions(context.Background(), id)
	if err != nil || len(vs) == 0 {
		t.Fatalf("no versions for %s: %v", id, err)
	}
	return vs[0]
}

func mustIntake(t *testing.T, r *Registry, ctx context.Context, f scenario.IntakeFile) scenario.IntakeDecision {
	t.Helper()
	d, err := r.Intake(ctx, f)
	if err != nil {
		t.Fatalf("intake %s: %v", f.Path, err)
	}
	return d
}

func file(src, body string) scenario.IntakeFile {
	return scenario.IntakeFile{Path: src + "/" + "x.yaml", Source: src, Artifact: []byte(body)}
}

func TestIntake_Matrix(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		signer := testutil.NewTestSigner(t)
		r := New(pool, signer.Verifier())

		vb := "id: vb\nname: VB\nlocal_check: true\n"
		f := file("builtin", vb)
		f.Signature, f.SignatureVerified = signer.Sign([]byte(vb)), true
		if d, err := r.Intake(ctx, f); err != nil || !d.Accepted {
			t.Fatalf("verified builtin: %+v %v", d, err)
		}
		if v := latest(t, r, "vb"); v.Origin != OriginVendor || v.Trust != TrustVendorSigned || v.Lifecycle != LifecyclePublished {
			t.Fatalf("verified builtin row: %+v", v)
		}

		ub := file("builtin", "id: ub\nname: UB\nlocal_check: true\n") // signing enabled, not verified
		if d := mustIntake(t, r, ctx, ub); d.Accepted {
			t.Fatal("unverified builtin must be refused when signing is enabled")
		}

		if d := mustIntake(t, r, ctx, file("intel", "id: in1\nname: In\nart_techniques: [T1082]\n")); !d.Accepted {
			t.Fatal("intel intake")
		}
		if v := latest(t, r, "in1"); v.Origin != OriginLocal || v.Trust != TrustUntrusted || v.Lifecycle != LifecycleDraft {
			t.Fatalf("intel row: %+v", v)
		}

		// Pre-migration custom file: grandfathered.
		if d := mustIntake(t, r, ctx, file("custom", "id: cu1\nname: Cu\nlocal_check: true\n")); !d.Accepted {
			t.Fatal("custom intake")
		}
		v := latest(t, r, "cu1")
		if v.Trust != TrustLocalTrusted || v.Lifecycle != LifecyclePublishedLocal || v.CreatedBy != ActorMigration {
			t.Fatalf("grandfathered custom row: %+v", v)
		}
	})
}

func TestIntake_DevBuildBuiltinStaysUntrusted(t *testing.T) { // A6 (intake half)
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		r := New(pool, testutil.DevVerifier())
		if d := mustIntake(t, r, context.Background(), file("builtin", "id: dv\nname: D\nlocal_check: true\n")); !d.Accepted {
			t.Fatal("dev builtin intake")
		}
		if v := latest(t, r, "dv"); v.Trust != TrustUntrusted || v.Lifecycle != LifecyclePublished {
			t.Fatalf("dev builtin must be UNTRUSTED/PUBLISHED: %+v", v)
		}
	})
}

func TestIntake_CustomAfterMigrationIsDraft(t *testing.T) { // plan amendment 2
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		if _, err := pool.Exec(ctx, `INSERT INTO content_registry_state (id) VALUES (1)`); err != nil {
			t.Fatal(err)
		}
		mustIntake(t, r, ctx, file("custom", "id: cu2\nname: Cu\nlocal_check: true\n"))
		if v := latest(t, r, "cu2"); v.Lifecycle != LifecycleDraft || v.Trust != TrustUntrusted {
			t.Fatalf("post-migration out-of-band custom file must be DRAFT: %+v", v)
		}
	})
}

func TestIntake_LocalOutOfBandEditBecomesDraft(t *testing.T) { // A11
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		if _, err := pool.Exec(ctx, `INSERT INTO content_registry_state (id) VALUES (1)`); err != nil {
			t.Fatal(err)
		}
		v1 := []byte("id: ob\nname: OB\nlocal_check: true\n")
		if err := r.RegisterLocalApproved(ctx, "ob", v1, "user:op"); err != nil {
			t.Fatal(err)
		}
		if d := mustIntake(t, r, ctx, file("custom", string(v1))); !d.Accepted {
			t.Fatal("same bytes on disk must be a no-op accept")
		}
		mustIntake(t, r, ctx, file("custom", "id: ob\nname: OB edited\nlocal_check: true\n"))
		vs, err := r.ListVersions(ctx, "ob")
		if err != nil {
			t.Fatal(err)
		}
		if len(vs) != 2 || vs[0].Lifecycle != LifecycleDraft || vs[0].Trust != TrustUntrusted ||
			vs[1].Lifecycle != LifecyclePublishedLocal {
			t.Fatalf("versions: %+v", vs)
		}
	})
}

func TestIntake_CrossOriginCollisionRefused(t *testing.T) { // A12 (registry half)
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		mustIntake(t, r, ctx, file("builtin", "id: col\nname: B\nlocal_check: true\n"))
		d, err := r.Intake(ctx, file("custom", "id: col\nname: C\nlocal_check: true\n"))
		if err != nil || d.Accepted {
			t.Fatalf("collision must be refused, not errored: %+v %v", d, err)
		}
		if v := latest(t, r, "col"); v.Origin != OriginVendor {
			t.Fatalf("builtin identity must survive: %+v", v)
		}
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action='content_registry.collision'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 || len(r.Refusals()) != 1 {
			t.Fatalf("collision audit=%d refusals=%d", n, len(r.Refusals()))
		}
	})
}

// Controller ruling: a byte-identical file under a different origin is a
// collision, never a no-op accept via the hash pre-check.
func TestIntake_CrossOriginIdenticalBytesRefused(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		body := "id: same\nname: S\nlocal_check: true\n"
		if d, err := r.Intake(ctx, file("builtin", body)); err != nil || !d.Accepted {
			t.Fatalf("builtin: %+v %v", d, err)
		}
		d, err := r.Intake(ctx, file("custom", body))
		if err != nil || d.Accepted {
			t.Fatalf("identical bytes under another origin must be refused: %+v %v", d, err)
		}
		vs, err := r.ListVersions(ctx, "same")
		if err != nil {
			t.Fatal(err)
		}
		if len(vs) != 1 || vs[0].Origin != OriginVendor {
			t.Fatalf("builtin identity must survive: %+v", vs)
		}
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action='content_registry.collision'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 || len(r.Refusals()) != 1 {
			t.Fatalf("collision audit=%d refusals=%d", n, len(r.Refusals()))
		}
	})
}

func TestIntake_ConcurrentSameBytesOneVersion(t *testing.T) { // Review Focus 2
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				mustIntake(t, r, ctx, file("intel", "id: race\nname: R\nart_techniques: [T1082]\n"))
			}()
		}
		wg.Wait()
		if vs, err := r.ListVersions(ctx, "race"); err != nil || len(vs) != 1 {
			t.Fatalf("want 1 version, got %d", len(vs))
		}
	})
}

func TestRegisterLocalApproved_RecreateAfterRetire(t *testing.T) { // Review Focus 5
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		b := []byte("id: rr\nname: RR\nlocal_check: true\n")
		if err := r.RegisterLocalApproved(ctx, "rr", b, "user:op"); err != nil {
			t.Fatal(err)
		}
		if err := r.RetireExecutable(ctx, "rr", "user:op", "deleted"); err != nil {
			t.Fatal(err)
		}
		if v := latest(t, r, "rr"); v.Lifecycle != LifecycleRetired {
			t.Fatalf("retire: %+v", v)
		}
		if err := r.RegisterLocalApproved(ctx, "rr", b, "user:op2"); err != nil {
			t.Fatal(err)
		}
		vs, err := r.ListVersions(ctx, "rr")
		if err != nil {
			t.Fatal(err)
		}
		if len(vs) != 1 || vs[0].Lifecycle != LifecyclePublishedLocal || vs[0].Trust != TrustLocalTrusted {
			t.Fatalf("re-approval: %+v", vs)
		}
	})
}

func TestRegisterLocalApproved_RequiresHumanActor(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		r := New(pool, testutil.DevVerifier())
		if err := r.RegisterLocalApproved(context.Background(), "h", []byte("id: h\nname: H\nlocal_check: true\n"), "intake"); err == nil {
			t.Fatal("non-human save must be rejected")
		}
	})
}

func TestIntake_ConcurrentGrandfatherOnlyOneTrusted(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		for i := 0; i < 5; i++ {
			id := fmt.Sprintf("gf%d", i)
			var wg sync.WaitGroup
			for _, name := range []string{"A", "B"} {
				wg.Add(1)
				go func() {
					defer wg.Done()
					body := "id: " + id + "\nname: " + name + "\nlocal_check: true\n"
					if _, err := r.Intake(ctx, file("custom", body)); err != nil {
						t.Error(err)
					}
				}()
			}
			wg.Wait()
			vs, err := r.ListVersions(ctx, id)
			if err != nil || len(vs) != 2 {
				t.Fatalf("%s: want 2 versions, got %d (%v)", id, len(vs), err)
			}
			trusted, drafts := 0, 0
			for _, v := range vs {
				switch {
				case v.Trust == TrustLocalTrusted && v.Lifecycle == LifecyclePublishedLocal && v.CreatedBy == ActorMigration:
					trusted++
				case v.Trust == TrustUntrusted && v.Lifecycle == LifecycleDraft && v.CreatedBy == ActorIntake:
					drafts++
				}
			}
			if trusted != 1 || drafts != 1 {
				t.Fatalf("%s: want 1 grandfathered + 1 draft, got %+v", id, vs)
			}
		}
	})
}

func TestIntake_VerifiedFlagWithEmptySignatureRefused(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		signer := testutil.NewTestSigner(t)
		r := New(pool, signer.Verifier())
		f := file("builtin", "id: es\nname: ES\nlocal_check: true\n")
		f.SignatureVerified = true
		if d := mustIntake(t, r, context.Background(), f); d.Accepted {
			t.Fatal("verified flag with empty signature must be refused")
		}
	})
}

func TestRegisterLocalApproved_ApprovesExistingIntakeDraft(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		// Post-migration, an out-of-band custom file is a custom-source DRAFT;
		// a UI save of the identical bytes approves that version in place.
		if _, err := pool.Exec(ctx, `INSERT INTO content_registry_state (id) VALUES (1)`); err != nil {
			t.Fatal(err)
		}
		body := "id: ad\nname: AD\nart_techniques: [T1082]\n"
		if d := mustIntake(t, r, ctx, file("custom", body)); !d.Accepted {
			t.Fatal("custom intake")
		}
		if v := latest(t, r, "ad"); v.Lifecycle != LifecycleDraft || v.Source != SourceCustom {
			t.Fatalf("setup: %+v", v)
		}
		if err := r.RegisterLocalApproved(ctx, "ad", []byte(body), "user:op"); err != nil {
			t.Fatal(err)
		}
		vs, err := r.ListVersions(ctx, "ad")
		if err != nil || len(vs) != 1 || vs[0].Lifecycle != LifecyclePublishedLocal || vs[0].Trust != TrustLocalTrusted {
			t.Fatalf("approval: %+v %v", vs, err)
		}
		var actor string
		if err := pool.QueryRow(ctx, `SELECT actor FROM content_version_events WHERE content_version_id=$1 AND to_lifecycle='PUBLISHED_LOCAL'`,
			vs[0].ID).Scan(&actor); err != nil || actor != "user:op" {
			t.Fatalf("approval event actor=%q err=%v", actor, err)
		}
	})
}

// Re-review M-a: the identical-bytes (hash-hit) path must not approve an
// intel-owned version through the UI save path either.
func TestRegisterLocalApproved_RefusesIntelIdenticalBytes(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		body := "id: ib\nname: I\nart_techniques: [T1082]\n"
		if d := mustIntake(t, r, ctx, file("intel", body)); !d.Accepted {
			t.Fatal("intel intake")
		}
		if err := r.RegisterLocalApproved(ctx, "ib", []byte(body), "user:op"); !errors.Is(err, ErrSourceCollision) {
			t.Fatalf("want ErrSourceCollision, got %v", err)
		}
		vs, err := r.ListVersions(ctx, "ib")
		if err != nil || len(vs) != 1 || vs[0].Lifecycle != LifecycleDraft || vs[0].Source != SourceIntel {
			t.Fatalf("intel DRAFT must be untouched: %+v %v", vs, err)
		}
	})
}

// Final-review T7: a UI save (custom source) must not mix new bytes into an
// intel-owned id, e.g. when the intel file is missing from disk.
func TestRegisterLocalApproved_RefusesIntelOwnedID(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		if d := mustIntake(t, r, ctx, file("intel", "id: io\nname: I\nart_techniques: [T1082]\n")); !d.Accepted {
			t.Fatal("intel intake")
		}
		err := r.RegisterLocalApproved(ctx, "io", []byte("id: io\nname: Mine\nlocal_check: true\n"), "user:op")
		if !errors.Is(err, ErrSourceCollision) {
			t.Fatalf("want ErrSourceCollision, got %v", err)
		}
		vs, err := r.ListVersions(ctx, "io")
		if err != nil || len(vs) != 1 || vs[0].Source != SourceIntel {
			t.Fatalf("intel version must be the only one: %+v %v", vs, err)
		}
	})
}

// Fix round 1 ruling (b): custom and intel are both LOCAL, so the origin
// check cannot stop one claiming the other's id; intake must.
func TestIntake_CustomIntelSourceCollisionRefused(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		if d := mustIntake(t, r, ctx, file("custom", "id: ci\nname: Custom\nlocal_check: true\n")); !d.Accepted {
			t.Fatalf("custom intake: %+v", d)
		}
		d, err := r.Intake(ctx, file("intel", "id: ci\nname: Intel\nart_techniques: [T1082]\n"))
		if err != nil || d.Accepted {
			t.Fatalf("intel claiming a custom id must be refused, not errored: %+v %v", d, err)
		}
		vs, err := r.ListVersions(ctx, "ci")
		if err != nil || len(vs) != 1 || vs[0].Source != SourceCustom {
			t.Fatalf("custom version must be the only one: %+v %v", vs, err)
		}
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action='content_registry.collision' AND resource='ci'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 || len(r.Refusals()) != 1 {
			t.Fatalf("collision audit=%d refusals=%d", n, len(r.Refusals()))
		}
	})
}

func TestIntake_SourceCollisionRecheckedUnderLock(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		mustIntake(t, r, ctx, file("intel", "id: cl\nname: I\nart_techniques: [T1082]\n"))
		a, err := analyzeArtifact([]byte("id: cl\nname: C\nlocal_check: true\n"))
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = r.createVersion(ctx, newVersion{contentID: "cl", origin: OriginLocal, source: SourceCustom,
			artifact: []byte("id: cl\nname: C\nlocal_check: true\n"), trust: TrustUntrusted, lifecycle: LifecycleDraft,
			actor: ActorIntake, analysis: a, exclusiveLocalSource: true})
		if !errors.Is(err, ErrSourceCollision) {
			t.Fatalf("want ErrSourceCollision under the lock, got %v", err)
		}
	})
}
