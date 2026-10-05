package contentregistry

import (
	"context"
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
		if d, _ := r.Intake(ctx, ub); d.Accepted {
			t.Fatal("unverified builtin must be refused when signing is enabled")
		}

		if d, _ := r.Intake(ctx, file("intel", "id: in1\nname: In\nart_techniques: [T1082]\n")); !d.Accepted {
			t.Fatal("intel intake")
		}
		if v := latest(t, r, "in1"); v.Origin != OriginLocal || v.Trust != TrustUntrusted || v.Lifecycle != LifecycleDraft {
			t.Fatalf("intel row: %+v", v)
		}

		// Pre-migration custom file: grandfathered.
		if d, _ := r.Intake(ctx, file("custom", "id: cu1\nname: Cu\nlocal_check: true\n")); !d.Accepted {
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
		if d, _ := r.Intake(context.Background(), file("builtin", "id: dv\nname: D\nlocal_check: true\n")); !d.Accepted {
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
		_, _ = r.Intake(ctx, file("custom", "id: cu2\nname: Cu\nlocal_check: true\n"))
		if v := latest(t, r, "cu2"); v.Lifecycle != LifecycleDraft || v.Trust != TrustUntrusted {
			t.Fatalf("post-migration out-of-band custom file must be DRAFT: %+v", v)
		}
	})
}

func TestIntake_LocalOutOfBandEditBecomesDraft(t *testing.T) { // A11
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		_, _ = pool.Exec(ctx, `INSERT INTO content_registry_state (id) VALUES (1)`)
		v1 := []byte("id: ob\nname: OB\nlocal_check: true\n")
		if err := r.RegisterLocalApproved(ctx, "ob", v1, "user:op"); err != nil {
			t.Fatal(err)
		}
		if d, _ := r.Intake(ctx, file("custom", string(v1))); !d.Accepted {
			t.Fatal("same bytes on disk must be a no-op accept")
		}
		_, _ = r.Intake(ctx, file("custom", "id: ob\nname: OB edited\nlocal_check: true\n"))
		vs, _ := r.ListVersions(ctx, "ob")
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
		_, _ = r.Intake(ctx, file("builtin", "id: col\nname: B\nlocal_check: true\n"))
		d, err := r.Intake(ctx, file("custom", "id: col\nname: C\nlocal_check: true\n"))
		if err != nil || d.Accepted {
			t.Fatalf("collision must be refused, not errored: %+v %v", d, err)
		}
		if v := latest(t, r, "col"); v.Origin != OriginVendor {
			t.Fatalf("builtin identity must survive: %+v", v)
		}
		var n int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action='content_registry.collision'`).Scan(&n)
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
		vs, _ := r.ListVersions(ctx, "same")
		if len(vs) != 1 || vs[0].Origin != OriginVendor {
			t.Fatalf("builtin identity must survive: %+v", vs)
		}
		var n int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action='content_registry.collision'`).Scan(&n)
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
				_, _ = r.Intake(ctx, file("intel", "id: race\nname: R\nart_techniques: [T1082]\n"))
			}()
		}
		wg.Wait()
		if vs, _ := r.ListVersions(ctx, "race"); len(vs) != 1 {
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
		vs, _ := r.ListVersions(ctx, "rr")
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
