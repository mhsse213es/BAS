package contentregistry

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/testutil"
)

func TestResolveExecutable_GateMatrixAgainstDB(t *testing.T) { // A5
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		signer := testutil.NewTestSigner(t)
		for _, dev := range []bool{false, true} {
			r := New(pool, signer.Verifier())
			if dev {
				r = New(pool, testutil.DevVerifier())
			}
			n, allowed := 0, 0
			for _, o := range allOrigins {
				for _, tr := range allTrusts {
					for _, lc := range allLifecycles {
						n++
						id := fmt.Sprintf("g-%s-%03d", map[bool]string{false: "p", true: "d"}[dev], n)
						art := []byte("id: " + id + "\nname: G\nlocal_check: true\n")
						var sig []byte
						if tr == TrustVendorSigned {
							sig = signer.Sign(art)
						}
						src := map[Origin]IntakeSource{OriginVendor: SourceBuiltin, OriginLocal: SourceCustom}[o]
						nv := newVersion{contentID: id, origin: o, source: src, artifact: art, signature: sig, trust: tr,
							lifecycle: lc, actor: ActorMigration, analysis: mustAnalyze(t, string(art))}
						if _, _, err := r.createVersion(ctx, nv); err != nil {
							continue // illegal combination rejected by DB (covered by A4)
						}
						_, err := r.ResolveExecutable(ctx, id)
						// A dev verifier cannot re-verify signatures, so the gate fails
						// closed for VENDOR_SIGNED versions even where Executable() allows them.
						want := Executable(o, tr, lc, dev) && !(dev && tr == TrustVendorSigned)
						if got := err == nil; got != want {
							t.Errorf("dev=%v %s/%s/%s: runnable=%v want %v (err=%v)", dev, o, tr, lc, got, want, err)
						}
						if want {
							allowed++
						}
					}
				}
			}
			// Guards against the createVersion `continue` silently skipping ALLOW cases.
			// Prod: VENDOR_SIGNED+PUBLISHED and LOCAL_TRUSTED+PUBLISHED_LOCAL.
			// Dev: VENDOR+UNTRUSTED+PUBLISHED and LOCAL_TRUSTED+PUBLISHED_LOCAL.
			if allowed != 2 {
				t.Errorf("dev=%v: %d allowed combinations created, want exactly 2", dev, allowed)
			}
		}
	})
}

func TestResolveExecutable_DraftDoesNotDisplacePublished(t *testing.T) { // A7
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		v1 := []byte("id: dd\nname: V1\nlocal_check: true\n")
		if err := r.RegisterLocalApproved(ctx, "dd", v1, "user:op"); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO content_registry_state (id) VALUES (1)`); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Intake(ctx, scenario.IntakeFile{Path: "custom/dd.yaml", Source: "custom", Artifact: []byte("id: dd\nname: V2\nlocal_check: true\n")}); err != nil {
			t.Fatal(err)
		}
		ev, err := r.ResolveExecutable(ctx, "dd")
		if err != nil || ev.Version != 1 || ev.Scenario.Name != "V1" {
			t.Fatalf("want v1 from stored bytes, got %+v err=%v", ev, err)
		}
	})
}

func TestResolveExecutable_DenialReasons(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		_, err := r.ResolveExecutable(ctx, "nope")
		var ne *ErrNotExecutable
		if !errors.As(err, &ne) || ne.Reason != "not registered" {
			t.Fatalf("unregistered: %v", err)
		}
		_, _ = r.Intake(ctx, scenario.IntakeFile{Path: "intel/i.yaml", Source: "intel", Artifact: []byte("id: idr\nname: I\nart_techniques: [T1082]\n")})
		_, err = r.ResolveExecutable(ctx, "idr")
		if !errors.As(err, &ne) || ne.Reason != "no executable version; latest v1 is DRAFT/UNTRUSTED" {
			t.Fatalf("draft: %v", err)
		}
	})
}

// signedPublished inserts a VENDOR_SIGNED+PUBLISHED version of id with the given name.
func signedPublished(t *testing.T, r *Registry, signer *testutil.TestSigner, id, name string) string {
	t.Helper()
	art := []byte(fmt.Sprintf("id: %s\nname: %s\nlocal_check: true\n", id, name))
	vid, _, err := r.createVersion(context.Background(), newVersion{contentID: id, origin: OriginVendor, source: SourceBuiltin,
		artifact: art, signature: signer.Sign(art), trust: TrustVendorSigned, lifecycle: LifecyclePublished,
		actor: ActorMigration, analysis: mustAnalyze(t, string(art))})
	if err != nil {
		t.Fatal(err)
	}
	return vid
}

func TestGateReverifiesVendorSignature(t *testing.T) { // A19
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		signer := testutil.NewTestSigner(t)
		r := New(pool, signer.Verifier())
		art := []byte("id: tv\nname: T\nlocal_check: true\n")
		if _, err := r.Intake(ctx, scenario.IntakeFile{Path: "tv.yaml", Source: "builtin", Artifact: art,
			Signature: signer.Sign(art), SignatureVerified: true}); err != nil {
			t.Fatal(err)
		}
		if _, err := r.ResolveExecutable(ctx, "tv"); err != nil {
			t.Fatalf("intact: %v", err)
		}
		// Superuser tamper of the stored bytes (keep size consistent with the CHECK).
		tampered := []byte("id: tv\nname: X\nlocal_check: true\n")
		if _, err := pool.Exec(ctx, `UPDATE content_versions SET artifact_bytes=$1, artifact_size=$2 WHERE content_id='tv'`,
			tampered, len(tampered)); err != nil {
			t.Fatal(err)
		}
		_, err := r.ResolveExecutable(ctx, "tv")
		var ne *ErrNotExecutable
		if !errors.As(err, &ne) || !strings.Contains(ne.Reason, "signature re-verification failed for v1") {
			t.Fatalf("tampered vendor content must be denied with re-verification reason, got %v", err)
		}
		var n int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action='content_registry.tamper'`).Scan(&n)
		if n != 1 {
			t.Fatalf("tamper audit rows = %d", n)
		}
	})
}

// A tampered newest version must deny, never fall through to an older intact one.
func TestResolveExecutable_TamperedNewestDoesNotFallThrough(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		signer := testutil.NewTestSigner(t)
		r := New(pool, signer.Verifier())
		signedPublished(t, r, signer, "ft", "V1")
		v2 := signedPublished(t, r, signer, "ft", "V2")
		if ev, err := r.ResolveExecutable(ctx, "ft"); err != nil || ev.Version != 2 {
			t.Fatalf("intact: want v2, got %+v err=%v", ev, err)
		}
		tampered := []byte("id: ft\nname: EVIL\nlocal_check: true\n")
		if _, err := pool.Exec(ctx, `UPDATE content_versions SET artifact_bytes=$1, artifact_size=$2 WHERE id=$3`,
			tampered, len(tampered), v2); err != nil {
			t.Fatal(err)
		}
		ev, err := r.ResolveExecutable(ctx, "ft")
		var ne *ErrNotExecutable
		if !errors.As(err, &ne) || !strings.Contains(ne.Reason, "signature re-verification failed for v2") {
			t.Fatalf("want denial for v2, got %+v err=%v", ev, err)
		}
	})
}

// Validly signed bytes of another content id swapped into this row must be denied.
func TestResolveExecutable_RejectsSwappedSignedBytes(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		signer := testutil.NewTestSigner(t)
		r := New(pool, signer.Verifier())
		signedPublished(t, r, signer, "sw-a", "A")
		bid := signedPublished(t, r, signer, "sw-b", "B")
		artA := []byte("id: sw-a\nname: A\nlocal_check: true\n")
		if _, err := pool.Exec(ctx,
			`UPDATE content_versions SET artifact_bytes=$1, artifact_size=$2, artifact_sha256=$3, signature_bytes=$4 WHERE id=$5`,
			artA, len(artA), sha256Hex(artA), signer.Sign(artA), bid); err != nil {
			t.Fatal(err)
		}
		_, err := r.ResolveExecutable(ctx, "sw-b")
		var ne *ErrNotExecutable
		if !errors.As(err, &ne) || !strings.Contains(ne.Reason, `does not match content id`) {
			t.Fatalf("swapped bytes must be denied, got %v", err)
		}
	})
}

// A dev build cannot verify signatures: deny, audited as unavailable, not tamper.
func TestResolveExecutable_DevBuildVendorSignedIsNotTamper(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		signer := testutil.NewTestSigner(t)
		r := New(pool, testutil.DevVerifier())
		signedPublished(t, r, signer, "dv", "V1")
		_, err := r.ResolveExecutable(ctx, "dv")
		var ne *ErrNotExecutable
		if !errors.As(err, &ne) || !strings.Contains(ne.Reason, "cannot verify signatures") {
			t.Fatalf("want signing-unavailable denial, got %v", err)
		}
		var tamper, unavail int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action='content_registry.tamper'`).Scan(&tamper)
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action='content_registry.signing_unavailable'`).Scan(&unavail)
		if tamper != 0 || unavail != 1 {
			t.Fatalf("tamper=%d signing_unavailable=%d, want 0 and 1", tamper, unavail)
		}
	})
}

func TestAttachVendorSignature(t *testing.T) { // A18
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		signer := testutil.NewTestSigner(t)
		r := New(pool, signer.Verifier())
		art := []byte("id: vf\nname: VF\nlocal_check: true\n")
		id, _, err := r.createVersion(ctx, newVersion{contentID: "vf", origin: OriginVendor, source: SourceBuiltin,
			artifact: art, trust: TrustUntrusted, lifecycle: LifecycleDraft, actor: "user:research", analysis: mustAnalyze(t, string(art))})
		if err != nil {
			t.Fatal(err)
		}
		for _, to := range []Lifecycle{LifecycleValidating, LifecycleValidated, LifecycleApproved} {
			actor := "user:research"
			if to == LifecycleValidating || to == LifecycleValidated {
				actor = ActorIntake // system-only moves
			}
			if err := r.Transition(ctx, id, to, actor, ""); err != nil {
				t.Fatalf("-> %s: %v", to, err)
			}
		}
		if err := r.Transition(ctx, id, LifecyclePublished, "user:research", ""); err == nil {
			t.Fatal("publish before signature must fail")
		}
		if err := r.AttachVendorSignature(ctx, id, []byte("garbage"), "user:research"); err == nil {
			t.Fatal("invalid signature must fail")
		}
		if err := r.AttachVendorSignature(ctx, id, signer.Sign(art), "user:research"); err != nil {
			t.Fatalf("valid signature: %v", err)
		}
		if err := r.AttachVendorSignature(ctx, id, signer.Sign(art), "user:research"); err == nil {
			t.Fatal("second attach must fail (signature already set)")
		}
		if err := r.Transition(ctx, id, LifecyclePublished, "user:research", ""); err != nil {
			t.Fatalf("publish after signature: %v", err)
		}
		if _, err := r.ResolveExecutable(ctx, "vf"); err != nil {
			t.Fatalf("published vendor content must run: %v", err)
		}
		// LOCAL content can never receive a vendor signature.
		la := []byte("id: lf\nname: LF\nlocal_check: true\n")
		lid, _, err := r.createVersion(ctx, newVersion{contentID: "lf", origin: OriginLocal, source: SourceCustom,
			artifact: la, trust: TrustUntrusted, lifecycle: LifecycleDraft, actor: ActorIntake, analysis: mustAnalyze(t, string(la))})
		if err != nil {
			t.Fatal(err)
		}
		if err := r.AttachVendorSignature(ctx, lid, signer.Sign(la), "user:research"); err == nil ||
			!strings.Contains(err.Error(), "only VENDOR content") {
			t.Fatalf("LOCAL content must be refused by the Go guard, got %v", err)
		}
	})
}

func TestResolveExecutable_PicksHighestExecutableVersion(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		for _, name := range []string{"V1", "V2"} {
			art := []byte(fmt.Sprintf("id: hv\nname: %s\nlocal_check: true\n", name))
			if err := r.RegisterLocalApproved(ctx, "hv", art, "user:op"); err != nil {
				t.Fatal(err)
			}
		}
		ev, err := r.ResolveExecutable(ctx, "hv")
		if err != nil || ev.Version != 2 || ev.Scenario.Name != "V2" {
			t.Fatalf("want v2, got %+v err=%v", ev, err)
		}
	})
}
