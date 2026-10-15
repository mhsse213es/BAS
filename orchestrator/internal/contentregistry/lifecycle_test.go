package contentregistry

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

var allOrigins = []Origin{OriginVendor, OriginLocal}
var allTrusts = []Trust{TrustVendorSigned, TrustLocalTrusted, TrustUntrusted}
var allLifecycles = []Lifecycle{LifecycleDraft, LifecycleValidating, LifecycleValidated, LifecycleApproved,
	LifecyclePublished, LifecyclePublishedLocal, LifecycleRetired, LifecycleRejected}

// A5 (pure half): exactly two combinations run in production; the dev
// exception adds exactly one.
func TestExecutableMatrix(t *testing.T) {
	for _, o := range allOrigins {
		for _, tr := range allTrusts {
			for _, lc := range allLifecycles {
				prod := (o == OriginVendor && tr == TrustVendorSigned && lc == LifecyclePublished) ||
					(o == OriginLocal && tr == TrustLocalTrusted && lc == LifecyclePublishedLocal)
				dev := prod || (o == OriginVendor && tr == TrustUntrusted && lc == LifecyclePublished)
				if got := Executable(o, tr, lc, false); got != prod {
					t.Errorf("prod %s/%s/%s = %v want %v", o, tr, lc, got, prod)
				}
				if got := Executable(o, tr, lc, true); got != dev {
					t.Errorf("dev %s/%s/%s = %v want %v", o, tr, lc, got, dev)
				}
			}
		}
	}
}

func TestCheckTransition_Rules(t *testing.T) {
	const user = "user:u1"
	cases := []struct {
		name     string
		o        Origin
		tr       Trust
		from, to Lifecycle
		actor    string
		ok       bool
	}{
		{"draft to validating by system", OriginVendor, TrustUntrusted, LifecycleDraft, LifecycleValidating, "system:validator", true},
		{"validated to approved vendor user", OriginVendor, TrustUntrusted, LifecycleValidated, LifecycleApproved, user, true},
		{"validated to approved needs human", OriginVendor, TrustUntrusted, LifecycleValidated, LifecycleApproved, "intake", false},
		{"approved local impossible", OriginLocal, TrustUntrusted, LifecycleValidated, LifecycleApproved, user, false},
		{"approved to published needs signature", OriginVendor, TrustUntrusted, LifecycleApproved, LifecyclePublished, user, false},
		{"approved to published signed", OriginVendor, TrustVendorSigned, LifecycleApproved, LifecyclePublished, user, true},
		{"draft to published_local local", OriginLocal, TrustUntrusted, LifecycleDraft, LifecyclePublishedLocal, user, true},
		{"draft to published_local vendor", OriginVendor, TrustUntrusted, LifecycleDraft, LifecyclePublishedLocal, user, false},
		{"draft straight to published", OriginVendor, TrustVendorSigned, LifecycleDraft, LifecyclePublished, user, false},
		{"retired to published_local re-approval", OriginLocal, TrustLocalTrusted, LifecycleRetired, LifecyclePublishedLocal, user, true},
		{"retired vendor is terminal", OriginVendor, TrustVendorSigned, LifecycleRetired, LifecyclePublished, user, false},
		{"rejected is terminal", OriginLocal, TrustUntrusted, LifecycleRejected, LifecycleDraft, user, false},
		{"published_local retire", OriginLocal, TrustLocalTrusted, LifecyclePublishedLocal, LifecycleRetired, user, true},
		{"retire needs human", OriginLocal, TrustLocalTrusted, LifecyclePublishedLocal, LifecycleRetired, "intake", false},
		{"validated is not executable shortcut", OriginLocal, TrustUntrusted, LifecycleValidated, LifecyclePublished, user, false},
		{"validated by human refused", OriginVendor, TrustUntrusted, LifecycleValidating, LifecycleValidated, user, false},
		{"validated by system", OriginVendor, TrustUntrusted, LifecycleValidating, LifecycleValidated, ActorIntake, true},
		{"validating back to draft by human refused", OriginLocal, TrustUntrusted, LifecycleValidating, LifecycleDraft, user, false},
		{"validating back to draft by generator", OriginLocal, TrustUntrusted, LifecycleValidating, LifecycleDraft, ActorGenerator, true},
		{"reject from approved", OriginVendor, TrustUntrusted, LifecycleApproved, LifecycleRejected, user, true},
	}
	for _, c := range cases {
		err := CheckTransition(c.o, c.tr, c.from, c.to, c.actor)
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v want ok=%v", c.name, err, c.ok)
		}
	}
}

func TestTrustAfter(t *testing.T) {
	if got := TrustAfter(OriginLocal, TrustUntrusted, LifecyclePublishedLocal); got != TrustLocalTrusted {
		t.Fatalf("local publish: %s", got)
	}
	if got := TrustAfter(OriginLocal, TrustLocalTrusted, LifecycleRetired); got != TrustLocalTrusted {
		t.Fatalf("retire keeps historical trust: %s", got)
	}
	if got := TrustAfter(OriginVendor, TrustUntrusted, LifecycleApproved); got != TrustUntrusted {
		t.Fatalf("approval never grants vendor trust: %s", got)
	}
}

func TestIsHumanActor(t *testing.T) {
	for in, want := range map[string]bool{"user:u1": true, "user:": false, "intake": false, "migration:pre-registry": false, "": false} {
		if IsHumanActor(in) != want {
			t.Errorf("IsHumanActor(%q) != %v", in, want)
		}
	}
}

func mustCreateDraftVersion(t *testing.T, reg *Registry, actor, contentID string) string {
	t.Helper()
	art := "id: " + contentID + "\nname: N\nsteps:\n  - {name: a, technique_id: T1082, framework: custom, command: x}\n"
	vid, _, err := reg.createVersion(context.Background(), newVersion{
		contentID: contentID, origin: OriginLocal, source: SourceCustom, artifact: []byte(art),
		trust: TrustUntrusted, lifecycle: LifecycleDraft, actor: actor, analysis: mustAnalyze(t, art),
	})
	if err != nil {
		t.Fatalf("createVersion(%s): %v", contentID, err)
	}
	return vid
}

// mustCreateGeneratedDraft creates a DRAFT version through the real factory
// path (RegisterGenerated), so it carries a 'generated_for' provenance
// relationship. This is genuine TCF-generated content, distinct from plain
// intel intake which shares ActorGenerator but has no generation provenance.
func mustCreateGeneratedDraft(t *testing.T, reg *Registry, pool *pgxpool.Pool, contentID string) string {
	t.Helper()
	thr := seedThreat(t, pool, contentID)
	art := "id: " + contentID + "\nname: N\nsteps:\n  - {name: a, technique_id: T1082, framework: custom, command: x}\n"
	vid, _, err := reg.RegisterGenerated(context.Background(), GeneratedCandidate{
		ContentID: contentID, Artifact: []byte(art), GenerationKey: "k-" + contentID,
		GenerationRef: "k-" + contentID, ThreatID: thr,
	})
	if err != nil {
		t.Fatalf("RegisterGenerated(%s): %v", contentID, err)
	}
	return vid
}

func assertLifecycle(t *testing.T, reg *Registry, vid string, want Lifecycle) {
	t.Helper()
	v, err := reg.LoadVersion(context.Background(), vid)
	if err != nil {
		t.Fatalf("LoadVersion: %v", err)
	}
	if v.Lifecycle != want {
		t.Fatalf("lifecycle = %s, want %s", v.Lifecycle, want)
	}
}

func TestTransition_TCFOriginDraftCannotPublishDirectly(t *testing.T) { // TCF Phase 6
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		reg := New(pool, testutil.DevVerifier())
		vid := mustCreateGeneratedDraft(t, reg, pool, "pubgate-generator")

		if err := reg.Transition(ctx, vid, LifecyclePublishedLocal, "user:admin1", "trying to publish"); err == nil {
			t.Fatal("DRAFT->PUBLISHED_LOCAL must be refused for factory-generated content")
		}
	})
}

// TestTransition_IntelIntakeDraftCanPublishDirectly guards the ruling that
// plain intel intake (ActorGenerator but no generation provenance) is EXEMPT
// from the validation gate -- it is not factory-generated content.
func TestTransition_IntelIntakeDraftCanPublishDirectly(t *testing.T) { // TCF Phase 6 regression guard
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		reg := New(pool, testutil.DevVerifier())
		// Plain createVersion with ActorGenerator and NO generated_for link --
		// exactly the shape SourceIntel intake produces (intake.go:183).
		vid := mustCreateDraftVersion(t, reg, ActorGenerator, "pubgate-intel-intake")

		if err := reg.Transition(ctx, vid, LifecyclePublishedLocal, "user:admin1", "operator publish"); err != nil {
			t.Fatalf("intel-intake DRAFT->PUBLISHED_LOCAL must succeed (no generation provenance): %v", err)
		}
		assertLifecycle(t, reg, vid, LifecyclePublishedLocal)
	})
}

func TestTransition_TCFOriginComposedDraftCannotPublishDirectly(t *testing.T) { // TCF Phase 6
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		reg := New(pool, testutil.DevVerifier())
		vid := mustCreateDraftVersion(t, reg, ActorComposer, "pubgate-composer")

		if err := reg.Transition(ctx, vid, LifecyclePublishedLocal, "user:admin1", "trying to publish"); err == nil {
			t.Fatal("DRAFT->PUBLISHED_LOCAL must be refused for composer-created content")
		}
	})
}

func TestTransition_OperatorDraftCanStillPublishDirectly(t *testing.T) { // TCF Phase 6 regression guard
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		reg := New(pool, testutil.DevVerifier())
		vid := mustCreateDraftVersion(t, reg, ActorIntake, "pubgate-intake")

		if err := reg.Transition(ctx, vid, LifecyclePublishedLocal, "user:admin1", "operator publish"); err != nil {
			t.Fatalf("intake-actor DRAFT->PUBLISHED_LOCAL must still succeed: %v", err)
		}
	})
}

func TestTransition_ValidatedTCFOriginCanStillPublish(t *testing.T) { // TCF Phase 6
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		reg := New(pool, testutil.DevVerifier())
		vid := mustCreateGeneratedDraft(t, reg, pool, "pubgate-validated")

		if err := reg.Transition(ctx, vid, LifecycleValidating, ActorValidationLab, "scanned"); err != nil {
			t.Fatalf("DRAFT->VALIDATING: %v", err)
		}
		if err := reg.Transition(ctx, vid, LifecycleValidated, ActorValidationLab, "passed"); err != nil {
			t.Fatalf("VALIDATING->VALIDATED: %v", err)
		}
		if err := reg.Transition(ctx, vid, LifecyclePublishedLocal, "user:admin1", "publish after validation"); err != nil {
			t.Fatalf("VALIDATED->PUBLISHED_LOCAL must succeed: %v", err)
		}
	})
}
