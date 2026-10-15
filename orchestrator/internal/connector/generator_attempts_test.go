package connector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/evidence"
	"github.com/audspect/bas/internal/threatidentity"
)

// dedupRegistrar mimics the real Content Registry's dedup behavior that
// recRegistrar (generator_test.go) does not: created=true only the first
// time a given GenerationKey is seen, false on every repeat -- needed to
// test the "changed but not created" and "created despite a later repeat"
// distinctions this task's precedence rule depends on.
type dedupRegistrar struct {
	seen map[string]bool
}

func (r *dedupRegistrar) RegisterGenerated(_ context.Context, c contentregistry.GeneratedCandidate) (string, bool, error) {
	if r.seen == nil {
		r.seen = map[string]bool{}
	}
	created := !r.seen[c.GenerationKey]
	r.seen[c.GenerationKey] = true
	return "v-" + c.GenerationKey[:8], created, nil
}

// collisionRegistrar is a Registrar fake that always returns the given error.
type collisionRegistrar struct{ err error }

func (c collisionRegistrar) RegisterGenerated(context.Context, contentregistry.GeneratedCandidate) (string, bool, error) {
	return "", false, c.err
}

func TestGenerator_WriteRecordsExactlyOneRowWhenBothChangedAndCreated(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		idStore := threatidentity.NewStore(pool)
		resolved, err := idStore.ResolveAndPersist(context.Background(), threatidentity.Incoming{Name: "APT-both"}, threatidentity.ProfileFields{})
		if err != nil {
			t.Fatal(err)
		}
		seedActiveTechnique(t, pool, resolved.ThreatID, "T1059")
		seedActiveTechnique(t, pool, resolved.ThreatID, "T1053")

		store := evidence.NewStore(pool)
		g := NewGenerator(t.TempDir(), nil, nil, nil).WithRegistrar(&dedupRegistrar{}).WithEvidenceStore(store).WithActiveTechniqueProjection()
		a := ThreatActor{Name: "APT-both", ThreatID: resolved.ThreatID, Source: "misp"}

		// First Write on a fresh actor: the registry has never seen this
		// GenerationKey (Created), and the working-copy file doesn't exist
		// on disk yet either (Changed) -- both would fire under the old,
		// non-exclusive counters.
		if _, err := g.Write([]ThreatActor{a}); err != nil {
			t.Fatalf("Write: %v", err)
		}

		got, err := store.ListGenerationAttempts(context.Background(), evidence.GenerationAttemptFilter{ThreatID: resolved.ThreatID})
		if err != nil {
			t.Fatalf("ListGenerationAttempts: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("expected exactly 1 attempt row, got %d", len(got))
		}
		if got[0].Outcome != "created" {
			t.Fatalf("expected outcome=created per the precedence rule, got %q", got[0].Outcome)
		}
	})
}

func TestGenerator_WriteRecordsChangedWhenFileRewrittenButNotCreated(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		idStore := threatidentity.NewStore(pool)
		resolved, err := idStore.ResolveAndPersist(context.Background(), threatidentity.Incoming{Name: "APT-changed"}, threatidentity.ProfileFields{})
		if err != nil {
			t.Fatal(err)
		}
		seedActiveTechnique(t, pool, resolved.ThreatID, "T1059")
		seedActiveTechnique(t, pool, resolved.ThreatID, "T1053")

		store := evidence.NewStore(pool)
		dir := t.TempDir()
		reg := &dedupRegistrar{}
		g := NewGenerator(dir, nil, nil, nil).WithRegistrar(reg).WithEvidenceStore(store).WithActiveTechniqueProjection()
		a := ThreatActor{Name: "APT-changed", ThreatID: resolved.ThreatID, Source: "misp"}

		if _, err := g.Write([]ThreatActor{a}); err != nil {
			t.Fatalf("first Write: %v", err)
		}
		// Delete the working-copy file but leave the registry version in
		// place (same actor, same GenerationKey -- dedupRegistrar now
		// reports created=false) -- the next Write rewrites the file
		// (Changed) without creating anything new (not Created).
		fname := filepath.Join(dir, "intel", threatidentity.ContentID(resolved.ThreatID)+".yaml")
		if err := os.Remove(fname); err != nil {
			t.Fatalf("remove working copy: %v", err)
		}

		if _, err := g.Write([]ThreatActor{a}); err != nil {
			t.Fatalf("second Write: %v", err)
		}

		got, err := store.ListGenerationAttempts(context.Background(), evidence.GenerationAttemptFilter{ThreatID: resolved.ThreatID, Limit: 1})
		if err != nil {
			t.Fatalf("ListGenerationAttempts: %v", err)
		}
		if len(got) != 1 || got[0].Outcome != "changed" {
			t.Fatalf("expected the most recent attempt to be outcome=changed, got %+v", got)
		}
	})
}

func TestGenerator_WriteRecordsGenerationNumberErrorOnSameRow(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		idStore := threatidentity.NewStore(pool)
		resolved, err := idStore.ResolveAndPersist(context.Background(), threatidentity.Incoming{Name: "APT-genfail"}, threatidentity.ProfileFields{})
		if err != nil {
			t.Fatal(err)
		}
		seedActiveTechnique(t, pool, resolved.ThreatID, "T1059")
		seedActiveTechnique(t, pool, resolved.ThreatID, "T1053")

		store := evidence.NewStore(pool)
		g := NewGenerator(t.TempDir(), nil, nil, nil).WithRegistrar(&dedupRegistrar{}).WithEvidenceStore(store).WithActiveTechniqueProjection()
		// evidenceRecordErr is an unexported, test-only override field (Step 3),
		// the same pattern this file's sibling generator_meta_test.go already
		// uses for attackMeta -- the UNIQUE(threat_id, generation_number)
		// constraint this would otherwise exercise only fails under a genuine
		// concurrent race, which a single-threaded test cannot engineer.
		g.evidenceRecordErr = errors.New("boom")
		a := ThreatActor{Name: "APT-genfail", ThreatID: resolved.ThreatID, Source: "misp"}

		if _, err := g.Write([]ThreatActor{a}); err != nil {
			t.Fatalf("Write: %v", err)
		}

		got, err := store.ListGenerationAttempts(context.Background(), evidence.GenerationAttemptFilter{ThreatID: resolved.ThreatID})
		if err != nil {
			t.Fatalf("ListGenerationAttempts: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("expected exactly 1 attempt row, got %d", len(got))
		}
		if got[0].Outcome != "created" {
			t.Fatalf("expected outcome to remain created even though evidence-recording failed, got %q", got[0].Outcome)
		}
		if got[0].Detail == nil || !strings.Contains(*got[0].Detail, "generation_number_error") {
			t.Fatalf("expected detail to record the generation_number_error, got %v", got[0].Detail)
		}
	})
}

func TestGenerator_WriteRecordsDistinctCollisionReasonCodes(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		reasonCode string
	}{
		{"source collision", contentregistry.ErrSourceCollision, "source_collision"},
		{"origin collision", contentregistry.ErrOriginCollision, "origin_collision"},
		{"threat collision", contentregistry.ErrThreatCollision, "threat_collision"},
		{"generic registrar error", errors.New("boom"), "registrar_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
				idStore := threatidentity.NewStore(pool)
				resolved, err := idStore.ResolveAndPersist(context.Background(), threatidentity.Incoming{Name: "APT-" + tc.reasonCode}, threatidentity.ProfileFields{})
				if err != nil {
					t.Fatal(err)
				}
				seedActiveTechnique(t, pool, resolved.ThreatID, "T1059")
				seedActiveTechnique(t, pool, resolved.ThreatID, "T1053")

				store := evidence.NewStore(pool)
				g := NewGenerator(t.TempDir(), nil, nil, nil).WithRegistrar(collisionRegistrar{err: tc.err}).WithEvidenceStore(store).WithActiveTechniqueProjection()
				a := ThreatActor{Name: "APT-" + tc.reasonCode, ThreatID: resolved.ThreatID, Source: "misp"}

				if _, err := g.Write([]ThreatActor{a}); err != nil {
					t.Fatalf("Write: %v", err)
				}

				got, err := store.ListGenerationAttempts(context.Background(), evidence.GenerationAttemptFilter{ThreatID: resolved.ThreatID})
				if err != nil {
					t.Fatalf("ListGenerationAttempts: %v", err)
				}
				if len(got) != 1 || got[0].Outcome != "failed" || got[0].ReasonCode != tc.reasonCode {
					t.Fatalf("expected outcome=failed reason_code=%s, got %+v", tc.reasonCode, got)
				}
			})
		})
	}
}
