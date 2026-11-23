package connector

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/evidence"
	"github.com/audspect/bas/internal/threatidentity"
)

// REQ-055: the new-draft hook fires once for a newly created version and not again for a rewrite of the same
// generation, so the lab is woken for new content only.
func TestGenerator_NewDraftHookFiresOnlyForCreatedVersions(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		idStore := threatidentity.NewStore(pool)
		resolved, err := idStore.ResolveAndPersist(context.Background(), threatidentity.Incoming{Name: "APT-hook"}, threatidentity.ProfileFields{})
		if err != nil {
			t.Fatal(err)
		}
		seedActiveTechnique(t, pool, resolved.ThreatID, "T1059")
		seedActiveTechnique(t, pool, resolved.ThreatID, "T1053") // the generator skips actors below its technique minimum

		var fired atomic.Int32
		g := NewGenerator(t.TempDir(), nil, nil, nil).WithRegistrar(&dedupRegistrar{}).WithEvidenceStore(evidence.NewStore(pool)).WithActiveTechniqueProjection()
		g.SetNewDraftHook(func() { fired.Add(1) })
		a := ThreatActor{Name: "APT-hook", ThreatID: resolved.ThreatID, Source: "misp"}

		if _, err := g.Write([]ThreatActor{a}); err != nil {
			t.Fatalf("first Write: %v", err)
		}
		if n := fired.Load(); n != 1 {
			t.Fatalf("hook fired %d times after a new draft, want 1", n)
		}
		if _, err := g.Write([]ThreatActor{a}); err != nil {
			t.Fatalf("second Write: %v", err)
		}
		if n := fired.Load(); n != 1 {
			t.Fatalf("hook fired %d times after a rewrite of the same generation, want still 1", n)
		}
	})
}
