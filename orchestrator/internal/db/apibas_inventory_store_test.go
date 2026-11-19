package db_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
)

func inventoryTarget(t *testing.T, pool *pgxpool.Pool, id string) {
	t.Helper()
	ctx := context.Background()
	if err := db.EnsureAPIBASJobSchema(ctx, pool); err != nil {
		t.Fatal(err)
	}
	err := db.CreateAPIBASTarget(ctx, pool, db.APIBASTarget{
		ID: id, Name: id, BaseURL: "https://x.example.test", Environment: "lab", AllowedHosts: []string{"x.example.test"},
		AllowedScenarios: []string{"API-BAS-AUTHZ-001"}, CredentialRefs: map[string]string{}, Enabled: true, CreatedBy: "t",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func inventoryRec(target, sha string) db.APIBASInventory {
	return db.APIBASInventory{
		TargetID: target, ImportedBy: "u", SourceSHA256: sha, SourceBytes: 10, Title: "T", APIVersion: "1", OpenAPIVersion: "3.0.0",
		Operations: 1, Body: []byte(`{"operations":[{"method":"GET","path":"/a","auth":"required"}]}`),
	}
}

func TestAPIBASInventoryVersionsAndDedupe(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		inventoryTarget(t, pool, "inv-a")

		if _, err := db.GetAPIBASInventory(ctx, pool, "inv-a", 0); !errors.Is(err, db.ErrAPIBASInventoryNotFound) {
			t.Fatalf("before any import: %v, want not found", err)
		}
		v1, prev, unchanged, err := db.SaveAPIBASInventory(ctx, pool, inventoryRec("inv-a", "h1"))
		if err != nil || v1.Version != 1 || unchanged || prev.Version != 0 {
			t.Fatalf("first save: %+v prev %d unchanged %t err %v", v1, prev.Version, unchanged, err)
		}
		// The same source again is recognised and writes nothing.
		again, _, unchanged, err := db.SaveAPIBASInventory(ctx, pool, inventoryRec("inv-a", "h1"))
		if err != nil || !unchanged || again.Version != 1 {
			t.Fatalf("identical re-import: version %d unchanged %t err %v", again.Version, unchanged, err)
		}
		v2, prev, unchanged, err := db.SaveAPIBASInventory(ctx, pool, inventoryRec("inv-a", "h2"))
		if err != nil || v2.Version != 2 || unchanged || prev.Version != 1 || len(prev.Body) == 0 {
			t.Fatalf("second save: version %d prev %d err %v", v2.Version, prev.Version, err)
		}
		cur, err := db.GetAPIBASInventory(ctx, pool, "inv-a", 0)
		if err != nil || cur.Version != 2 {
			t.Fatalf("current: %+v %v", cur, err)
		}
		old, err := db.GetAPIBASInventory(ctx, pool, "inv-a", 1)
		if err != nil || old.SourceSHA256 != "h1" || len(old.Body) == 0 {
			t.Fatalf("version 1: %+v %v", old, err)
		}
		if _, err := db.GetAPIBASInventory(ctx, pool, "inv-a", 9); !errors.Is(err, db.ErrAPIBASInventoryNotFound) {
			t.Errorf("missing version: %v", err)
		}
		list, err := db.ListAPIBASInventoryVersions(ctx, pool, "inv-a")
		if err != nil || len(list) != 2 || list[0].Version != 2 {
			t.Fatalf("list: %d %v", len(list), err)
		}
		for _, r := range list {
			if len(r.Body) != 0 {
				t.Error("the version list must not carry bodies")
			}
		}
		// A different target is not affected, and an unknown one is refused.
		inventoryTarget(t, pool, "inv-b")
		other, _, _, err := db.SaveAPIBASInventory(ctx, pool, inventoryRec("inv-b", "h1"))
		if err != nil || other.Version != 1 {
			t.Errorf("second target: %+v %v", other, err)
		}
		if _, _, _, err := db.SaveAPIBASInventory(ctx, pool, inventoryRec("no-such-target", "h9")); !errors.Is(err, db.ErrAPIBASTargetNotFound) {
			t.Errorf("unknown target: %v", err)
		}
	})
}

func TestAPIBASInventoryPrunesOldVersions(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		inventoryTarget(t, pool, "inv-prune")
		total := db.MaxAPIBASInventoryVersions + 5
		for i := 1; i <= total; i++ {
			if _, _, _, err := db.SaveAPIBASInventory(ctx, pool, inventoryRec("inv-prune", fmt.Sprintf("h%d", i))); err != nil {
				t.Fatal(err)
			}
		}
		list, err := db.ListAPIBASInventoryVersions(ctx, pool, "inv-prune")
		if err != nil || len(list) != db.MaxAPIBASInventoryVersions {
			t.Fatalf("%d versions kept, want %d (%v)", len(list), db.MaxAPIBASInventoryVersions, err)
		}
		if list[0].Version != total || list[len(list)-1].Version != total-db.MaxAPIBASInventoryVersions+1 {
			t.Errorf("kept versions %d..%d", list[len(list)-1].Version, list[0].Version)
		}
	})
}

// Concurrent imports of different documents each get their own version; none is lost and none repeats.
func TestAPIBASInventoryConcurrentImports(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		inventoryTarget(t, pool, "inv-conc")
		const n = 8
		var wg sync.WaitGroup
		versions := make(chan int, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				v, _, _, err := db.SaveAPIBASInventory(ctx, pool, inventoryRec("inv-conc", fmt.Sprintf("c%d", i)))
				if err != nil {
					t.Error(err)
					return
				}
				versions <- v.Version
			}()
		}
		wg.Wait()
		close(versions)
		seen := map[int]bool{}
		for v := range versions {
			if seen[v] {
				t.Errorf("version %d issued twice", v)
			}
			seen[v] = true
		}
		if len(seen) != n {
			t.Errorf("%d distinct versions, want %d", len(seen), n)
		}
	})
}
