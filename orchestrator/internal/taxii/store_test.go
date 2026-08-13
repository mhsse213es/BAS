package taxii

import (
	"context"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func TestCreate_PersistsAndGetRoundTrips(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		created, err := store.Create(ctx, ConnectorConfig{
			Name: "FS-ISAC Test", ServerURL: "https://taxii.example.org", AuthType: "basic",
			Username: "user1", Password: "secret1", Enabled: true,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if created.ID == "" {
			t.Fatal("Create() returned empty ID")
		}
		if created.LastPollStatus != "never" {
			t.Errorf("LastPollStatus = %q, want \"never\"", created.LastPollStatus)
		}

		got, err := store.Get(ctx, created.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.Name != "FS-ISAC Test" || got.ServerURL != "https://taxii.example.org" || got.Password != "secret1" {
			t.Errorf("Get() = %+v, fields don't round-trip", got)
		}
	})
}

func TestGet_NotFound_ReturnsErrNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := NewStore(pool).Get(context.Background(), "does-not-exist")
		if err != ErrNotFound {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
	})
}

func TestListEnabled_OnlyReturnsEnabledRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		if _, err := store.Create(ctx, ConnectorConfig{Name: "Enabled One", ServerURL: "https://a.example", Enabled: true}); err != nil {
			t.Fatalf("create enabled: %v", err)
		}
		if _, err := store.Create(ctx, ConnectorConfig{Name: "Disabled One", ServerURL: "https://b.example", Enabled: false}); err != nil {
			t.Fatalf("create disabled: %v", err)
		}
		got, err := store.ListEnabled(ctx)
		if err != nil {
			t.Fatalf("ListEnabled: %v", err)
		}
		for _, c := range got {
			if c.Name == "Disabled One" {
				t.Fatal("ListEnabled returned a disabled row")
			}
		}
		found := false
		for _, c := range got {
			if c.Name == "Enabled One" {
				found = true
			}
		}
		if !found {
			t.Fatal("ListEnabled did not return the enabled row")
		}
	})
}

func TestUpdate_KeepsSecretWhenFlagSet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		created, err := store.Create(ctx, ConnectorConfig{Name: "Orig", ServerURL: "https://a.example", Password: "orig-secret", Enabled: false})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		updated, err := store.Update(ctx, created.ID, ConnectorConfig{
			Name: "Renamed", ServerURL: "https://a.example", Password: "", Enabled: true,
		}, true, true, true) // keepPassword/keepClientCert/keepClientKey
		if err != nil {
			t.Fatalf("Update: %v", err)
		}
		if updated.Name != "Renamed" || !updated.Enabled {
			t.Errorf("Update() = %+v, plain fields not applied", updated)
		}
		if updated.Password != "orig-secret" {
			t.Errorf("Password = %q, want kept value %q", updated.Password, "orig-secret")
		}
	})
}

func TestDelete_RemovesRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		created, err := store.Create(ctx, ConnectorConfig{Name: "ToDelete", ServerURL: "https://a.example"})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if err := store.Delete(ctx, created.ID); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if _, err := store.Get(ctx, created.ID); err != ErrNotFound {
			t.Fatalf("Get after Delete: err = %v, want ErrNotFound", err)
		}
	})
}

func TestRecordPollResult_UpdatesStatusAndSummary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		created, err := store.Create(ctx, ConnectorConfig{Name: "PollTest", ServerURL: "https://a.example"})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if err := store.RecordPollResult(ctx, created.ID, "ok", PollSummary{Processed: 3, Skipped: 1, Malformed: 0}, ""); err != nil {
			t.Fatalf("RecordPollResult: %v", err)
		}
		got, err := store.Get(ctx, created.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.LastPollStatus != "ok" || got.LastPollSummary.Processed != 3 || got.LastPollAt == nil {
			t.Errorf("Get() after RecordPollResult = %+v", got)
		}
	})
}

func TestIngestedObjects_HasThenRecordThenHasAgain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		cfg, err := store.Create(ctx, ConnectorConfig{Name: "IdemTest", ServerURL: "https://a.example"})
		if err != nil {
			t.Fatalf("create config: %v", err)
		}
		var iocID string
		if err := pool.QueryRow(ctx,
			`INSERT INTO iocs (type, value, source, origin, status) VALUES ('ip','203.0.113.9','threat_feed','threat-feed','reported') RETURNING id`,
		).Scan(&iocID); err != nil {
			t.Fatalf("seed ioc: %v", err)
		}
		modified := time.Now().UTC().Truncate(time.Second)

		has, err := store.HasIngested(ctx, cfg.ID, "indicator--abc", modified)
		if err != nil {
			t.Fatalf("HasIngested (before): %v", err)
		}
		if has {
			t.Fatal("HasIngested returned true before any RecordIngested call")
		}

		if err := store.RecordIngested(ctx, cfg.ID, "indicator--abc", modified, iocID); err != nil {
			t.Fatalf("RecordIngested: %v", err)
		}

		has, err = store.HasIngested(ctx, cfg.ID, "indicator--abc", modified)
		if err != nil {
			t.Fatalf("HasIngested (after): %v", err)
		}
		if !has {
			t.Fatal("HasIngested returned false after RecordIngested")
		}
	})
}
