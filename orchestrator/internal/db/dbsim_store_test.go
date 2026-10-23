package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
)

func dbsimRun(runID, result string) db.DBSimRun {
	return db.DBSimRun{ScenarioID: "DB-01", ScenarioVersion: "1", TargetID: "t1", Engine: "postgresql",
		RunID: runID, Result: result, Report: []byte(`{"result":"` + result + `"}`)}
}

func TestDBSimRunSchemaIdempotentSaveGetList(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		for i := 0; i < 2; i++ {
			if err := db.EnsureDBSimRunSchema(ctx, pool); err != nil {
				t.Fatal(err)
			}
		}
		id, err := db.SaveDBSimRun(ctx, pool, dbsimRun("r1", "FAIL"))
		if err != nil || id == "" {
			t.Fatalf("save %q %v", id, err)
		}
		if _, err := db.SaveDBSimRun(ctx, pool, dbsimRun("r1", "FAIL")); !errors.Is(err, db.ErrDBSimRunDuplicate) {
			t.Fatalf("dup: %v", err)
		}
		got, err := db.GetDBSimRun(ctx, pool, id)
		if err != nil || got.Result != "FAIL" || string(got.Report) == "" {
			t.Fatalf("get %+v %v", got, err)
		}
		l, err := db.ListDBSimRuns(ctx, pool, "DB-01", "t1", 10)
		if err != nil || len(l) != 1 {
			t.Fatalf("list %v %v", l, err)
		}
		if _, err := db.GetDBSimRun(ctx, pool, "nope"); !errors.Is(err, db.ErrDBSimRunNotFound) {
			t.Fatalf("notfound: %v", err)
		}
		if _, err := db.SaveDBSimRun(ctx, pool, dbsimRun("r2", "MAYBE")); !errors.Is(err, db.ErrDBSimRunInvalid) {
			t.Fatalf("invalid: %v", err)
		}
	})
}
