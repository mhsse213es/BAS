package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
)

// Expectations, written before the cases run: the schema is idempotent; a saved run lists back with its
// outcome; a second save of the same tag and build is refused; invalid input never reaches the database.
func TestAPIBASRunSchemaIdempotent(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		for i := 0; i < 2; i++ {
			if err := db.EnsureAPIBASRunSchema(ctx, pool); err != nil {
				t.Fatalf("ensure #%d: %v", i+1, err)
			}
		}
	})
}

func apibasRun(tag, build string) db.APIBASRun {
	return db.APIBASRun{
		RunTag: tag, ScenarioID: "API-BAS-AUTHZ-001", Build: build,
		Result: "FAIL", Exploitability: "exploited", Detection: "detected",
		Report: []byte(`{"ScenarioID":"API-BAS-AUTHZ-001","RunTag":"` + tag + `"}`),
	}
}

func TestAPIBASRunSaveAndList(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureAPIBASRunSchema(ctx, pool); err != nil {
			t.Fatal(err)
		}
		id, err := db.SaveAPIBASRun(ctx, pool, apibasRun("run-1", "vulnerable"))
		if err != nil || id == "" {
			t.Fatalf("save: id=%q err=%v", id, err)
		}
		runs, err := db.ListAPIBASRuns(ctx, pool, "API-BAS-AUTHZ-001", 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(runs) != 1 || runs[0].RunTag != "run-1" || runs[0].Result != "FAIL" || runs[0].Exploitability != "exploited" {
			t.Fatalf("listed %+v, want the saved run with FAIL/exploited", runs)
		}
	})
}

func TestAPIBASRunDuplicateTagAndBuildRefused(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureAPIBASRunSchema(ctx, pool); err != nil {
			t.Fatal(err)
		}
		if _, err := db.SaveAPIBASRun(ctx, pool, apibasRun("run-dup", "fixed")); err != nil {
			t.Fatal(err)
		}
		if _, err := db.SaveAPIBASRun(ctx, pool, apibasRun("run-dup", "fixed")); !errors.Is(err, db.ErrAPIBASRunDuplicate) {
			t.Fatalf("duplicate save err = %v, want ErrAPIBASRunDuplicate", err)
		}
		// The same tag with the other build is a different record.
		if _, err := db.SaveAPIBASRun(ctx, pool, apibasRun("run-dup", "vulnerable")); err != nil {
			t.Fatalf("other build save: %v", err)
		}
	})
}

func TestAPIBASRunInvalidInputRefused(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureAPIBASRunSchema(ctx, pool); err != nil {
			t.Fatal(err)
		}
		bad := map[string]func(r *db.APIBASRun){
			"empty tag":      func(r *db.APIBASRun) { r.RunTag = "" },
			"unknown build":  func(r *db.APIBASRun) { r.Build = "staging" },
			"unknown result": func(r *db.APIBASRun) { r.Result = "MAYBE" },
			"invalid json":   func(r *db.APIBASRun) { r.Report = []byte(`{not json`) },
		}
		for name, mutate := range bad {
			r := apibasRun("run-bad-"+name[:4], "vulnerable")
			mutate(&r)
			if _, err := db.SaveAPIBASRun(ctx, pool, r); !errors.Is(err, db.ErrAPIBASRunInvalid) {
				t.Fatalf("%s: err = %v, want ErrAPIBASRunInvalid", name, err)
			}
		}
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM apibas_runs WHERE run_tag LIKE 'run-bad-%'`).Scan(&n); err != nil || n != 0 {
			t.Fatalf("invalid runs reached the table: n=%d err=%v", n, err)
		}
	})
}
