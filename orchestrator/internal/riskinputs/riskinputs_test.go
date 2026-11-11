package riskinputs

import (
	"context"
	"errors"
	"flag"
	"os"
	"testing"

	"github.com/audspect/bas/internal/riskquant"
	"github.com/audspect/bas/internal/testutil"
	"github.com/jackc/pgx/v5/pgxpool"
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

func rng(l, m, h float64) *riskquant.Range { return &riskquant.Range{Low: l, Likely: m, High: h} }

func input(tech string, f, m *riskquant.Range) Input {
	return Input{TechniqueID: tech, Label: "test " + tech, Frequency: *f, Magnitude: *m}
}

// Each change writes one history row holding the previous and new values, and bumps the version.
func TestPutRecordsPreviousAndNewValues(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		tech := "T-RI-PUT-1"
		if _, err := Put(ctx, pool, input(tech, rng(1, 2, 4), rng(10, 20, 30)), "risk.owner@example.test"); err != nil {
			t.Fatal(err)
		}
		got, err := Put(ctx, pool, input(tech, rng(2, 3, 5), rng(10, 20, 30)), "risk.owner@example.test")
		if err != nil {
			t.Fatal(err)
		}
		if got.Version != 2 {
			t.Errorf("version = %d, want 2", got.Version)
		}
		h, err := History(ctx, pool, tech)
		if err != nil {
			t.Fatal(err)
		}
		if len(h) != 2 {
			t.Fatalf("history rows = %d, want 2", len(h))
		}
		if h[0].Previous != nil || h[0].Current == nil || h[0].Current.Frequency.Likely != 2 {
			t.Errorf("first entry should have no previous and current likely=2, got %+v", h[0])
		}
		if h[1].Previous == nil || h[1].Previous.Frequency.Likely != 2 || h[1].Current.Frequency.Likely != 3 {
			t.Errorf("second entry must reconstruct the prior value, got %+v", h[1])
		}
		if h[1].Actor != "risk.owner@example.test" {
			t.Errorf("actor = %q", h[1].Actor)
		}
	})
}

// A rejected write changes nothing: no row and no history.
func TestRejectedInputWritesNothing(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		tech := "T-RI-BAD-1"
		if _, err := Put(ctx, pool, input(tech, rng(-1, 1, 2), rng(10, 20, 30)), "owner"); err == nil {
			t.Fatal("negative frequency must be rejected")
		}
		if _, err := Put(ctx, pool, input(tech, rng(3, 2, 4), rng(10, 20, 30)), "owner"); err == nil {
			t.Fatal("unordered bounds must be rejected")
		}
		if list, _ := List(ctx, pool); containsTech(list, tech) {
			t.Error("a rejected input must not be stored")
		}
		if h, _ := History(ctx, pool, tech); len(h) != 0 {
			t.Errorf("a rejected input must leave no history, got %d rows", len(h))
		}
	})
}

// The database itself refuses bad values, even if the application layer is bypassed.
func TestDatabaseRejectsBadValuesDirectly(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		for name, q := range map[string]string{
			"negative":  `INSERT INTO risk_exposure_input (technique_id,freq_low,freq_likely,freq_high,mag_low,mag_likely,mag_high,updated_by) VALUES ('T-RI-DB-1',-1,1,2,1,1,1,'x')`,
			"nan":       `INSERT INTO risk_exposure_input (technique_id,freq_low,freq_likely,freq_high,mag_low,mag_likely,mag_high,updated_by) VALUES ('T-RI-DB-2','NaN',1,2,1,1,1,'x')`,
			"unordered": `INSERT INTO risk_exposure_input (technique_id,freq_low,freq_likely,freq_high,mag_low,mag_likely,mag_high,updated_by) VALUES ('T-RI-DB-3',3,2,4,1,1,1,'x')`,
		} {
			if _, err := pool.Exec(ctx, q); err == nil {
				t.Errorf("%s: database accepted the row", name)
			}
		}
	})
}

// Clearing an input removes it and records the value that was removed. Clearing a missing one is ErrNotFound.
func TestClearRemovesAndRecords(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		tech := "T-RI-CLR-1"
		if _, err := Put(ctx, pool, input(tech, rng(1, 1, 1), rng(5, 5, 5)), "owner"); err != nil {
			t.Fatal(err)
		}
		if err := Clear(ctx, pool, tech, "owner"); err != nil {
			t.Fatal(err)
		}
		if list, _ := List(ctx, pool); containsTech(list, tech) {
			t.Error("cleared input is still stored")
		}
		h, _ := History(ctx, pool, tech)
		if len(h) != 2 || h[1].Action != "clear" || h[1].Previous == nil || h[1].Previous.Magnitude.Likely != 5 {
			t.Errorf("clear must record the removed value, got %+v", h)
		}
		if err := Clear(ctx, pool, tech, "owner"); !errors.Is(err, ErrNotFound) {
			t.Errorf("clearing a missing input = %v, want ErrNotFound", err)
		}
	})
}

// Currency is never assumed: unset reads as empty, and only a valid ISO-style code is accepted.
func TestCurrencyIsExplicitAndValidated(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `DELETE FROM risk_settings`); err != nil {
			t.Fatal(err)
		}
		if c, err := Currency(ctx, pool); err != nil || c != "" {
			t.Fatalf("unset currency = %q, %v; want empty", c, err)
		}
		if _, err := SetCurrency(ctx, pool, "inr", "owner"); err == nil {
			t.Error("lower-case code must be rejected")
		}
		if _, err := SetCurrency(ctx, pool, "INRR", "owner"); err == nil {
			t.Error("four-letter code must be rejected")
		}
		if _, err := SetCurrency(ctx, pool, "INR", "owner"); err != nil {
			t.Fatal(err)
		}
		if c, _ := Currency(ctx, pool); c != "INR" {
			t.Errorf("currency = %q, want INR", c)
		}
	})
}

func containsTech(list []Input, tech string) bool {
	for _, in := range list {
		if in.TechniqueID == tech {
			return true
		}
	}
	return false
}
