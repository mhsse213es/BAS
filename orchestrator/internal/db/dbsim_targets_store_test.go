package db_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/dbsim"
)

func dbsimTargetRec(t *testing.T, id string, mode dbsim.ExecMode) dbsim.TargetRecord {
	t.Helper()
	reg, err := dbsim.TargetRegistration{ID: id, Engine: "postgresql", Host: "db1.example.com", Port: 5432,
		CredentialRef: "dbcred:prod-pg-ro", ExpectedIdentity: "7312345678901234567", Mode: mode}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	return dbsim.TargetRecord{TargetRegistration: reg, CreatedBy: "u1", CreatedAt: time.Now().UTC().Truncate(time.Microsecond)}
}

// Needs the Docker-backed test database (TestMain of this package): written and
// compiled, run on a Docker-capable host.
func TestDBSimTargetRegistryStore(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		for i := 0; i < 2; i++ { // idempotent
			if err := db.EnsureDBSimTargetSchema(ctx, pool); err != nil {
				t.Fatal(err)
			}
		}
		st := db.DBSimTargetStore{Pool: pool}
		rec := dbsimTargetRec(t, "t1", dbsim.ModeClient)
		if err := st.Create(ctx, rec); err != nil {
			t.Fatal(err)
		}
		if err := st.Create(ctx, rec); !errors.Is(err, dbsim.ErrTargetExists) {
			t.Fatalf("duplicate: %v", err)
		}
		got, err := st.Get(ctx, "t1")
		if err != nil || got.ExpectedIdentity != "7312345678901234567" || got.CredentialRef != "dbcred:prod-pg-ro" ||
			got.IdentityCheck.Checked || got.ToTarget().ReadOnlyIdentityVerified {
			t.Fatalf("get %+v %v", got, err)
		}
		// A recorded pass verifies; a later failure withdraws it.
		at := time.Now().UTC().Truncate(time.Microsecond)
		if err := st.SaveIdentityCheck(ctx, "t1", dbsim.IdentityCheckState{Checked: true, Passed: true, At: at, By: "u1"}); err != nil {
			t.Fatal(err)
		}
		got, _ = st.Get(ctx, "t1")
		if !got.ToTarget().ReadOnlyIdentityVerified || got.IdentityCheck.By != "u1" {
			t.Fatalf("pass not stored: %+v", got.IdentityCheck)
		}
		if err := st.SaveIdentityCheck(ctx, "t1", dbsim.IdentityCheckState{Checked: true, At: at, By: "u2", Reasons: []string{"identity can write data"}}); err != nil {
			t.Fatal(err)
		}
		got, _ = st.Get(ctx, "t1")
		if got.ToTarget().ReadOnlyIdentityVerified || len(got.IdentityCheck.Reasons) != 1 {
			t.Fatalf("failure not stored: %+v", got.IdentityCheck)
		}
		if err := st.SaveIdentityCheck(ctx, "missing", dbsim.IdentityCheckState{Checked: true, At: at}); !errors.Is(err, dbsim.ErrTargetNotFound) {
			t.Fatalf("save missing: %v", err)
		}
		// A client target cannot be stored lab-confirmed (CHECK constraint, not just validation).
		bad := dbsimTargetRec(t, "t2", dbsim.ModeClient)
		bad.LabConfirmed = true
		if err := st.Create(ctx, bad); err == nil {
			t.Fatal("client + lab_confirmed stored")
		}
		l, err := st.List(ctx)
		if err != nil || len(l) != 1 {
			t.Fatalf("list %v %v", l, err)
		}
		res := db.DBSimTargetResolver{Store: st}
		if tg, err := res.Resolve(ctx, "t1"); err != nil || tg.ID != "t1" {
			t.Fatalf("resolve %+v %v", tg, err)
		}
		if _, err := res.Resolve(ctx, "nope"); !errors.Is(err, dbsim.ErrTargetNotFound) {
			t.Fatalf("resolve missing: %v", err)
		}
		if err := st.Delete(ctx, "t1"); err != nil {
			t.Fatal(err)
		}
		if err := st.Delete(ctx, "t1"); !errors.Is(err, dbsim.ErrTargetNotFound) {
			t.Fatalf("delete missing: %v", err)
		}
	})
}

func TestDBSimClientModeSettingStore(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureDBSimTargetSchema(ctx, pool); err != nil {
			t.Fatal(err)
		}
		st := db.DBSimSettingsStore{Pool: pool}
		if v, found, err := st.GetClientMode(ctx); err != nil || found || dbsim.ClientModeFromSetting(v, found, err) {
			t.Fatalf("default must be unset/OFF: %q %v %v", v, found, err)
		}
		if err := st.SetClientMode(ctx, true, "u1"); err != nil {
			t.Fatal(err)
		}
		if v, found, err := st.GetClientMode(ctx); !dbsim.ClientModeFromSetting(v, found, err) {
			t.Fatalf("enabled not read back: %q %v %v", v, found, err)
		}
		if err := st.SetClientMode(ctx, false, "u1"); err != nil {
			t.Fatal(err)
		}
		if v, found, err := st.GetClientMode(ctx); dbsim.ClientModeFromSetting(v, found, err) {
			t.Fatalf("disabled still on: %q %v %v", v, found, err)
		}
	})
}
