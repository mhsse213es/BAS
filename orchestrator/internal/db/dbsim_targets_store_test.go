package db_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/dbsim/dbadmin"
)

func dbsimAudit(action string) dbadmin.AuditEntry {
	return dbadmin.AuditEntry{ActorID: "u1", Action: "dbsim.test_" + action, Resource: "dbsim-target:t1", Outcome: "ok"}
}

// failingAudit cannot be marshalled, so its audit insert fails inside the transaction.
func failingAudit() dbadmin.AuditEntry {
	e := dbsimAudit("fail")
	e.Detail = map[string]any{"bad": make(chan int)}
	return e
}

func dbsimTargetRec(t *testing.T, id string, mode dbsim.ExecMode) dbsim.TargetRecord {
	t.Helper()
	reg, err := dbsim.TargetRegistration{ID: id, Engine: "postgresql", Host: "db1.example.com", Port: 5432,
		CredentialRef: "dbcred:prod-pg-ro", ExpectedIdentity: "7312345678901234567", Mode: mode, AgentID: "0123456789abcdef"}.Normalize()
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
		if err := st.Create(ctx, rec, dbsimAudit("create")); err != nil {
			t.Fatal(err)
		}
		if err := st.Create(ctx, rec, dbsimAudit("create")); !errors.Is(err, dbsim.ErrTargetExists) {
			t.Fatalf("duplicate: %v", err)
		}
		got, err := st.Get(ctx, "t1")
		if err != nil || got.ExpectedIdentity != "7312345678901234567" || got.CredentialRef != "dbcred:prod-pg-ro" ||
			got.IdentityCheck.Checked || got.ToTarget().ReadOnlyIdentityVerified {
			t.Fatalf("get %+v %v", got, err)
		}
		got0 := got
		missingRec := got
		missingRec.ID = "missing"
		// A recorded pass verifies; a later failure withdraws it.
		at := time.Now().UTC().Truncate(time.Microsecond)
		if err := st.SaveIdentityCheck(ctx, got0, dbsim.IdentityCheckState{Checked: true, Passed: true, At: at, By: "u1"}, dbsimAudit("check")); err != nil {
			t.Fatal(err)
		}
		got, _ = st.Get(ctx, "t1")
		if !got.ToTarget().ReadOnlyIdentityVerified || got.IdentityCheck.By != "u1" {
			t.Fatalf("pass not stored: %+v", got.IdentityCheck)
		}
		if err := st.SaveIdentityCheck(ctx, got0, dbsim.IdentityCheckState{Checked: true, At: at, By: "u2", Reasons: []string{"identity can write data"}}, dbsimAudit("check")); err != nil {
			t.Fatal(err)
		}
		got, _ = st.Get(ctx, "t1")
		if got.ToTarget().ReadOnlyIdentityVerified || len(got.IdentityCheck.Reasons) != 1 {
			t.Fatalf("failure not stored: %+v", got.IdentityCheck)
		}
		if err := st.SaveIdentityCheck(ctx, missingRec, dbsim.IdentityCheckState{Checked: true, At: at}, dbsimAudit("check")); !errors.Is(err, dbsim.ErrTargetNotFound) {
			t.Fatalf("save missing: %v", err)
		}
		// A client target cannot be stored lab-confirmed (CHECK constraint, not just validation).
		bad := dbsimTargetRec(t, "t2", dbsim.ModeClient)
		bad.LabConfirmed = true
		if err := st.Create(ctx, bad, dbsimAudit("create")); err == nil {
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
		if err := st.Delete(ctx, "t1", dbsimAudit("delete")); err != nil {
			t.Fatal(err)
		}
		if err := st.Delete(ctx, "t1", dbsimAudit("delete")); !errors.Is(err, dbsim.ErrTargetNotFound) {
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
		if err := st.SetClientMode(ctx, true, "u1", dbsimAudit("mode")); err != nil {
			t.Fatal(err)
		}
		if v, found, err := st.GetClientMode(ctx); !dbsim.ClientModeFromSetting(v, found, err) {
			t.Fatalf("enabled not read back: %q %v %v", v, found, err)
		}
		if err := st.SetClientMode(ctx, false, "u1", dbsimAudit("mode")); err != nil {
			t.Fatal(err)
		}
		if v, found, err := st.GetClientMode(ctx); dbsim.ClientModeFromSetting(v, found, err) {
			t.Fatalf("disabled still on: %q %v %v", v, found, err)
		}
	})
}

// Needs the Docker-backed test database: written and compiled, run on a
// Docker-capable host. Covers fix-round findings I1 (atomic audit) and I4
// (binding to the record version).
func TestDBSimStoreMutationsAreAtomicWithAuditAndBoundToTheRecord(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureDBSimTargetSchema(ctx, pool); err != nil {
			t.Fatal(err)
		}
		st := db.DBSimTargetStore{Pool: pool}
		ss := db.DBSimSettingsStore{Pool: pool}
		rec := dbsimTargetRec(t, "t1", dbsim.ModeClient)

		// I1: a failing audit insert rolls the change back.
		if err := st.Create(ctx, rec, failingAudit()); err == nil {
			t.Fatal("create succeeded although its audit row failed")
		}
		if _, err := st.Get(ctx, "t1"); !errors.Is(err, dbsim.ErrTargetNotFound) {
			t.Fatalf("a target exists without its audit row: %v", err)
		}
		if err := st.Create(ctx, rec, dbsimAudit("create")); err != nil {
			t.Fatal(err)
		}
		if err := ss.SetClientMode(ctx, true, "u1", failingAudit()); err == nil {
			t.Fatal("setting changed although its audit row failed")
		}
		if v, found, err := ss.GetClientMode(ctx); dbsim.ClientModeFromSetting(v, found, err) {
			t.Fatal("client mode is on without its audit row")
		}
		at := time.Now().UTC().Truncate(time.Microsecond)
		pass := dbsim.IdentityCheckState{Checked: true, Passed: true, At: at, By: "u1"}
		cur, _ := st.Get(ctx, "t1")
		if err := st.SaveIdentityCheck(ctx, cur, pass, failingAudit()); err == nil {
			t.Fatal("check recorded although its audit row failed")
		}
		if got, _ := st.Get(ctx, "t1"); got.IdentityCheck.Checked {
			t.Fatal("a check result exists without its audit row")
		}
		if err := st.Delete(ctx, "t1", failingAudit()); err == nil {
			t.Fatal("delete succeeded although its audit row failed")
		}
		if _, err := st.Get(ctx, "t1"); err != nil {
			t.Fatalf("target vanished: %v", err)
		}

		// I4: delete + re-register the same id; the old version's pass is refused.
		if err := st.Delete(ctx, "t1", dbsimAudit("delete")); err != nil {
			t.Fatal(err)
		}
		again := rec
		again.CreatedAt = rec.CreatedAt.Add(time.Second)
		if err := st.Create(ctx, again, dbsimAudit("create")); err != nil {
			t.Fatal(err)
		}
		if err := st.SaveIdentityCheck(ctx, cur, pass, dbsimAudit("check")); !errors.Is(err, dbsim.ErrTargetChanged) {
			t.Fatalf("a pass for the old version was recorded: %v", err)
		}
		if got, _ := st.Get(ctx, "t1"); got.IdentityCheck.Checked {
			t.Fatal("the re-registered target inherited a pass")
		}
		// A stale pass does not verify through the resolver.
		fresh, _ := st.Get(ctx, "t1")
		if err := st.SaveIdentityCheck(ctx, fresh, dbsim.IdentityCheckState{Checked: true, Passed: true, At: at, By: "u1"}, dbsimAudit("check")); err != nil {
			t.Fatal(err)
		}
		res := db.DBSimTargetResolver{Store: st, Now: func() time.Time { return at.Add(23 * time.Hour) }}
		if tg, _ := res.Resolve(ctx, "t1"); !tg.ReadOnlyIdentityVerified {
			t.Fatal("a 23h-old pass must verify")
		}
		res.Now = func() time.Time { return at.Add(24 * time.Hour) }
		if tg, _ := res.Resolve(ctx, "t1"); tg.ReadOnlyIdentityVerified {
			t.Fatal("a pass exactly at the max age must not verify")
		}
	})
}

// Needs the Docker-backed test database (run on a Docker host). Fix round 2 I-1:
// a slower earlier check never overwrites a newer result, and its audit row rolls back.
func TestDBSimSaveIdentityCheckRefusesAnOlderResult(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureDBSimTargetSchema(ctx, pool); err != nil {
			t.Fatal(err)
		}
		st := db.DBSimTargetStore{Pool: pool}
		if err := st.Create(ctx, dbsimTargetRec(t, "t1", dbsim.ModeClient), dbsimAudit("create")); err != nil {
			t.Fatal(err)
		}
		cur, _ := st.Get(ctx, "t1")
		t2 := time.Now().UTC().Truncate(time.Microsecond)
		t1 := t2.Add(-time.Minute)
		if err := st.SaveIdentityCheck(ctx, cur, dbsim.IdentityCheckState{Checked: true, At: t2, By: "fail", Reasons: []string{"x"}}, dbsimAudit("check")); err != nil {
			t.Fatal(err)
		}
		slow := dbsimAudit("slow")
		slow.Action = "dbsim.test_slow_pass"
		err := st.SaveIdentityCheck(ctx, cur, dbsim.IdentityCheckState{Checked: true, Passed: true, At: t1, By: "slow"}, slow)
		if !errors.Is(err, dbsim.ErrIdentityCheckSuperseded) {
			t.Fatalf("want ErrIdentityCheckSuperseded, got %v", err)
		}
		got, _ := st.Get(ctx, "t1")
		if got.IdentityCheck.Passed || got.IdentityCheck.By != "fail" {
			t.Fatalf("the newer failure was overwritten: %+v", got.IdentityCheck)
		}
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'dbsim.test_slow_pass'`).Scan(&n); err != nil || n != 0 {
			t.Fatalf("the superseded check kept an audit row: n=%d err=%v", n, err)
		}
		// An equal timestamp is accepted (idempotent re-record); a changed version is ErrTargetChanged.
		if err := st.SaveIdentityCheck(ctx, cur, dbsim.IdentityCheckState{Checked: true, At: t2, By: "same"}, dbsimAudit("check")); err != nil {
			t.Fatalf("equal timestamp refused: %v", err)
		}
		other := cur
		other.CredentialRef = "dbcred:other"
		if err := st.SaveIdentityCheck(ctx, other, dbsim.IdentityCheckState{Checked: true, At: t2.Add(time.Hour)}, dbsimAudit("check")); !errors.Is(err, dbsim.ErrTargetChanged) {
			t.Fatalf("want ErrTargetChanged, got %v", err)
		}
	})
}

// Needs the Docker-backed test database: written and compiled, run on a
// Docker-capable host. Round-trips agent_id and proves the additive migration on
// a dbsim_targets table created before agent binding existed.
func TestDBSimTargetAgentBindingRoundTripAndMigration(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		// A pre-binding table (no agent_id column) holding one registered target.
		if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS dbsim_targets`); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `CREATE TABLE dbsim_targets (
			id text PRIMARY KEY, display_name text NOT NULL, engine text NOT NULL, host text NOT NULL, port integer NOT NULL,
			db_server_host text NOT NULL, database_name text NOT NULL DEFAULT '', tls_mode text NOT NULL DEFAULT '',
			credential_ref text NOT NULL, expected_identity text NOT NULL, mode text NOT NULL,
			lab_confirmed boolean NOT NULL DEFAULT false, created_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT NOW(),
			identity_check_passed boolean NOT NULL DEFAULT false, identity_check_at timestamptz,
			identity_check_by text NOT NULL DEFAULT '', identity_check_reasons jsonb NOT NULL DEFAULT '[]'::jsonb)`); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO dbsim_targets (id, display_name, engine, host, port, db_server_host,
			credential_ref, expected_identity, mode, created_by, identity_check_passed, identity_check_at)
			VALUES ('legacy','legacy','postgresql','db0.example.com',5432,'db0.example.com','dbcred:old','7001','client','u0',true,NOW())`); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ { // the migration is idempotent
			if err := db.EnsureDBSimTargetSchema(ctx, pool); err != nil {
				t.Fatal(err)
			}
		}
		st := db.DBSimTargetStore{Pool: pool}
		old, err := st.Get(ctx, "legacy")
		if err != nil || old.AgentID != "" {
			t.Fatalf("a legacy row must come back with no agent: %+v %v", old, err)
		}
		if old.ToTarget().ReadOnlyIdentityVerified || old.ToTarget().AgentID != "" {
			t.Fatal("a legacy row with a stored pass must fail closed (not eligible) until re-registered")
		}
		// New registrations round-trip agent_id, and the resolver maps it to the Target.
		rec := dbsimTargetRec(t, "t1", dbsim.ModeClient)
		if err := st.Create(ctx, rec, dbsimAudit("create")); err != nil {
			t.Fatal(err)
		}
		got, err := st.Get(ctx, "t1")
		if err != nil || got.AgentID != "0123456789abcdef" {
			t.Fatalf("agent_id not round-tripped: %+v %v", got, err)
		}
		list, err := st.List(ctx)
		if err != nil || len(list) != 2 {
			t.Fatalf("list: %+v %v", list, err)
		}
		tg, err := db.DBSimTargetResolver{Store: st}.Resolve(ctx, "t1")
		if err != nil || tg.AgentID != "0123456789abcdef" {
			t.Fatalf("resolver did not map the agent: %+v %v", tg, err)
		}
		// A check result is bound to the agent: a different agent is a changed version.
		other := got
		other.AgentID = "fedcba9876543210"
		if err := st.SaveIdentityCheck(ctx, other, dbsim.IdentityCheckState{Checked: true, Passed: true, At: time.Now().UTC()}, dbsimAudit("check")); !errors.Is(err, dbsim.ErrTargetChanged) {
			t.Fatalf("want ErrTargetChanged for another agent, got %v", err)
		}
		if err := st.SaveIdentityCheck(ctx, got, dbsim.IdentityCheckState{Checked: true, Passed: true, At: time.Now().UTC()}, dbsimAudit("check")); err != nil {
			t.Fatalf("same agent refused: %v", err)
		}
	})
}
