//go:build dbsim_integration

package postgres

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"

	"audspect/agent/dbprobe"
)

// DBSIM_PG_DSN is space-separated key=value: host port dbname user password
// [tlsmode], pointing at a THROWAWAY lab database where the user may create
// schemas and roles.
func liveAdapter(t *testing.T, mode dbprobe.ExecMode) *Adapter {
	t.Helper()
	dsn := os.Getenv("DBSIM_PG_DSN")
	if dsn == "" {
		t.Skip("DBSIM_PG_DSN not set; skipping live PostgreSQL test")
	}
	cfg := dbprobe.ConnectionConfig{Engine: "postgresql", Mode: mode, TLSMode: "disable"}
	for _, kv := range strings.Fields(dsn) {
		k, v, _ := strings.Cut(kv, "=")
		switch k {
		case "host":
			cfg.Host = v
		case "port":
			cfg.Port, _ = strconv.Atoi(v)
		case "dbname":
			cfg.Database = v
		case "user":
			cfg.User = v
		case "password":
			cfg.Password = v
		case "tlsmode":
			cfg.TLSMode = v
		}
	}
	a := New()
	if err := a.Connect(context.Background(), cfg); err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { a.Close() })
	return a
}

func TestPGIdentityIsSystemIdentifier(t *testing.T) {
	a := liveAdapter(t, dbprobe.ModeLab)
	id, err := a.Identity(context.Background())
	if err != nil || id == "" {
		t.Fatalf("id=%q err=%v", id, err)
	}
	for _, c := range id {
		if c < '0' || c > '9' {
			t.Fatalf("system_identifier should be numeric: %q", id)
		}
	}
}

func TestPGReadGrantsReturnsSeededGrant(t *testing.T) {
	a := liveAdapter(t, dbprobe.ModeLab)
	ctx := context.Background()
	f := dbprobe.Fixture{ID: "it1", Kind: "pg_basic"}
	if err := a.Seed(ctx, f); err != nil {
		t.Fatal(err)
	}
	defer func() {
		r, err := a.Cleanup(ctx, f)
		if err != nil || len(r.Residual) != 0 {
			t.Errorf("cleanup: %+v %v", r, err)
		}
	}()
	gs, err := a.ReadGrants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range gs {
		if g.Role == "dbsim_it1_ro" && g.Object == "dbsim_it1.restricted" && g.Privilege == "SELECT" {
			return
		}
	}
	t.Fatalf("seeded grant not found in %v", gs)
}

func TestPGClientModeProbeRunsInReadOnlyTransaction(t *testing.T) {
	a := liveAdapter(t, dbprobe.ModeClient)
	ctx := context.Background()
	res, err := a.RunProbe(ctx, def("auth_check"), spec("auth_check", dbprobe.ModeClient, nil))
	if err != nil || res.Denied {
		t.Fatalf("%+v %v", res, err)
	}
	// Same connection, same begin statement: a write must fail with 25006.
	if err := a.s.Exec(ctx, beginStmt(dbprobe.ModeClient, dbprobe.ClassReadOnly)); err != nil {
		t.Fatal(err)
	}
	defer a.s.Exec(ctx, "ROLLBACK")
	err = a.s.Exec(ctx, "CREATE TEMP TABLE dbsim_ro_probe(x int)")
	if err == nil || !strings.Contains(err.Error(), "25006") {
		t.Fatalf("expected SQLSTATE 25006, got %v", err)
	}
}

func TestPGMarkerLandsInApplicationName(t *testing.T) {
	a := liveAdapter(t, dbprobe.ModeLab)
	ctx := context.Background()
	if err := a.s.Exec(ctx, "BEGIN READ ONLY"); err != nil {
		t.Fatal(err)
	}
	defer a.s.Exec(ctx, "ROLLBACK")
	if err := a.applyTxnSettings(ctx, spec("auth_check", dbprobe.ModeLab, nil)); err != nil {
		t.Fatal(err)
	}
	rows, err := a.s.Query(ctx, "SELECT current_setting('application_name')", 2)
	if err != nil || len(rows) != 1 || rows[0][0] != "dbsim-abc123" {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
}
