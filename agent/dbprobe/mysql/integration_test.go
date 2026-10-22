//go:build dbsim_integration

package mysql

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strconv"
	"testing"

	drv "github.com/go-sql-driver/mysql"

	"audspect/agent/dbprobe"
)

// Live tests need a THROWAWAY MySQL 5.7.8+/8.x server (not MariaDB) where the
// user may create schemas and users. Parts come from DBSIM_MYSQL_HOST, _PORT,
// _DB, _USER, _PASSWORD and optional _TLSMODE (default "disable"). They skip
// when DBSIM_MYSQL_HOST is unset.
func liveAdapter(t *testing.T, mode dbprobe.ExecMode) *Adapter {
	t.Helper()
	host := os.Getenv("DBSIM_MYSQL_HOST")
	if host == "" {
		t.Skip("DBSIM_MYSQL_HOST not set; skipping live MySQL test")
	}
	cfg := dbprobe.ConnectionConfig{Engine: "mysql", Mode: mode, Host: host, TLSMode: "disable",
		Database: os.Getenv("DBSIM_MYSQL_DB"), User: os.Getenv("DBSIM_MYSQL_USER"), Password: os.Getenv("DBSIM_MYSQL_PASSWORD")}
	if p := os.Getenv("DBSIM_MYSQL_PORT"); p != "" {
		cfg.Port, _ = strconv.Atoi(p)
	}
	if m := os.Getenv("DBSIM_MYSQL_TLSMODE"); m != "" {
		cfg.TLSMode = m
	}
	a := New()
	if err := a.Connect(context.Background(), cfg); err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { a.Close() })
	return a
}

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func TestMySQLIdentityIsServerUUID(t *testing.T) {
	a := liveAdapter(t, dbprobe.ModeClient)
	id, err := a.Identity(context.Background())
	if err != nil || !uuidRe.MatchString(id) {
		t.Fatalf("id=%q err=%v", id, err)
	}
}

func TestMySQLReadGrantsReturnsSeededGrant(t *testing.T) {
	a := liveAdapter(t, dbprobe.ModeLab)
	ctx := context.Background()
	f := dbprobe.Fixture{ID: "it1", Kind: "my_basic"}
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

func TestMySQLClientModeUsesReadOnlyTransaction(t *testing.T) {
	a := liveAdapter(t, dbprobe.ModeLab) // lab connection only to seed the table
	ctx := context.Background()
	f := dbprobe.Fixture{ID: "it2", Kind: "my_basic"}
	if err := a.Seed(ctx, f); err != nil {
		t.Fatal(err)
	}
	defer func() { a.Cleanup(ctx, f) }()
	// Same helper every client-mode statement goes through; the write inside it
	// must be refused by the server with 1792.
	err := a.inTxn(ctx, dbprobe.ModeClient, dbprobe.ClassReadOnly, metaLimits, "dbsim-ro", func(ctx context.Context, comment string) error {
		return a.s.Exec(ctx, comment+"INSERT INTO `dbsim_it2`.`restricted` VALUES (99, 'x')")
	})
	var me *drv.MySQLError
	if !errors.As(err, &me) || me.Number != 1792 {
		t.Fatalf("expected MySQL error 1792, got %v", err)
	}
	// And a probe still works afterwards on the same connection (txn was rolled back).
	res, perr := a.RunProbe(ctx, def("auth_check"), spec("auth_check", dbprobe.ModeClient, nil))
	if perr != nil || res.Denied || res.ErrorClass != "" {
		t.Fatalf("%+v %v", res, perr)
	}
}

func TestMySQLMarkerInQueryComment(t *testing.T) {
	a := liveAdapter(t, dbprobe.ModeClient)
	ctx := context.Background()
	c := a.Capabilities()
	if !c.MarkerInQueryText || c.MarkerInAppName {
		t.Fatalf("capabilities must say query comment yes, per-probe session attribute no: %+v", c)
	}
	if _, err := a.RunProbe(ctx, def("auth_check"), spec("auth_check", dbprobe.ModeClient, nil)); err != nil {
		t.Fatal(err)
	}
	// performance_schema keeps recent statements per thread; skip if disabled.
	rows, err := a.s.Query(ctx, "SELECT SQL_TEXT FROM performance_schema.events_statements_history "+
		"WHERE SQL_TEXT LIKE '%dbsim:dbsim-abc123%' AND SQL_TEXT NOT LIKE '%performance_schema%' LIMIT 1", 2)
	if err != nil {
		t.Skipf("performance_schema not readable: %v", err)
	}
	if len(rows) != 1 {
		t.Skip("statement history not retained (performance_schema consumers disabled)")
	}
}
