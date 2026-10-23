//go:build dbsim_integration

package postgres

import (
	"context"
	"os"
	"strings"
	"testing"

	"audspect/agent/dbprobe"
)

// WRITTEN, NOT EXECUTED on the build host (no database). UNVERIFIED until run on
// staging against a THROWAWAY PostgreSQL database (fix round 1, finding I2).
//
// Each case connects as a pre-provisioned account whose credentials come from
// DBSIM_PG_ID_<CASE>="user:password" (same host/port/db/TLS as DBSIM_PG_DSN) and
// runs check_readonly_identity. The expected answer is that the false-PASS path is
// CLOSED: the named capability is "yes". Provision as a superuser:
//
//	NOINHERIT       CREATE ROLE idw_writer NOLOGIN; GRANT INSERT ON app.t TO idw_writer;
//	                CREATE ROLE id_noinherit LOGIN NOINHERIT PASSWORD '...'; GRANT idw_writer TO id_noinherit;
//	                -> can_write=yes (SET ROLE idw_writer would let it write)
//	VIEW            CREATE VIEW app.v AS SELECT * FROM app.t; CREATE ROLE id_view LOGIN PASSWORD '...';
//	                GRANT INSERT ON app.v TO id_view;  -> can_write=yes
//	SERVERFILES     CREATE ROLE id_files LOGIN PASSWORD '...'; GRANT pg_write_server_files TO id_files;
//	                -> can_admin=yes
func runIdentityAs(t *testing.T, envName string) dbprobe.ProbeResult {
	t.Helper()
	cred := os.Getenv(envName)
	if cred == "" {
		t.Skipf("%s not set; skipping", envName)
	}
	user, pass, ok := strings.Cut(cred, ":")
	if !ok {
		t.Fatalf("%s must be user:password", envName)
	}
	a := liveAdapter(t, dbprobe.ModeLab) // validates DBSIM_PG_DSN; closed by cleanup
	a.Close()
	cfg := a.target
	cfg.User, cfg.Password = user, pass
	b := New()
	if err := b.Connect(context.Background(), cfg); err != nil {
		t.Fatalf("connect as %s: %v", user, err)
	}
	defer b.Close()
	res, err := b.RunProbe(context.Background(), def(dbprobe.ProbeCheckReadOnlyIdentity), spec(dbprobe.ProbeCheckReadOnlyIdentity, dbprobe.ModeLab, nil))
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	return res
}

func TestPGIdentityNoInheritMemberOfWriterRoleCanWriteLive(t *testing.T) {
	res := runIdentityAs(t, "DBSIM_PG_ID_NOINHERIT")
	if !noteHas(res.Notes, "can_write=yes") {
		t.Fatalf("a NOINHERIT member of a writer role must report can_write=yes: %v", res.Notes)
	}
}

func TestPGIdentityWriteGrantOnViewCanWriteLive(t *testing.T) {
	res := runIdentityAs(t, "DBSIM_PG_ID_VIEW")
	if !noteHas(res.Notes, "can_write=yes") {
		t.Fatalf("INSERT on a view must report can_write=yes: %v", res.Notes)
	}
}

func TestPGIdentityPredefinedServerFilesRoleIsAdminLive(t *testing.T) {
	res := runIdentityAs(t, "DBSIM_PG_ID_SERVERFILES")
	if !noteHas(res.Notes, "can_admin=yes") {
		t.Fatalf("pg_write_server_files must report can_admin=yes: %v", res.Notes)
	}
}

func noteHas(notes []string, frag string) bool {
	for _, n := range notes {
		if strings.Contains(n, frag) {
			return true
		}
	}
	return false
}
