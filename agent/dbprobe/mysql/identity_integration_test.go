//go:build dbsim_integration

package mysql

import (
	"context"
	"os"
	"strings"
	"testing"

	"audspect/agent/dbprobe"
)

// WRITTEN, NOT EXECUTED on the build host (no database). UNVERIFIED until run on
// staging against a THROWAWAY MySQL 8.x server (fix round 1, finding I3).
//
// Each case connects as a pre-provisioned account whose credentials come from
// DBSIM_MYSQL_ID_<CASE>="user:password" (same host/port/db/TLS as the DBSIM_MYSQL_*
// variables) and runs check_readonly_identity. The expected answer is that the
// false-PASS path is CLOSED. Provision as an administrator:
//
//	INACTIVEROLE  CREATE ROLE idw_writer; GRANT INSERT ON app.* TO idw_writer;
//	              CREATE USER id_inactive IDENTIFIED BY '...'; GRANT USAGE ON *.* TO id_inactive;
//	              GRANT idw_writer TO id_inactive;   (no SET DEFAULT ROLE: granted, not active)
//	              -> can_write must NOT be "no" (unknown)
//	GRANTOPTION   CREATE USER id_grant IDENTIFIED BY '...'; GRANT SELECT ON app.* TO id_grant WITH GRANT OPTION;
//	              -> can_admin=yes
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
	a := liveAdapter(t, dbprobe.ModeLab) // validates the DBSIM_MYSQL_* variables
	cfg := a.target
	a.Close()
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

func noteHas(notes []string, frag string) bool {
	for _, n := range notes {
		if strings.Contains(n, frag) {
			return true
		}
	}
	return false
}

func TestMySQLIdentityGrantedInactiveWriterRoleIsNotNoLive(t *testing.T) {
	res := runIdentityAs(t, "DBSIM_MYSQL_ID_INACTIVEROLE")
	if noteHas(res.Notes, "can_write=no") {
		t.Fatalf("a granted-but-inactive writer role must not be reported can_write=no: %v", res.Notes)
	}
}

func TestMySQLIdentityGrantOptionOnlyAccountIsAdminLive(t *testing.T) {
	res := runIdentityAs(t, "DBSIM_MYSQL_ID_GRANTOPTION")
	if !noteHas(res.Notes, "can_admin=yes") {
		t.Fatalf("WITH GRANT OPTION must report can_admin=yes: %v", res.Notes)
	}
}
