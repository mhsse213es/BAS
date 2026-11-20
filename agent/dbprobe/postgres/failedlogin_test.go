package postgres

import (
	"context"
	"strings"
	"testing"

	"audspect/agent/dbprobe"
)

func failedLoginSpec() dbprobe.DBProbeSpec {
	s := spec(dbprobe.ProbeAuthFailedLogin, dbprobe.ModeLab, nil)
	s.FixtureID = "empty"
	return s
}

// DB-04-04: a login with a wrong password for a throwaway account is refused
// by the server (28P01) and reported as a denial the audit trail must record.
func TestAuthFailedLoginRefusedWithWrongPassword(t *testing.T) {
	d := &dialScript{}
	d.steps = []func() (session, error){failWith(pgErr("28P01", `password authentication failed for user "dbsim_abc123def456_acct"`))}
	a, admin := revokeAdapter(t, d)
	res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeAuthFailedLogin), failedLoginSpec())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Denied || res.ErrorClass != "auth_failed" {
		t.Fatalf("a refused wrong-password login is Denied/auth_failed: %+v", res)
	}
	create, ok := findPrefix(admin, `CREATE ROLE "`+revokeAcct+`" LOGIN PASSWORD '`)
	if !ok {
		t.Fatalf("no throwaway CREATE ROLE: %v", execSQL(admin))
	}
	if len(d.pws) != 1 || d.users[0] != revokeAcct {
		t.Fatalf("one login attempt, as the throwaway account: users=%v", d.users)
	}
	if strings.Contains(create, "PASSWORD '"+d.pws[0]+"'") {
		t.Fatal("the attempt must use a wrong password, not the account's real one")
	}
}

// If the server accepts the wrong password, that is a finding, never a denial.
func TestAuthFailedLoginAcceptedIsFinding(t *testing.T) {
	d := &dialScript{}
	d.steps = []func() (session, error){d.okSession(clockQuery)}
	a, _ := revokeAdapter(t, d)
	res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeAuthFailedLogin), failedLoginSpec())
	if err != nil {
		t.Fatal(err)
	}
	if res.Denied || res.ErrorClass != "login_allowed" {
		t.Fatalf("an accepted wrong-password login must be login_allowed, not denied: %+v", res)
	}
}
