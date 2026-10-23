package mysql

import (
	"context"
	"errors"
	"strings"
	"testing"

	"audspect/agent/dbprobe"
)

// Fix round 1, I3. NEVER run against a real MySQL server: fake-session tests only.
// The semantics are UNVERIFIED until the dbsim_integration tests run on staging.

func runIdent(t *testing.T, ans map[string]func() ([][]any, error)) (dbprobe.ProbeResult, *fakeSession) {
	t.Helper()
	a, f := identAdapter(dbprobe.ModeClient, ans)
	res, err := a.RunProbe(context.Background(), def(dbprobe.ProbeCheckReadOnlyIdentity), identSpec(dbprobe.ModeClient))
	if err != nil {
		t.Fatal(err)
	}
	return res, f
}

const allUnknownNote = "identity_checks=can_write=unknown,can_ddl=unknown,can_admin=unknown,can_audit=unknown"

// (a) a granted-but-inactive role can be activated with SET ROLE.
func TestIdentityGrantedInactiveRoleFailsClosed(t *testing.T) {
	ans := identAnswers([]byte("NONE"), "G||USAGE", "S|app|SELECT")
	ans["APPLICABLE_ROLES"] = func() ([][]any, error) { return [][]any{{[]byte("`writer`@`%`")}}, nil }
	res, _ := runIdent(t, ans)
	if res.ErrorClass != "identity_check_incomplete" || !hasNote(res.Notes, allUnknownNote) {
		t.Fatalf("a granted inactive role must make every 'no' unknown: %+v %v", res, res.Notes)
	}
	// A definite finding from the direct privileges survives.
	ans = identAnswers([]byte("NONE"), "G||USAGE", "S|app|INSERT")
	ans["APPLICABLE_ROLES"] = func() ([][]any, error) { return [][]any{{[]byte("`r`@`%`")}}, nil }
	res, _ = runIdent(t, ans)
	if !hasNote(res.Notes, "identity_checks=can_write=yes,can_ddl=unknown,can_admin=unknown,can_audit=unknown") {
		t.Fatalf("%v", res.Notes)
	}
}

func TestIdentityApplicableRolesErrorsAreHandledNarrowly(t *testing.T) {
	// 5.7: neither CURRENT_ROLE() (1305) nor APPLICABLE_ROLES (1109) exists: no roles, usable.
	ans := identAnswers([]byte("NONE"), "G||USAGE", "S|app|SELECT")
	ans["CURRENT_ROLE"] = func() ([][]any, error) { return nil, myErr(1305, "FUNCTION CURRENT_ROLE does not exist") }
	ans["APPLICABLE_ROLES"] = func() ([][]any, error) {
		return nil, myErr(1109, "Unknown table 'APPLICABLE_ROLES' in information_schema")
	}
	res, _ := runIdent(t, ans)
	if res.ErrorClass != "" || !hasNote(res.Notes, "identity_checks=can_write=no,can_ddl=no,can_admin=no,can_audit=no") {
		t.Fatalf("5.7: %+v %v", res, res.Notes)
	}
	// Any other error reading APPLICABLE_ROLES is unknown, never 'no roles'.
	for _, e := range []error{myErr(1227, "denied"), myErr(1142, "denied"), myErr(2013, "lost"), nil} {
		ans := identAnswers([]byte("NONE"), "G||USAGE", "S|app|SELECT")
		err := e
		ans["APPLICABLE_ROLES"] = func() ([][]any, error) {
			if err == nil {
				return nil, errors.New("transport")
			}
			return nil, err
		}
		res, _ := runIdent(t, ans)
		if res.ErrorClass != "identity_check_incomplete" || !hasNote(res.Notes, allUnknownNote) {
			t.Fatalf("error %v read as 'no roles': %+v %v", e, res, res.Notes)
		}
	}
	// 1109 with a working CURRENT_ROLE() is incoherent (8.0 has both): still tolerated only on the
	// documented error code, so the table being absent is read as no roles ONLY via 1109.
	ans = identAnswers([]byte("NONE"), "G||USAGE", "S|app|SELECT")
	ans["APPLICABLE_ROLES"] = func() ([][]any, error) { return nil, myErr(1109, "Unknown table") }
	if res, _ := runIdent(t, ans); res.ErrorClass != "" {
		t.Fatalf("1109 is the documented 'no table' error: %+v", res)
	}
}

// (b) GRANT OPTION is IS_GRANTABLE=YES on another row, not a PRIVILEGE_TYPE.
func TestIdentityGrantOptionOnlyAccountIsAdmin(t *testing.T) {
	res, f := runIdent(t, identAnswers([]byte("NONE"), "G||USAGE", "S|app|SELECT|YES"))
	if !hasNote(res.Notes, "identity_checks=can_write=no,can_ddl=no,can_admin=yes,can_audit=no") {
		t.Fatalf("%v", res.Notes)
	}
	joined := ""
	for _, c := range f.calls {
		joined += c.sql + "\n"
	}
	if strings.Count(joined, "IS_GRANTABLE") < 4 {
		t.Fatalf("every scope must select IS_GRANTABLE: %s", joined)
	}
	if !strings.Contains(joined, "information_schema.APPLICABLE_ROLES") {
		t.Fatal("APPLICABLE_ROLES is not queried")
	}
}

// (c) EXECUTE can run a SECURITY DEFINER routine.
func TestIdentityExecuteMakesWriteUnknown(t *testing.T) {
	res, _ := runIdent(t, identAnswers([]byte("NONE"), "G||USAGE", "S|app|EXECUTE"))
	if res.ErrorClass != "identity_check_incomplete" || !hasNote(res.Notes, "identity_checks=can_write=unknown,can_ddl=no,can_admin=no,can_audit=no") {
		t.Fatalf("%+v %v", res, res.Notes)
	}
}
