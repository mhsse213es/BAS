package mysqlaudit

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/dbsim"
)

var fxSince = time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)

const fxMarker = "dbsim:f-run1"

func fxQuery(user, sql string, status int, at time.Time) Record {
	return Record{Name: "Query", Time: at, ConnectionID: "9", User: user, SQLText: sql, Status: status}
}

func TestMarkedQueryPassesWhenEveryStatementIsAudited(t *testing.T) {
	recs := []Record{
		fxQuery(FixtureUser, "/* "+fxMarker+" */ FLUSH STATUS", 0, fxSince.Add(time.Second)),
	}
	if res, why := MarkedQueryVerdict(recs, fxMarker, FixtureUser, fxSince, []string{"FLUSH STATUS"}); res != dbsim.ResultPass {
		t.Fatalf("want PASS, got %s (%s)", res, why)
	}
}

func TestMarkedQueryFailsWhenOneStatementIsMissing(t *testing.T) {
	recs := []Record{
		fxQuery(FixtureUser, "/* "+fxMarker+" */ GRANT SELECT ON dbsim_audit_fixture.sensitive_synth TO 'dbsim_harness'@'%'", 0, fxSince.Add(time.Second)),
	}
	res, why := MarkedQueryVerdict(recs, fxMarker, FixtureUser, fxSince, []string{"GRANT SELECT", "REVOKE SELECT"})
	if res != dbsim.ResultFail {
		t.Fatalf("a missing REVOKE must FAIL, got %s (%s)", res, why)
	}
}

func TestMarkedQueryIgnoresFailedStatementsOtherUsersAndOldEvents(t *testing.T) {
	recs := []Record{
		fxQuery(FixtureUser, "/* "+fxMarker+" */ FLUSH STATUS", 1142, fxSince.Add(time.Second)),
		fxQuery("someone_else", "/* "+fxMarker+" */ FLUSH STATUS", 0, fxSince.Add(time.Second)),
		fxQuery(FixtureUser, "/* "+fxMarker+" */ FLUSH STATUS", 0, fxSince.Add(-time.Hour)),
	}
	if res, _ := MarkedQueryVerdict(recs, fxMarker, FixtureUser, fxSince, []string{"FLUSH STATUS"}); res != dbsim.ResultFail {
		t.Fatalf("a failed statement, another user, or an old event must not count, got %s", res)
	}
}

func TestFixtureRunIDIsSafeAndSpecific(t *testing.T) {
	m, err := fixtureMarker("run1")
	if err != nil || m != "dbsim:f-run1" {
		t.Fatalf("marker=%q err=%v", m, err)
	}
	for _, bad := range []string{"", "a-b", "a b", "a'b", "averyveryveryverylongrunidthatexceedsthelimit"} {
		if _, err := fixtureMarker(bad); err == nil {
			t.Errorf("run id %q must be refused", bad)
		}
	}
}

// MySQL drops the marker comment from some statements (GRANT is re-printed without it).
// The run is still attributable: a marked statement on the same connection proves the
// connection belongs to this run, and the unmarked statement is on that connection.
func TestUnmarkedGrantIsAttributedThroughItsMarkedConnection(t *testing.T) {
	recs := []Record{
		fxQueryOn(FixtureUser, "77", "GRANT SELECT ON `dbsim_audit_fixture`.`sensitive_synth` TO 'dbsim_harness'@'%'", 0, fxSince.Add(time.Second)),
		fxQueryOn(FixtureUser, "77", "/* "+fxMarker+" */ REVOKE SELECT ON dbsim_audit_fixture.sensitive_synth FROM 'dbsim_harness'@'%'", 0, fxSince.Add(2*time.Second)),
	}
	if res, why := MarkedQueryVerdict(recs, fxMarker, FixtureUser, fxSince, []string{"GRANT SELECT", "REVOKE SELECT"}); res != dbsim.ResultPass {
		t.Fatalf("want PASS, got %s (%s)", res, why)
	}
}

func TestUnmarkedStatementOnAnotherConnectionDoesNotCount(t *testing.T) {
	recs := []Record{
		fxQueryOn(FixtureUser, "12", "GRANT SELECT ON dbsim_audit_fixture.sensitive_synth TO 'dbsim_harness'@'%'", 0, fxSince.Add(time.Second)),
		fxQueryOn(FixtureUser, "77", "/* "+fxMarker+" */ REVOKE SELECT ON dbsim_audit_fixture.sensitive_synth FROM 'dbsim_harness'@'%'", 0, fxSince.Add(2*time.Second)),
	}
	if res, _ := MarkedQueryVerdict(recs, fxMarker, FixtureUser, fxSince, []string{"GRANT SELECT", "REVOKE SELECT"}); res != dbsim.ResultFail {
		t.Fatalf("a statement on a connection with no marked statement must not count, got %s", res)
	}
}

func fxQueryOn(user, conn, sql string, status int, at time.Time) Record {
	return Record{Name: "Query", Time: at, ConnectionID: conn, User: user, SQLText: sql, Status: status}
}
