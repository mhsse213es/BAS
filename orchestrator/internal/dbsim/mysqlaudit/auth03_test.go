package mysqlaudit

import (
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/dbsim"
)

var t03Since = time.Date(2026, 11, 20, 11, 0, 0, 0, time.UTC)

func t03Connect(conn, user string, at time.Time) Record {
	return Record{Name: "Connect", Time: at, ConnectionID: conn, User: user}
}

func t03Query(conn, user, sql string, at time.Time) Record {
	return Record{Name: "Query", Time: at, ConnectionID: conn, User: user, SQLText: sql}
}

const t03Marker = "dbsim:auth-run-abc"

func TestAuthEventPassWhenConnectAndMarkedQueryShareConnection(t *testing.T) {
	recs := []Record{
		t03Connect("43", HarnessUser, t03Since.Add(time.Second)),
		t03Query("43", HarnessUser, "SELECT /* "+t03Marker+" */ CONNECTION_ID()", t03Since.Add(2*time.Second)),
	}
	res, why := AuthEventVerdict(recs, t03Marker, HarnessUser, t03Since)
	if res != dbsim.ResultPass {
		t.Fatalf("want PASS, got %s (%s)", res, why)
	}
}

func TestAuthEventFailWhenMarkedQueryIsOnAnotherConnection(t *testing.T) {
	recs := []Record{
		t03Connect("43", HarnessUser, t03Since.Add(time.Second)),
		t03Query("99", HarnessUser, "SELECT /* "+t03Marker+" */ CONNECTION_ID()", t03Since.Add(2*time.Second)),
	}
	if res, why := AuthEventVerdict(recs, t03Marker, HarnessUser, t03Since); res != dbsim.ResultFail {
		t.Fatalf("want FAIL (identity not tied to the connection), got %s (%s)", res, why)
	}
}

func TestAuthEventFailWhenConnectEventIsMissing(t *testing.T) {
	recs := []Record{
		t03Query("43", HarnessUser, "SELECT /* "+t03Marker+" */ CONNECTION_ID()", t03Since.Add(2*time.Second)),
	}
	if res, why := AuthEventVerdict(recs, t03Marker, HarnessUser, t03Since); res != dbsim.ResultFail {
		t.Fatalf("want FAIL (authentication event missing), got %s (%s)", res, why)
	}
}

func TestAuthEventIgnoresOtherUsersAndEventsBeforeTheRun(t *testing.T) {
	recs := []Record{
		t03Connect("43", "someone_else", t03Since.Add(time.Second)),
		t03Connect("43", HarnessUser, t03Since.Add(-time.Hour)),
		t03Query("43", HarnessUser, "SELECT /* "+t03Marker+" */ CONNECTION_ID()", t03Since.Add(2*time.Second)),
	}
	if res, _ := AuthEventVerdict(recs, t03Marker, HarnessUser, t03Since); res != dbsim.ResultFail {
		t.Fatalf("a Connect for another user or before the run must not count, got %s", res)
	}
}

func TestParseRecordsKeepsConnectAndQuery(t *testing.T) {
	const connect = `{"audit_record":{"name":"Connect","timestamp":"2026-11-20T11:00:00Z","connection_id":"43","status":0,"user":"dbsim_harness","priv_user":"dbsim_harness","ip":"172.17.0.1","db":""}}`
	recs, err := ParseRecords(strings.NewReader(connect + "\n" + queryLine + "\n"))
	if err != nil {
		t.Fatalf("ParseRecords: %v", err)
	}
	if len(recs) != 2 || recs[0].Name != "Connect" || recs[0].ConnectionID != "43" || recs[0].User != HarnessUser {
		t.Fatalf("records = %+v", recs)
	}
}
