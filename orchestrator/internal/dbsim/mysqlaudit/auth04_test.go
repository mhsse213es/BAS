package mysqlaudit

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/dbsim"
)

var t04Since = time.Date(2026, 11, 20, 11, 0, 0, 0, time.UTC)

const t04User = "dbsim_nx_run1"

func t04Connect(user string, status int, at time.Time) Record {
	return Record{Name: "Connect", Time: at, ConnectionID: "77", User: user, Status: status}
}

func TestFailedLoginPassOnRefusedConnectForMarkerName(t *testing.T) {
	recs := []Record{t04Connect(t04User, 1045, t04Since.Add(time.Second))}
	if res, why := FailedLoginVerdict(recs, t04User, t04Since); res != dbsim.ResultPass {
		t.Fatalf("want PASS, got %s (%s)", res, why)
	}
}

func TestFailedLoginFailWhenTheLoginSucceeded(t *testing.T) {
	recs := []Record{t04Connect(t04User, 0, t04Since.Add(time.Second))}
	if res, _ := FailedLoginVerdict(recs, t04User, t04Since); res != dbsim.ResultFail {
		t.Fatalf("a successful connect is not a failed-login event, got %s", res)
	}
}

func TestFailedLoginFailWhenNoEventRecorded(t *testing.T) {
	if res, _ := FailedLoginVerdict(nil, t04User, t04Since); res != dbsim.ResultFail {
		t.Fatalf("want FAIL when the refused login is not audited, got %s", res)
	}
}

func TestFailedLoginIgnoresOtherNamesAndEarlierEvents(t *testing.T) {
	recs := []Record{
		t04Connect("someone_else", 1045, t04Since.Add(time.Second)),
		t04Connect(t04User, 1045, t04Since.Add(-time.Hour)),
	}
	if res, _ := FailedLoginVerdict(recs, t04User, t04Since); res != dbsim.ResultFail {
		t.Fatalf("other names and events before the run must not count, got %s", res)
	}
}

func TestFailedLoginNameIsRunSpecificAndSafe(t *testing.T) {
	n, err := failedLoginName("run1")
	if err != nil || n != "dbsim_nx_run1" {
		t.Fatalf("name=%q err=%v", n, err)
	}
	for _, bad := range []string{"", "a-b", "a b", "a'b", "averyveryveryverylongrunidthatexceedsthelimit"} {
		if _, err := failedLoginName(bad); err == nil {
			t.Errorf("run id %q must be refused", bad)
		}
	}
}
