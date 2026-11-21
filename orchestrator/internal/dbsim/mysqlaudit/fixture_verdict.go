package mysqlaudit

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/audspect/bas/internal/dbsim"
)

// FixtureUser is the lab-only account for the privileged and DDL tests (05-08).
// Its grants are limited to the disposable schema, plus global RELOAD for test 05.
const FixtureUser = "dbsim_fixture"

var reFixtureRun = regexp.MustCompile(`^[A-Za-z0-9]{1,22}$`)

// fixtureMarker is the run-specific comment tag the fixture statements carry.
func fixtureMarker(runID string) (string, error) {
	if !reFixtureRun.MatchString(runID) {
		return "", fmt.Errorf("run id %q must be 1-22 letters or digits", runID)
	}
	return "dbsim:f-" + runID, nil
}

// MarkedQueryVerdict is the shared grade for tests 05-08. Every expected statement
// must appear as a successful Query record for user, carrying the marker, inside the
// run window. Any statement that is absent or was refused is FAIL, and the reason
// names it.
func MarkedQueryVerdict(recs []Record, marker, user string, since time.Time, want []string) (dbsim.RunResult, string) {
	marked := markedConnections(recs, marker, user, since)
	for _, text := range want {
		if !auditedStatement(recs, marked, user, since, text) {
			return dbsim.ResultFail, fmt.Sprintf("no successful statement for %s by %s on a marked connection inside the run window", text, user)
		}
	}
	return dbsim.ResultPass, fmt.Sprintf("all %d expected statements audited for %s", len(want), user)
}

// markedConnections returns the connection IDs that carry the run marker. MySQL can
// drop the marker comment from a statement (GRANT is re-printed without it), so a
// statement is attributed to the run through its connection, not its own text.
func markedConnections(recs []Record, marker, user string, since time.Time) map[string]bool {
	out := map[string]bool{}
	for _, r := range recs {
		if r.Name == "Query" && r.User == user && !r.Time.Before(since) && r.Status == 0 && strings.Contains(r.SQLText, marker) {
			out[r.ConnectionID] = true
		}
	}
	return out
}

func auditedStatement(recs []Record, marked map[string]bool, user string, since time.Time, text string) bool {
	wantText := strings.ToUpper(text)
	for _, r := range recs {
		if r.Name != "Query" || r.User != user || r.Time.Before(since) || r.Status != 0 || !marked[r.ConnectionID] {
			continue
		}
		if strings.Contains(strings.ToUpper(r.SQLText), wantText) {
			return true
		}
	}
	return false
}
