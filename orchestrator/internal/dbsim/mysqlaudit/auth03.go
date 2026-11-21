package mysqlaudit

import (
	"strings"
	"time"

	"github.com/audspect/bas/internal/dbsim"
)

// AuthEventVerdict grades test 03 from the audit records. PASS needs a Connect record
// for user on connection C inside the run window, and a Query record carrying the
// marker on the same connection C. Anything else is FAIL, because the audit trail
// was readable and the expected event is absent or not tied to this login.
func AuthEventVerdict(recs []Record, marker, user string, since time.Time) (dbsim.RunResult, string) {
	connects := map[string]bool{}
	for _, r := range recs {
		if r.Name == "Connect" && r.User == user && !r.Time.Before(since) {
			connects[r.ConnectionID] = true
		}
	}
	if len(connects) == 0 {
		return dbsim.ResultFail, "no Connect record for the harness user inside the run window"
	}
	for _, r := range recs {
		if r.Name == "Query" && connects[r.ConnectionID] && r.User == user && !r.Time.Before(since) && containsMarker(r.SQLText, marker) {
			return dbsim.ResultPass, "Connect and marked Query share connection " + r.ConnectionID
		}
	}
	return dbsim.ResultFail, "marked Query not found on the connection that authenticated"
}

func containsMarker(sql, marker string) bool {
	return marker != "" && strings.Contains(sql, marker)
}
