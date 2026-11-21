package mysqlaudit

import (
	"fmt"
	"regexp"
	"time"

	"github.com/audspect/bas/internal/dbsim"
)

var reFailName = regexp.MustCompile(`^[A-Za-z0-9]{1,22}$`)

// failedLoginName is a made-up account name that exists nowhere. It carries the run
// marker, so a refused connect for it is attributable to this run. No account is
// created, and no real credential is used.
func failedLoginName(runID string) (string, error) {
	if !reFailName.MatchString(runID) {
		return "", fmt.Errorf("run id %q must be 1-22 letters or digits", runID)
	}
	return "dbsim_nx_" + runID, nil
}

// FailedLoginVerdict grades test 04. PASS needs a Connect record for the marker name
// with a non-zero status (a refused login), inside the run window. A successful connect
// for that name is not a failed-login event, so it does not pass.
func FailedLoginVerdict(recs []Record, name string, since time.Time) (dbsim.RunResult, string) {
	for _, r := range recs {
		if r.Name == "Connect" && r.User == name && !r.Time.Before(since) && r.Status != 0 {
			return dbsim.ResultPass, fmt.Sprintf("refused Connect for %s with status %d", name, r.Status)
		}
	}
	return dbsim.ResultFail, "no refused Connect record for the marker account inside the run window"
}
