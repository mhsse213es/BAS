package dbsim

import (
	"strings"
	"testing"
)

// Defence in depth: an audit event only counts when its statement BEGINS with
// the exact marker comment (after the log prefix) and is not a meta/lookup
// statement. A statement that merely mentions the marker does not.
func TestAuditEventMustBeginWithTheMarkerComment(t *testing.T) {
	c := "/* dbsim:bas-dbsim:abc123 */ "
	cases := map[string]struct {
		stmt string
		want bool
	}{
		"plain":            {c + "SELECT 1", true},
		"statement prefix": {"statement: " + c + "SELECT 1", true},
		"execute prefix":   {"execute S_1: " + c + "SELECT 1", true},
		"leading space":    {"  " + c + "SELECT 1", true},
		"mid statement":    {"SELECT '" + c + "'", false},
		"in where clause":  {"SELECT 1 WHERE x LIKE '%bas-dbsim:abc123%'", false},
		"comment second":   {"SELECT 1 " + c, false},
		"meta statement":   {c + "SELECT 1 /* dbsim:dbsim-meta */", false},
		"audit lookup":     {c + "SELECT * FROM dbsim_audit.pg_log", false},
		"general log":      {c + "SELECT argument FROM mysql.general_log", false},
	}
	for name, tc := range cases {
		o := auditOutcome(AuditFound, DBProbeAuditEvent{Time: t0, Statement: tc.stmt})
		_, rep := mustValid(t, auditMeta(), o)
		got := rep.Dimensions.Audit == DimPass
		if got != tc.want {
			t.Errorf("%s: audit pass=%v want %v", name, got, tc.want)
		}
		if !tc.want && !strings.Contains(rep.Record.Limitations, "no audit event carrying this run's marker") {
			t.Errorf("%s: missing downgrade limitation: %q", name, rep.Record.Limitations)
		}
	}
}
