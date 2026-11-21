package mysql

import "testing"

// DB-04 (MySQL): the general log and the performance-schema history are not audit
// evidence. Coverage is covered only when an audit plugin is active AND its output
// is readable; otherwise at most partial.
func TestMySQLCoverageNeverCountsGeneralLogAsAudit(t *testing.T) {
	cases := []struct {
		name                                  string
		pluginActive, pluginReadable, logging bool
		want                                  string
	}{
		{"general log only is partial, not covered", false, false, true, "partial"},
		{"active plugin but unreadable is partial", true, false, true, "partial"},
		{"active and readable plugin is covered", true, true, true, "covered"},
		{"nothing logging is none", false, false, false, "none"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := mysqlAuditCoverage(c.pluginActive, c.pluginReadable, c.logging); got != c.want {
				t.Fatalf("mysqlAuditCoverage(%v,%v,%v) = %q, want %q", c.pluginActive, c.pluginReadable, c.logging, got, c.want)
			}
		})
	}
}
