package mysqlaudit

import (
	"context"
	"fmt"
	"io"

	"github.com/audspect/bas/internal/dbsim"
)

// Querier is the harness's own MySQL connection, used only for the fixed
// statements in this package. It is supplied by the lab harness, never by the agent.
type Querier interface {
	Query(ctx context.Context, sql string) ([][]string, error)
}

// PluginActive reports whether SHOW PLUGINS rows contain audit_log with status
// ACTIVE. Any other row, including general_log, does not count.
func PluginActive(rows [][]string) bool {
	for _, r := range rows {
		if len(r) >= 2 && r[0] == "audit_log" && r[1] == "ACTIVE" {
			return true
		}
	}
	return false
}

// CoverageVerdict is the MySQL audit-coverage rule. covered needs an active plugin
// and a readable audit file; an active plugin with an unreadable file is partial;
// no active plugin is none.
func CoverageVerdict(pluginActive bool, readErr error) string {
	switch {
	case pluginActive && readErr == nil:
		return "covered"
	case pluginActive:
		return "partial"
	}
	return "none"
}

// Collect is the harness's evidence collection. It issues exactly one fixed query
// (SHOW PLUGINS) and reads the audit file through open. It returns an error, and no
// coverage value, when the plugin state cannot be determined.
func Collect(ctx context.Context, q Querier, open func() (io.ReadCloser, error)) (dbsim.HarnessEvidence, error) {
	rows, err := q.Query(ctx, "SHOW PLUGINS")
	if err != nil {
		return dbsim.HarnessEvidence{}, fmt.Errorf("harness plugin check: %w", err)
	}
	active := PluginActive(rows)
	var readErr error
	if active {
		readErr = readable(open)
	}
	return dbsim.HarnessEvidence{AuditCoverage: CoverageVerdict(active, readErr)}, nil
}

// readable proves the audit file parses, not just that it opens.
func readable(open func() (io.ReadCloser, error)) error {
	rc, err := open()
	if err != nil {
		return err
	}
	defer rc.Close()
	_, err = ReadEvents(rc)
	return err
}
