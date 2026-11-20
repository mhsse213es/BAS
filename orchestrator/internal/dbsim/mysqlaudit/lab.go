package mysqlaudit

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/audspect/bas/internal/dbsim"
)

// LabConfig names the lab-host inputs for the harness evidence. None of them come
// from the agent.
type LabConfig struct {
	PasswordFile string // harness-owned, mode 600
	Addr         string // host:port of the lab MySQL, e.g. 127.0.0.1:53306
	AuditFile    string // the Percona audit_log file on the lab host
}

// Evidence is the harness's reading of the lab MySQL audit plugin. It opens the
// harness connection, runs Collect, and closes the connection. Any failure returns
// an error and no verdict.
func Evidence(ctx context.Context, cfg LabConfig) (dbsim.HarnessEvidence, error) {
	dsn, err := DSNFromFile(cfg.PasswordFile, cfg.Addr)
	if err != nil {
		return dbsim.HarnessEvidence{}, err
	}
	q, err := OpenSQLQuerier(dsn)
	if err != nil {
		return dbsim.HarnessEvidence{}, err
	}
	defer q.DB.Close()
	open := func() (io.ReadCloser, error) {
		f, err := os.Open(cfg.AuditFile)
		if err != nil {
			return nil, fmt.Errorf("audit file: %w", err)
		}
		return f, nil
	}
	return Collect(ctx, q, open)
}
