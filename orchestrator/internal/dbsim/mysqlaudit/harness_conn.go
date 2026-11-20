package mysqlaudit

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"

	"github.com/go-sql-driver/mysql"
)

// HarnessUser is the least-privilege lab account. It has no grants beyond login.
const HarnessUser = "dbsim_harness"

// DSNFromFile reads the harness password from a file the harness owns. The file
// must not be readable by group or others. The DSN is built with the driver's own
// config, so the password is never hand-concatenated.
func DSNFromFile(path, addr string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("harness password file: %w", err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("harness password file %s is readable by group or others (mode %v); chmod 600 it", path, fi.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("harness password file: %w", err)
	}
	cfg := mysql.NewConfig()
	cfg.User = HarnessUser
	cfg.Passwd = strings.TrimSpace(string(raw))
	cfg.Net = "tcp"
	cfg.Addr = addr
	return cfg.FormatDSN(), nil
}

// SQLQuerier runs the harness's own fixed statements. It accepts only SHOW PLUGINS.
type SQLQuerier struct{ DB *sql.DB }

// OpenSQLQuerier opens the harness connection. Nothing is queried here.
func OpenSQLQuerier(dsn string) (*SQLQuerier, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("open harness connection: %w", err)
	}
	return &SQLQuerier{DB: db}, nil
}

// Query refuses every statement except the fixed SHOW PLUGINS, then returns all
// columns of each row as strings.
func (q *SQLQuerier) Query(ctx context.Context, stmt string) ([][]string, error) {
	if stmt != "SHOW PLUGINS" {
		return nil, fmt.Errorf("harness querier refuses statement %q: only SHOW PLUGINS is permitted", stmt)
	}
	if q.DB == nil {
		return nil, fmt.Errorf("harness querier has no database")
	}
	rows, err := q.DB.QueryContext(ctx, stmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out [][]string
	for rows.Next() {
		vals := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		r := make([]string, len(cols))
		for i, v := range vals {
			r[i] = v.String
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
