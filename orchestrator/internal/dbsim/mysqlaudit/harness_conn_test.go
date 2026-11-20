package mysqlaudit

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeSecret(t *testing.T, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "harness.pw")
	if err := os.WriteFile(p, []byte("s3cret-not-real"), mode); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func TestDSNFromFileRefusesGroupOrWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits do not apply on Windows")
	}
	p := writeSecret(t, 0o644)
	if _, err := DSNFromFile(p, "127.0.0.1:53306"); err == nil {
		t.Fatal("a password file readable by group or others must be refused")
	}
}

func TestDSNFromFileBuildsHarnessDSN(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits do not apply on Windows")
	}
	p := writeSecret(t, 0o600)
	dsn, err := DSNFromFile(p, "127.0.0.1:53306")
	if err != nil {
		t.Fatalf("DSNFromFile: %v", err)
	}
	if !strings.HasPrefix(dsn, "dbsim_harness:") || !strings.Contains(dsn, "@tcp(127.0.0.1:53306)/") {
		t.Errorf("unexpected DSN shape (password redacted): %q", strings.Replace(dsn, "s3cret-not-real", "***", 1))
	}
}

func TestDSNFromFileMissingFileIsError(t *testing.T) {
	if _, err := DSNFromFile(filepath.Join(t.TempDir(), "nope"), "127.0.0.1:53306"); err == nil {
		t.Fatal("a missing password file must be an error")
	}
}

func TestSQLQuerierRefusesAnyStatementOtherThanShowPlugins(t *testing.T) {
	q := &SQLQuerier{} // no database: the refusal must happen before any query
	for _, sql := range []string{"SELECT 1", "SELECT * FROM mysql.general_log", "SHOW PLUGINS; DROP TABLE x"} {
		if _, err := q.Query(t.Context(), sql); err == nil {
			t.Errorf("statement %q must be refused by the harness querier", sql)
		}
	}
}
