package mysqlaudit

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Evidence must fail closed before it opens any connection when the password file is
// unsafe: no verdict, and the error names the file problem.
func TestEvidenceRefusesUnsafePasswordFileBeforeConnecting(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits do not apply on Windows")
	}
	p := filepath.Join(t.TempDir(), "harness.pw")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	ev, err := Evidence(context.Background(), LabConfig{
		PasswordFile: p, Addr: "127.0.0.1:53306", AuditFile: filepath.Join(t.TempDir(), "audit.log"),
	})
	if err == nil {
		t.Fatal("an unsafe password file must be an error")
	}
	if ev.AuditCoverage != "" {
		t.Fatalf("no verdict may be reported: %q", ev.AuditCoverage)
	}
}
