//go:build linux || darwin

package secretstore

import (
	"os"
	"path/filepath"
	"testing"
)

// A key file that is not owned by root is refused. When the test runs as root, the ownership check passes, so the test
// skips: the refusal can only be observed as a non-root user.
func TestKeyFileOwnedByRootRequired(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: the owner check passes, so the non-root refusal cannot be observed")
	}
	path := filepath.Join(t.TempDir(), "k")
	if err := os.WriteFile(path, []byte(newKey(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyFile(path); err == nil {
		t.Fatal("a key file owned by a non-root user was accepted")
	}
}
