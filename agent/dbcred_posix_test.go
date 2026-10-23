//go:build linux || darwin

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Not executed on the Windows development host; compile-checked for linux and
// darwin (go vet GOOS=linux/darwin).

func withCredDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig := dbcredStoreDir
	dbcredStoreDir = dir
	t.Cleanup(func() { dbcredStoreDir = orig })
	return dir
}

func TestDBCredPosixSymlinkFileRefused(t *testing.T) {
	dir := withCredDir(t)
	target := filepath.Join(t.TempDir(), "real.json")
	if err := os.WriteFile(target, []byte(`{"user":"u","password":"p"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "lab-pg-ro.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveDBCredential("dbcred:lab-pg-ro"); err == nil {
		t.Fatal("a symlinked credential file must be refused")
	}
}

func TestDBCredPosixGroupWritableDirRefused(t *testing.T) {
	dir := withCredDir(t)
	if err := os.WriteFile(filepath.Join(dir, "lab-pg-ro.json"), []byte(`{"user":"u","password":"p"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveDBCredential("dbcred:lab-pg-ro"); err == nil {
		t.Fatal("a group-writable credential directory must be refused")
	}
}

func TestDBCredPosixMissingDirIsUnresolved(t *testing.T) {
	orig := dbcredStoreDir
	dbcredStoreDir = filepath.Join(t.TempDir(), "absent")
	t.Cleanup(func() { dbcredStoreDir = orig })
	if _, err := resolveDBCredential("dbcred:lab-pg-ro"); err == nil {
		t.Fatal("expected unresolved")
	}
}
