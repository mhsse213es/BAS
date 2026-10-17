package main

import (
	"os"
	"runtime"
	"testing"
)

func TestWriteReadInstallConfig_RoundTrips(t *testing.T) {
	path, err := writeInstallConfig("https://bas.example:9000", "s3cr3t-value")
	if err != nil {
		t.Fatalf("writeInstallConfig: %v", err)
	}
	defer os.Remove(path)

	serverURL, secret, err := readInstallConfig(path)
	if err != nil {
		t.Fatalf("readInstallConfig: %v", err)
	}
	if serverURL != "https://bas.example:9000" || secret != "s3cr3t-value" {
		t.Fatalf("got (%q, %q), want (%q, %q)", serverURL, secret, "https://bas.example:9000", "s3cr3t-value")
	}
}

func TestWriteInstallConfig_OwnerOnlyPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits don't apply on Windows")
	}
	path, err := writeInstallConfig("https://bas.example:9000", "s3cr3t-value")
	if err != nil {
		t.Fatalf("writeInstallConfig: %v", err)
	}
	defer os.Remove(path)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("config file mode = %v, want 0600 -- it carries the agent secret in plaintext", info.Mode().Perm())
	}
}

func TestReadInstallConfig_MissingSecondLine_ReturnsError(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "install-config-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if _, err := f.WriteString("https://bas.example:9000\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	f.Close()

	if _, _, err := readInstallConfig(f.Name()); err == nil {
		t.Fatal("expected an error for a config file missing the secret line, got nil")
	}
}
