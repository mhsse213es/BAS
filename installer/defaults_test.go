package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadInstallDefaultsFromDir_ReadsValidFile(t *testing.T) {
	dir := t.TempDir()
	content := `{"serverURL":"https://192.168.10.78:9443","enrollPort":"9445"}`
	if err := os.WriteFile(filepath.Join(dir, "bas-agent-defaults.json"), []byte(content), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	d := loadInstallDefaultsFromDir(dir)
	if d.ServerURL != "https://192.168.10.78:9443" {
		t.Errorf("ServerURL = %q, want %q", d.ServerURL, "https://192.168.10.78:9443")
	}
	if d.EnrollPort != "9445" {
		t.Errorf("EnrollPort = %q, want %q", d.EnrollPort, "9445")
	}
}

func TestLoadInstallDefaultsFromDir_MissingFile_ReturnsZeroValue(t *testing.T) {
	dir := t.TempDir()
	d := loadInstallDefaultsFromDir(dir)
	if d.ServerURL != "" || d.EnrollPort != "" {
		t.Errorf("expected zero value for a missing file, got %+v", d)
	}
}

func TestLoadInstallDefaultsFromDir_MalformedJSON_ReturnsZeroValue(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bas-agent-defaults.json"), []byte("not json"), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	d := loadInstallDefaultsFromDir(dir)
	if d.ServerURL != "" || d.EnrollPort != "" {
		t.Errorf("expected zero value for malformed JSON, got %+v", d)
	}
}
