package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/audspect/bas/internal/api"
)

func TestClusterCredentialsFromDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "lab-east.token"), []byte("  tok-east \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lab-east.ca"), []byte("PEM"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lab-west.token"), []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := clusterCredentialsFromDir(dir)

	tok, ca, err := src("lab-east")
	if err != nil || tok != "tok-east" || string(ca) != "PEM" {
		t.Fatalf("lab-east: got %q %q %v", tok, ca, err)
	}
	if _, _, err := src("lab-west"); !errors.Is(err, api.ErrK8sClusterNoCredential) {
		t.Errorf("blank token must mean no credential, got %v", err)
	}
	if _, _, err := src("unregistered"); !errors.Is(err, api.ErrK8sClusterNoCredential) {
		t.Errorf("missing token must mean no credential, got %v", err)
	}
	for _, name := range []string{"../etc", "a/b", `a\b`, "..", ""} {
		if _, _, err := src(name); !errors.Is(err, api.ErrK8sClusterNoCredential) {
			t.Errorf("%q must be refused as no credential, got %v", name, err)
		}
	}
	none := clusterCredentialsFromDir("")
	if _, _, err := none("lab-east"); !errors.Is(err, api.ErrK8sClusterNoCredential) {
		t.Errorf("unset directory must mean no credential, got %v", err)
	}
}
