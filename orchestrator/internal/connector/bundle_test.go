package connector

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const validBundle = `{
  "version": "2026-07-17",
  "generated_at": "2026-07-17T00:00:00Z",
  "actors": [
    {"name":"APT36","techniques":[{"id":"T1059.001","name":"PowerShell"},{"id":"T1566.001"}],"sectors":["banking"],"confidence":"high"}
  ]
}`

func writeBundle(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, BundleFileName), []byte(content), 0644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
}

func TestBundleSource_Fetch_Valid(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, validBundle)
	bs := NewBundleSource(dir, func(string) error { return nil }) // verify passes

	actors, err := bs.Fetch()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(actors) != 1 || actors[0].Name != "APT36" {
		t.Fatalf("actors = %+v", actors)
	}
	if len(actors[0].Techniques) != 2 || actors[0].Techniques[0].ID != "T1059.001" {
		t.Fatalf("techniques = %+v", actors[0].Techniques)
	}
	if actors[0].Source != "bundle" {
		t.Fatalf("source = %q, want bundle", actors[0].Source)
	}
	if bs.Version() != "2026-07-17" {
		t.Fatalf("version = %q", bs.Version())
	}
}

func TestBundleSource_Fetch_VerifyFails(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, validBundle)
	tampered := errors.New("tampered")
	bs := NewBundleSource(dir, func(string) error { return tampered })

	actors, err := bs.Fetch()
	if !errors.Is(err, tampered) {
		t.Fatalf("err = %v, want tampered", err)
	}
	if actors != nil {
		t.Fatalf("actors should be nil on verify failure, got %+v", actors)
	}
}

func TestBundleSource_Fetch_Missing(t *testing.T) {
	bs := NewBundleSource(t.TempDir(), func(string) error { return nil })
	if _, err := bs.Fetch(); err == nil {
		t.Fatal("expected error for missing bundle")
	}
}

func TestBundleSource_Fetch_Malformed(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, "{ not json")
	bs := NewBundleSource(dir, func(string) error { return nil })
	if _, err := bs.Fetch(); err == nil {
		t.Fatal("expected parse error")
	}
}
