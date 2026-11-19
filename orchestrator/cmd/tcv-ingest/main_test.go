package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeManifest(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "bundle-manifest.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func noEnv(string) string { return "" }

func TestRun_UsageWithoutManifestFlag(t *testing.T) {
	var out bytes.Buffer
	if code := run(nil, noEnv, &out); code != 2 {
		t.Errorf("exit = %d, want 2 (usage)", code)
	}
	if !strings.Contains(out.String(), "-manifest") {
		t.Errorf("usage text should name -manifest, got %q", out.String())
	}
}

func TestRun_MissingManifestFileFailsClosed(t *testing.T) {
	var out bytes.Buffer
	code := run([]string{"-manifest", filepath.Join(t.TempDir(), "nope.json")},
		func(k string) string {
			if k == "DATABASE_URL" {
				return "postgres://unused"
			}
			return ""
		}, &out)
	if code == 0 {
		t.Error("a missing manifest must exit non-zero")
	}
}

func TestRun_MalformedManifestFailsClosed(t *testing.T) {
	var out bytes.Buffer
	p := writeManifest(t, `{not json`)
	code := run([]string{"-manifest", p}, func(k string) string {
		if k == "DATABASE_URL" {
			return "postgres://unused"
		}
		return ""
	}, &out)
	if code == 0 {
		t.Error("a malformed manifest must exit non-zero")
	}
}

func TestRun_RequiresDatabaseURL(t *testing.T) {
	var out bytes.Buffer
	p := writeManifest(t, `{"schema":1,"bundle_id":"b","packaged_at":"2026-11-10T09:00:00Z","entries":[]}`)
	if code := run([]string{"-manifest", p}, noEnv, &out); code == 0 {
		t.Error("missing DATABASE_URL must exit non-zero")
	}
	if !strings.Contains(out.String(), "DATABASE_URL") {
		t.Errorf("error should name DATABASE_URL, got %q", out.String())
	}
}
