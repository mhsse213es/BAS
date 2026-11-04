package secretstore

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidRef(t *testing.T) {
	good := []string{"cred:siem_configs:3f2a-91bc:token", "cred:taxii_connector_config:row1:client_key"}
	for _, r := range good {
		if !ValidRef(r) {
			t.Errorf("ValidRef(%q) = false, want true", r)
		}
	}
	bad := []string{
		"",
		"cred:siem_configs:../etc:token", // path separator
		"cred:siem_configs:row 1:token",  // space
		"cred:Siem_configs:row1:token",   // upper-case table
		"cred:siem_configs:row1:Token",   // upper-case column
		"cred::row1:token",               // empty table
		"cred:siem_configs:row1:token:x", // extra part
		"dbcred:lab-pg:row1:token",       // wrong prefix
		"cred:siem_configs:" + strings.Repeat("a", 81) + ":token", // row id too long
	}
	for _, r := range bad {
		if ValidRef(r) {
			t.Errorf("ValidRef(%q) = true, want false", r)
		}
	}
}

func TestMakeRef(t *testing.T) {
	ref, err := MakeRef("siem_configs", "3f2a-91bc", "token")
	if err != nil || ref != "cred:siem_configs:3f2a-91bc:token" {
		t.Fatalf("MakeRef = %q, %v", ref, err)
	}
	if _, err := MakeRef("siem_configs", "a/b", "token"); !errors.Is(err, ErrBadRef) {
		t.Errorf("MakeRef with a slash in the row id: err = %v, want ErrBadRef", err)
	}
}

// fakeInfo is the minimum fs.FileInfo the mode check reads.
type fakeInfo struct{ mode fs.FileMode }

func (f fakeInfo) Name() string       { return "k" }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return false }
func (f fakeInfo) Sys() any           { return nil }

func TestCheckKeyPerms(t *testing.T) {
	cases := []struct {
		mode fs.FileMode
		ok   bool
	}{
		{0o600, true},
		{0o400, true},
		{0o640, false},
		{0o604, false},
		{0o644, false},
	}
	for _, c := range cases {
		err := checkKeyPerms(fakeInfo{mode: c.mode})
		if (err == nil) != c.ok {
			t.Errorf("mode %o: err = %v, want ok=%t", c.mode, err, c.ok)
		}
	}
}

// newKey returns base64 text of 32 random bytes, the format LoadKeyFile accepts.
func newKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// passCheck stands in for the platform ownership and mode check, so the format rules can be tested on any host.
func passCheck(fs.FileInfo) error { return nil }

func TestLoadKeyFileFormat(t *testing.T) {
	dir := t.TempDir()
	good := newKey(t)
	path := filepath.Join(dir, "k")
	if err := os.WriteFile(path, []byte(good+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadKeyFile(path, passCheck)
	if err != nil || got != good {
		t.Fatalf("loadKeyFile = %q, %v; want the key text", got, err)
	}

	cases := map[string]string{
		"short key":  base64.StdEncoding.EncodeToString([]byte("too-short")),
		"not base64": "!!!not-base64!!!",
		"empty":      "",
		"two lines":  good + "\n" + good,
	}
	for name, content := range cases {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "_"))
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := loadKeyFile(p, passCheck)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if content != "" && strings.Contains(err.Error(), content) {
			t.Errorf("%s: error text carries the key material", name)
		}
	}
}

func TestLoadKeyFileMissing(t *testing.T) {
	if _, err := loadKeyFile(filepath.Join(t.TempDir(), "absent"), passCheck); err == nil {
		t.Fatal("a missing key file was accepted")
	}
}
