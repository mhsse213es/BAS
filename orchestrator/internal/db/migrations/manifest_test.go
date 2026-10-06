package migrations_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/db/migrations"
)

// Shipped migrations are immutable (README.md): every embedded *.sql must be
// listed in MANIFEST.sha256 with its LF-normalised hash. A new migration is
// appended to the manifest in the same commit; an edit to a listed one fails.
func TestManifest_PinsEveryMigration(t *testing.T) {
	if err := checkManifest(migrations.FS, "MANIFEST.sha256"); err != nil {
		t.Fatal(err)
	}
}

func checkManifest(fsys fs.FS, manifest string) error {
	raw, err := os.ReadFile(manifest)
	if err != nil {
		return err
	}
	listed := map[string]string{}
	for _, l := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		if l = strings.TrimSpace(l); l == "" {
			continue
		}
		sum, name, ok := strings.Cut(l, "  ")
		if !ok {
			return fmt.Errorf("malformed manifest line %q", l)
		}
		listed[name] = sum
	}
	files, err := fs.Glob(fsys, "*.sql")
	if err != nil {
		return err
	}
	var problems []string
	for _, f := range files {
		b, err := fs.ReadFile(fsys, f)
		if err != nil {
			return err
		}
		h := sha256.Sum256(bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")))
		got := hex.EncodeToString(h[:])
		switch want, ok := listed[f]; {
		case !ok:
			problems = append(problems, f+": not in "+manifest+" (append "+got+"  "+f+")")
		case want != got:
			problems = append(problems, f+": changed since it was pinned -- shipped files are immutable; add a new numbered file instead")
		}
		delete(listed, f)
	}
	for f := range listed {
		problems = append(problems, f+": listed in "+manifest+" but missing")
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "\n"))
	}
	return nil
}
