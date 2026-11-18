package scenario

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCobaltBFSIPacks_ParseWithCommandAndCleanup(t *testing.T) {
	want := map[string]int{
		"cobalt-group-bfsi-credential-access": 8,
		"cobalt-group-bfsi-lateral-movement":  6,
		"cobalt-group-bfsi-discovery":         4,
	}
	for pack, n := range want {
		b, err := os.ReadFile(filepath.Join("..", "..", "..", "scenarios", pack+".yaml"))
		if err != nil {
			t.Fatalf("read %s: %v", pack, err)
		}
		sc, err := ParseYAML(b)
		if err != nil {
			t.Fatalf("parse %s: %v", pack, err)
		}
		if len(sc.Steps) != n {
			t.Errorf("%s: got %d steps, want %d", pack, len(sc.Steps), n)
		}
		for _, s := range sc.Steps {
			if s.Command == "" {
				t.Errorf("%s %s: empty command", pack, s.TechniqueID)
			}
			if s.Cleanup == "" {
				t.Errorf("%s %s: empty cleanup", pack, s.TechniqueID)
			}
		}
	}
}
