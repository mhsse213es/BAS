package scenario

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The cloud VM packs (everything matching cloud-vm-*.yaml except the original cloud-vm-attack) must resolve every
// step to a real catalog entry. An unclassified step falls closed to destructive, which is what mislabelled the
// read-only probes before; this test keeps that from coming back.
func TestCloudVMPacks_EveryStepHasACatalogEntry(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "scenarios", "cloud-vm-*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no cloud VM packs found: %v", err)
	}
	steps := 0
	for _, f := range files {
		if strings.HasSuffix(f, "cloud-vm-attack.yaml") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		sc, err := ParseYAML(b)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for i, s := range sc.Steps {
			steps++
			c := ResolveExecutionClass(s.TechniqueID, s.ActionKey)
			if c.DestructiveAction == "unclassified" {
				t.Errorf("%s step %d (%s, action_key %q) has no catalog entry", filepath.Base(f), i, s.TechniqueID, s.ActionKey)
			}
		}
	}
	if steps == 0 {
		t.Fatal("no steps checked")
	}
}

// Exactly the three write-and-delete steps are destructive. Every other cloud VM step is non-destructive, or
// potentially destructive for the secret-value read and the role assumption.
func TestCloudVMPacks_DestructiveSetIsExact(t *testing.T) {
	wantDestructive := map[string]bool{
		"cloud_access_key_create": true,
		"cloud_client_secret_add": true,
		"cloud_synthetic_upload":  true,
	}
	for technique, c := range cloudVMClassifications {
		for action, cl := range c {
			isDestructive := cl.Class == ClassDestructive
			if isDestructive != wantDestructive[action] {
				t.Errorf("%s/%s class %s, destructive set expects destructive=%v", technique, action, cl.Class, wantDestructive[action])
			}
		}
	}
}
