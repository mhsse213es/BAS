package scenario

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cloudVMExpectedClass is the class each cloud VM action_key must resolve to. The test reads the scenario files
// themselves, so it checks what the scenarios declare, not a copy of the catalog.
var cloudVMExpectedClass = map[string]ExecutionClass{
	"cloud_imds_probe":          ClassNonDestructive,
	"cloud_token_issue":         ClassNonDestructive,
	"cloud_token_use_read":      ClassNonDestructive,
	"cloud_inventory_read":      ClassNonDestructive,
	"cloud_role_read":           ClassNonDestructive,
	"cloud_identity_read":       ClassNonDestructive,
	"cloud_secret_name_read":    ClassNonDestructive,
	"policy_simulation_read":    ClassNonDestructive,
	"local_credential_scan":     ClassNonDestructive,
	"remote_mgmt_exposure_read": ClassNonDestructive,
	"startup_location_read":     ClassNonDestructive,
	"cloud_object_list_read":    ClassNonDestructive,
	"cloud_object_head_read":    ClassNonDestructive,
	"cloud_secret_value_read":   ClassPotentiallyDestructive,
	"cloud_role_assume":         ClassPotentiallyDestructive,
	"cloud_access_key_create":   ClassDestructive,
	"cloud_client_secret_add":   ClassDestructive,
	"cloud_synthetic_upload":    ClassDestructive,
}

// Every step of the new cloud VM packs (cloud-vm-*.yaml except the original cloud-vm-attack) must declare an
// action_key in the expected table, and must resolve to that class in the catalog. An empty action_key or a
// resolution through the technique's enumerate fallback fails here, which is how the inverted classes slipped in.
func TestCloudVMPacks_StepsDeclaredAndClassifiedAsExpected(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "scenarios", "cloud-vm-*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no cloud VM packs found: %v", err)
	}
	checked := 0
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
			checked++
			want, known := cloudVMExpectedClass[s.ActionKey]
			if !known {
				t.Errorf("%s step %d (%s): action_key %q is not in the cloud VM table", filepath.Base(f), i, s.TechniqueID, s.ActionKey)
				continue
			}
			c := ResolveExecutionClass(s.TechniqueID, s.ActionKey)
			if c.DestructiveAction == "unclassified" {
				t.Errorf("%s step %d (%s, %q): no catalog entry", filepath.Base(f), i, s.TechniqueID, s.ActionKey)
				continue
			}
			if c.Class != want {
				t.Errorf("%s step %d (%s, %q): catalog class %s, expected %s", filepath.Base(f), i, s.TechniqueID, s.ActionKey, c.Class, want)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no cloud VM steps checked")
	}
}
