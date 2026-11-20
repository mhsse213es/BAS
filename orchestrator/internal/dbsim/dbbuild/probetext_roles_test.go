package dbbuild

import (
	"strings"
	"testing"
)

func TestRoleNameDiscoveryObjectiveDoesNotClaimHiddenNames(t *testing.T) {
	obj := probeText["read_foreign_role_names"].objective
	if strings.Contains(obj, "not visible") {
		t.Fatalf("objective still claims names are hidden: %q", obj)
	}
	if !strings.Contains(obj, "recorded") {
		t.Fatalf("objective should say the visibility is recorded: %q", obj)
	}
}
