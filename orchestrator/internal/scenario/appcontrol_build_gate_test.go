package scenario

import (
	"path/filepath"
	"strings"
	"testing"
)

// Every behavioral path must record its Windows build, and every path that
// depends on a build-gated feature must refuse to run below the floor. The
// floor is the build that introduced the features the path tests.
//
// The below-floor branch cannot be exercised on this host, which runs a
// supported build. This static check verifies the gate is present in each
// step. The live check runs on the current build. Old-build behaviour is
// stated as a limitation, not claimed as tested.
func TestAppControlBuildGate_EveryPathRecordsBuildAndGates(t *testing.T) {
	path := filepath.Join("..", "..", "..", "scenarios", "appcontrol-efficacy.yaml")
	gated := map[string]string{
		"Application control indirect execution":    "-ge 17763",
		"Application control alternate binary":      "-ge 17763",
		"Application control script host proxy":     "-ge 17763",
		"Application control alternate PowerShell":  "-ge 17763",
		"Application control parent-child ASR":      "-ge 17763",
		"Application control in-process PowerShell": "-lt 17763",
	}
	for prefix, gate := range gated {
		cmd := loadStepCommand(t, path, prefix)
		if !strings.Contains(cmd, "APPCTL_HOST: os_build=") {
			t.Errorf("step %q does not record its Windows build (APPCTL_HOST)", prefix)
		}
		if !strings.Contains(cmd, gate) {
			t.Errorf("step %q is not gated on the minimum Windows build (want %q)", prefix, gate)
		}
	}
}
