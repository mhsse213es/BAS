package scenario

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// buildExpr is the expression each gated step reads for the Windows build.
const buildExpr = "[Environment]::OSVersion.Version.Build"

// belowFloorBuild is a build number under the 17763 floor, used to exercise the
// gate without an older Windows host.
const belowFloorBuild = "17000"

// gatedFamilySteps are the step names whose availability depends on the build
// floor. The in-process step is gated the same way and is covered separately.
var gatedFamilySteps = []string{
	"Application control indirect execution",
	"Application control alternate binary",
	"Application control script host proxy",
	"Application control alternate PowerShell",
	"Application control parent-child ASR",
}

// withBuild returns the step command with the build read replaced by a fixed
// number. The rest of the step runs unchanged.
func withBuild(command, build string) string {
	return strings.ReplaceAll(command, buildExpr, build)
}

// TestAppControlBuildFloor_BelowFloorIsNotApplicable checks that each gated step
// reports not_applicable, with no verdict, when the build is below the floor. It
// runs the shipped step text with the family fixtures' stubbed cmdlets. The
// assertion is on the real gate decision, not on the text of the gate.
func TestAppControlBuildFloor_BelowFloorIsNotApplicable(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("behavioral steps are Windows PowerShell")
	}
	path := filepath.Join("..", "..", "..", "scenarios", "appcontrol-efficacy.yaml")
	for _, fx := range gateFixtures() {
		t.Run(fx.name, func(t *testing.T) {
			command := withBuild(loadStepCommand(t, path, fx.step), belowFloorBuild)
			out := runPosturePowerShell(t, familyPrelude(fx)+"\n"+command)
			if !strings.Contains(out, "APPCTL_OUTCOME: not_applicable") {
				t.Errorf("below the floor (build %s) the step must report not_applicable\n%s", belowFloorBuild, out)
			}
			for _, verdict := range []string{"PASS:", "FAIL:", "APPCTL_OUTCOME: blocked_as_expected", "APPCTL_OUTCOME: allowed_unexpectedly", "APPCTL_OUTCOME: allowed_by_policy"} {
				if strings.Contains(out, verdict) {
					t.Errorf("below the floor the step must not produce a verdict, found %q\n%s", verdict, out)
				}
			}
			if !strings.Contains(out, "APPCTL_HOST: os_build="+belowFloorBuild) {
				t.Errorf("the build the gate used must be recorded\n%s", out)
			}
		})
	}
}

// gateFixtures returns one fixture per gated step. The first family fixture for a
// step is used when one exists. Otherwise a neutral fixture is used. Below the
// floor the step returns before it reads any stubbed state, so the neutral
// fixture only needs to let the prelude run.
func gateFixtures() []familyFixture {
	out := make([]familyFixture, 0, len(gatedFamilySteps))
	for _, step := range gatedFamilySteps {
		fx, ok := firstFamilyFixture(step)
		if !ok {
			fx = familyFixture{
				name:       step + " (neutral: no family fixture)",
				step:       step,
				rcType:     "Exe",
				mode:       "Enabled",
				appIDState: "Running",
				logOK:      true,
			}
		}
		out = append(out, fx)
	}
	return out
}

func firstFamilyFixture(step string) (familyFixture, bool) {
	for _, fx := range familyFixtures {
		if fx.step == step {
			return fx, true
		}
	}
	return familyFixture{}, false
}

// TestAppControlBuildFloor_InProcessBelowFloorIsNotApplicable applies the same
// check to the in-process host step, which has its own harness. Its helper is
// present, so only the build gate decides the result.
func TestAppControlBuildFloor_InProcessBelowFloorIsNotApplicable(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("behavioral steps are Windows PowerShell")
	}
	path := filepath.Join("..", "..", "..", "scenarios", "appcontrol-efficacy.yaml")
	command := withBuild(loadStepCommand(t, path, inprocessStep), belowFloorBuild)
	out := runPosturePowerShell(t, inprocessPrelude(inprocessFixture{
		helper: true, policy: "restricted",
		output: "HOST_LANGUAGE_MODE: ConstrainedLanguage\nHOST_ADDTYPE: blocked\nMARKER\n",
	})+"\n"+command)
	if !strings.Contains(out, "APPCTL_OUTCOME: not_applicable") {
		t.Errorf("in-process host below the floor must report not_applicable\n%s", out)
	}
	if strings.Contains(out, "APPCTL_OUTCOME: blocked_as_expected") || strings.Contains(out, "PASS:") {
		t.Errorf("in-process host below the floor must not produce a verdict\n%s", out)
	}
}
