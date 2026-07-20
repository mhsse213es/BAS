package scenario

import (
	"strings"
	"testing"
)

const sampleAtomicYAML = `
attack_technique: T1082
display_name: System Information Discovery
atomic_tests:
  - name: Hostname Discovery
    supported_platforms:
      - windows
    executor:
      name: powershell
      command: hostname
  - name: macOS only test
    supported_platforms:
      - macos
    executor:
      name: sh
      command: uname -a
  - name: Payload-backed test
    supported_platforms:
      - windows
    input_arguments:
      tool_path:
        default: PathToAtomicsFolder\T1082\bin\tool.exe
    executor:
      name: command_prompt
      command: "#{tool_path} /scan"
`

func TestNormalizeAtomicAllPlatforms(t *testing.T) {
	tech, name, tests, err := normalizeAtomic([]byte(sampleAtomicYAML))
	if err != nil {
		t.Fatalf("normalizeAtomic: %v", err)
	}
	if tech != "T1082" {
		t.Errorf("technique = %q, want T1082", tech)
	}
	if name != "System Information Discovery" {
		t.Errorf("display name = %q", name)
	}
	// Two Windows tests + one macOS/sh test = 3 total.
	if len(tests) != 3 {
		t.Fatalf("got %d tests, want 3: %+v", len(tests), tests)
	}

	// Windows tests come first (Windows loop runs before Unix loop).
	win := tests[:2]
	if win[0].Executor != "powershell" || win[0].Command != "hostname" || win[0].Platform != "windows" {
		t.Errorf("win[0] = %+v", win[0])
	}
	// test indices preserve original ordinal position (0 and 2).
	if win[0].Index != 0 || win[1].Index != 2 {
		t.Errorf("indices = %d,%d want 0,2", win[0].Index, win[1].Index)
	}

	// The payload-backed Windows test must rewrite PathToAtomicsFolder.
	pt := win[1]
	if pt.Executor != "cmd" {
		t.Errorf("payload test executor = %q, want cmd", pt.Executor)
	}
	if !strings.Contains(pt.Command, "%BAS_PAYLOAD_DIR%\\tool.exe") {
		t.Errorf("command not rewritten to staging dir: %q", pt.Command)
	}
	if len(pt.RequiredPayloads) != 1 || !strings.EqualFold(pt.RequiredPayloads[0], "tool.exe") {
		t.Errorf("required payloads = %v, want [tool.exe]", pt.RequiredPayloads)
	}

	// macOS/sh test.
	mac := tests[2]
	if mac.Platform != "darwin" || mac.Executor != "bash" {
		t.Errorf("mac test = %+v, want platform=darwin executor=bash", mac)
	}
	if mac.Command != "uname -a" {
		t.Errorf("mac command = %q, want uname -a", mac.Command)
	}
}

func TestNormalizeAtomicMissingTechnique(t *testing.T) {
	_, _, _, err := normalizeAtomic([]byte("display_name: x\natomic_tests: []\n"))
	if err == nil {
		t.Fatal("expected error for missing attack_technique")
	}
}

func TestMapARTElevation(t *testing.T) {
	if got := mapARTElevation(true); got.Effective() != "admin" {
		t.Errorf("mapARTElevation(true) = %q, want admin", got.Effective())
	}
	if got := mapARTElevation(false); got.Effective() != "user" {
		t.Errorf("mapARTElevation(false) = %q, want user", got.Effective())
	}
}

const elevationAtomicYAML = `
attack_technique: T1548.002
display_name: Bypass UAC
atomic_tests:
  - name: Elevated test
    supported_platforms:
      - windows
    executor:
      name: powershell
      command: whoami
      elevation_required: true
  - name: Non-elevated test
    supported_platforms:
      - windows
    executor:
      name: powershell
      command: whoami
`

func TestNormalizeAtomic_ElevationRequired(t *testing.T) {
	_, _, tests, err := normalizeAtomic([]byte(elevationAtomicYAML))
	if err != nil {
		t.Fatalf("normalizeAtomic: %v", err)
	}
	if len(tests) != 2 {
		t.Fatalf("got %d tests, want 2", len(tests))
	}
	elevated, plain := tests[0], tests[1]
	if elevated.RequiresPriv.Effective() != "admin" {
		t.Errorf("elevated test RequiresPriv = %q, want admin", elevated.RequiresPriv.Effective())
	}
	if !elevated.OriginalElevationRequired {
		t.Error("elevated test OriginalElevationRequired = false, want true")
	}
	if plain.RequiresPriv.Effective() != "user" {
		t.Errorf("plain test RequiresPriv = %q, want user", plain.RequiresPriv.Effective())
	}
	if plain.OriginalElevationRequired {
		t.Error("plain test OriginalElevationRequired = true, want false")
	}
}
