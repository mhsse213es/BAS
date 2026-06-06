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

func TestNormalizeAtomicWindowsOnly(t *testing.T) {
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
	// Only the two Windows tests should survive; the macOS/sh one is dropped.
	if len(tests) != 2 {
		t.Fatalf("got %d tests, want 2: %+v", len(tests), tests)
	}

	if tests[0].Executor != "powershell" || tests[0].Command != "hostname" {
		t.Errorf("test0 = %+v", tests[0])
	}
	// test indices preserve original ordinal position (0 and 2).
	if tests[0].Index != 0 || tests[1].Index != 2 {
		t.Errorf("indices = %d,%d want 0,2", tests[0].Index, tests[1].Index)
	}

	// The payload-backed test must rewrite PathToAtomicsFolder to the agent's
	// staging dir and record the required payload basename.
	pt := tests[1]
	if pt.Executor != "cmd" {
		t.Errorf("payload test executor = %q, want cmd", pt.Executor)
	}
	if !strings.Contains(pt.Command, "%BAS_PAYLOAD_DIR%\\tool.exe") {
		t.Errorf("command not rewritten to staging dir: %q", pt.Command)
	}
	if len(pt.RequiredPayloads) != 1 || !strings.EqualFold(pt.RequiredPayloads[0], "tool.exe") {
		t.Errorf("required payloads = %v, want [tool.exe]", pt.RequiredPayloads)
	}
}

func TestNormalizeAtomicMissingTechnique(t *testing.T) {
	_, _, _, err := normalizeAtomic([]byte("display_name: x\natomic_tests: []\n"))
	if err == nil {
		t.Fatal("expected error for missing attack_technique")
	}
}
