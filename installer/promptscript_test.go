package main

import (
	"strings"
	"testing"
)

func TestBuildPromptScript_NoPreset_AsksForServerURLAndSecret(t *testing.T) {
	script := buildPromptScript("")
	if !strings.Contains(script, `display dialog "Enter the Server URL`) {
		t.Error("expected a Server URL dialog when no preset is given")
	}
	if !strings.Contains(script, `display dialog "Enter the Agent Secret:`) {
		t.Error("expected a Secret dialog")
	}
}

func TestBuildPromptScript_WithPreset_SkipsServerURLDialog(t *testing.T) {
	script := buildPromptScript("https://192.168.10.78:9443")
	if strings.Contains(script, "display dialog \"Enter the Server URL") {
		t.Error("expected the Server URL dialog to be skipped when a preset is given")
	}
	if !strings.Contains(script, `display dialog "Enter the Agent Secret:`) {
		t.Error("expected a Secret dialog")
	}
	if !strings.Contains(script, `set serverURL to "https://192.168.10.78:9443"`) {
		t.Errorf("expected serverURL to be set from the preset verbatim, got: %s", script)
	}
}

func TestBuildPromptScript_WithPreset_QuotesPresetSafely(t *testing.T) {
	// A preset containing a double quote must not break out of the
	// AppleScript string literal -- same injection concern shellquote.go
	// already guards for shell strings.
	script := buildPromptScript(`https://h"; display dialog "pwned`)
	if strings.Contains(script, `"pwned`) && !strings.Contains(script, `\"pwned`) {
		t.Errorf("preset value was not safely quoted: %s", script)
	}
}
