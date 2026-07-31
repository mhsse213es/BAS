package scenario

import (
	"testing"
)

func TestArtResolveArgs_CuratedArgument_LeftAsLiteralToken(t *testing.T) {
	prev := ArtifactCuratedLookup
	ArtifactCuratedLookup = func(techniqueID, testName, argName string) bool {
		return techniqueID == "T0000" && testName == "Example Test" && argName == "output_file"
	}
	defer func() { ArtifactCuratedLookup = prev }()

	args := map[string]artInputArg{
		"output_file": {Default: `C:\Windows\Temp\payload.exe`},
	}
	got := artResolveArgs(`Copy-Item -Destination "#{output_file}"`, args, "T0000", "Example Test")
	want := `Copy-Item -Destination "#{output_file}"`
	if got != want {
		t.Errorf("artResolveArgs (curated) = %q, want the token left literal: %q", got, want)
	}
}

func TestArtResolveArgs_NonCuratedArgument_ResolvesAsBefore(t *testing.T) {
	args := map[string]artInputArg{
		"hostname": {Default: "DESKTOP-TEST"},
	}
	got := artResolveArgs(`whoami; #{hostname}`, args, "T1082", "Hostname Discovery")
	want := `whoami; DESKTOP-TEST`
	if got != want {
		t.Errorf("artResolveArgs (non-curated) = %q, want %q (unchanged behavior)", got, want)
	}
}

func TestArtResolveArgs_NonCuratedArgument_EmptyDefault_UsesPlaceholder(t *testing.T) {
	args := map[string]artInputArg{
		"tool_path": {Default: ""},
	}
	got := artResolveArgs(`& "#{tool_path}"`, args, "T1082", "Some Test")
	want := `& "$env:TEMP\bas-placeholder-tool_path"`
	if got != want {
		t.Errorf("artResolveArgs (empty default) = %q, want %q", got, want)
	}
}
