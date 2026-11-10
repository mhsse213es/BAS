package contentimport

import (
	"bytes"
	"encoding/base64"
	"regexp"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

const yaraSample = `
// a comment
rule Demo_Stealer : tag1 tag2 {
  meta:
    description = "demo"
    mitre_attack = "T1003.001"
  strings:
    $a = "sekurlsa::logonpasswords" ascii
    $b = "mimikatz" nocase wide
    $h = { 4D 5A ?? 00 [2] 50 45 }
    $rx = /pass[0-9]+/
  condition:
    uint16(0) == 0x5A4D and ($a or $b) and filesize < 2MB
}

rule Second {
  meta:
    attack = "T1059"
  strings:
    $x = "one"
    $y = "two"
  condition:
    all of them
}
`

func gen(t *testing.T, src, os, tech string) []*YaraResult {
	t.Helper()
	rules, err := ParseYARA(src)
	if err != nil {
		t.Fatal(err)
	}
	var out []*YaraResult
	for _, r := range rules {
		res, err := GenerateYARA(r, os, tech)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, res)
	}
	return out
}

func TestYARA_ParsesEveryRuleInTheFile(t *testing.T) {
	rs := gen(t, yaraSample, "windows", "")
	if len(rs) != 2 || rs[0].Rule.Name != "Demo_Stealer" || rs[1].Rule.Name != "Second" {
		t.Fatalf("rules: %+v", rs)
	}
}

func TestYARA_FileHoldsTheHeaderAndTheSmallestSatisfyingStrings(t *testing.T) {
	r := gen(t, yaraSample, "windows", "")[0]
	if !r.Coverage.Emulable {
		t.Fatalf("%+v", r.Coverage)
	}
	if !bytes.HasPrefix(r.Content, []byte("MZ")) {
		t.Errorf("the MZ header test must be satisfied: %q", r.Content)
	}
	if !bytes.Contains(r.Content, []byte("sekurlsa::logonpasswords")) {
		t.Errorf("one of ($a or $b) is enough, and $a is first: %q", r.Content)
	}
	if bytes.Contains(r.Content, []byte("m\x00i\x00m\x00")) {
		t.Errorf("only one alternative is needed")
	}
	if len(r.Coverage.NotEmulated) != 1 || !strings.Contains(r.Coverage.NotEmulated[0], "$rx") {
		t.Errorf("the regex string must be reported: %v", r.Coverage.NotEmulated)
	}
	if r.Step.TechniqueID != "T1003.001" {
		t.Errorf("technique from meta: %s", r.Step.TechniqueID)
	}
}

func TestYARA_AllOfThemCarriesEveryString(t *testing.T) {
	r := gen(t, yaraSample, "linux", "")[1]
	if !bytes.Contains(r.Content, []byte("one")) || !bytes.Contains(r.Content, []byte("two")) {
		t.Errorf("%q", r.Content)
	}
}

func TestYARA_TheCommandWritesExactlyTheContentAndChecksForRemoval(t *testing.T) {
	r := gen(t, yaraSample, "windows", "")[1]
	m := regexp.MustCompile(`FromBase64String\('([A-Za-z0-9+/=]+)'\)`).FindStringSubmatch(r.Step.Command)
	if m == nil {
		t.Fatalf("no payload in command: %s", r.Step.Command)
	}
	got, _ := base64.StdEncoding.DecodeString(m[1])
	if !bytes.Equal(got, r.Content) {
		t.Errorf("payload differs from the content")
	}
	for _, want := range []string{"Test-Path $f", "exit 1", r.Step.Marker} {
		if !strings.Contains(r.Step.Command, want) {
			t.Errorf("command lacks %q", want)
		}
	}
	if strings.Contains(r.Step.Command, "Invoke-Expression") || strings.Contains(r.Step.Command, "Start-Process") {
		t.Error("the file must never be executed")
	}
}

func TestYARA_LinuxStepUsesBashAndRemovesItsFolder(t *testing.T) {
	r := gen(t, yaraSample, "linux", "")[1]
	if r.Step.Executor != "bash" || !strings.Contains(r.Step.Command, "base64 -d") || !strings.HasPrefix(r.Step.Cleanup, "rm -rf /tmp/audspect-") {
		t.Errorf("%s / %s", r.Step.Command, r.Step.Cleanup)
	}
}

func TestYARA_NoTechniqueNeedsAnOverride(t *testing.T) {
	src := "rule R { strings: $a = \"x\" condition: $a }"
	if r := gen(t, src, "windows", "")[0]; r.Coverage.Emulable {
		t.Error("technique is required")
	}
	if r := gen(t, src, "windows", "T1204")[0]; !r.Coverage.Emulable || r.Step.TechniqueID != "T1204" {
		t.Errorf("%+v", r.Coverage)
	}
}

func TestYARA_ARuleWithNothingReproducibleSaysSo(t *testing.T) {
	src := "rule R { meta: attack=\"T1204\" strings: $a = /x+/ condition: $a }"
	r := gen(t, src, "windows", "")[0]
	if r.Coverage.Emulable || r.Step != nil {
		t.Fatal("no step without a reproducible string")
	}
}

func TestYARA_WideAndHexAndEscapes(t *testing.T) {
	s := decodeYaraString("$w", `"AB" wide`)
	if !bytes.Equal(s.data, []byte{'A', 0, 'B', 0}) {
		t.Errorf("wide: %v", s.data)
	}
	s = decodeYaraString("$e", `"a\x41\n"`)
	if string(s.data) != "aA\n" {
		t.Errorf("escapes: %q", s.data)
	}
	s = decodeYaraString("$h", `{ 41 ?? [3] 42 }`)
	if !bytes.Equal(s.data, []byte{0x41, 0, 0, 0, 0, 0x42}) {
		t.Errorf("hex: %v", s.data)
	}
	if s = decodeYaraString("$x", `"a" xor`); s.why == "" {
		t.Error("xor cannot be reproduced and must say so")
	}
	if s = decodeYaraString("$bad", `"a\x4"`); s.why == "" {
		t.Error("a truncated \\x escape must be rejected, not read past the end")
	}
}

func TestYARA_StepPassesScenarioValidation(t *testing.T) {
	r := gen(t, yaraSample, "windows", "")[1]
	sc := &scenario.Scenario{ID: "imp-yara", Name: "t", Steps: []scenario.Step{*r.Step}}
	if err := sc.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := sc.ValidateMarkers(); err != nil {
		t.Fatal(err)
	}
}

func TestYARA_ContentIsBounded(t *testing.T) {
	big := strings.Repeat("A", 3000)
	src := "rule R { meta: attack=\"T1204\" strings: $a = \"" + big + "\" $b = \"" + big + "\" condition: all of them }"
	r := gen(t, src, "windows", "")[0]
	if r.Coverage.Emulable {
		t.Error("content over the limit must be refused, not truncated")
	}
}
