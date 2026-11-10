package contentimport

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

const certutilRule = `
title: Certutil Download
id: 11111111-2222-3333-4444-555555555555
level: high
tags: [attack.command_and_control, attack.t1105]
logsource: {product: windows, category: process_creation}
detection:
  selection_img:
    Image|endswith: '\certutil.exe'
  selection_cli:
    CommandLine|contains|all:
      - 'urlcache'
      - '-split'
  filter:
    ParentImage|endswith: '\trusted.exe'
  condition: selection_img and selection_cli and not filter
`

func mustGen(t *testing.T, src, tech string) *SigmaResult {
	t.Helper()
	r, err := ParseSigma([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	res, err := GenerateSigma(r, tech)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return res
}

func TestSigma_WindowsProcessCreation_RunsAHarmlessCopyNamedAfterTheImage(t *testing.T) {
	res := mustGen(t, certutilRule, "")
	if !res.Coverage.Emulable || res.Step == nil {
		t.Fatalf("expected an emulable draft, got %+v", res.Coverage)
	}
	st := res.Step
	if st.TechniqueID != "T1105" || st.Executor != "cmd" {
		t.Errorf("technique/executor: %s %s", st.TechniqueID, st.Executor)
	}
	for _, want := range []string{`copy /y "%SystemRoot%\System32\cmd.exe"`, `certutil.exe" /c echo`, "urlcache", "-split", st.Marker} {
		if !strings.Contains(st.Command, want) {
			t.Errorf("command lacks %q:\n%s", want, st.Command)
		}
	}
	if !strings.Contains(st.Cleanup, "rmdir /s /q") {
		t.Errorf("cleanup must remove the copy: %s", st.Cleanup)
	}
	if res.Rule.Techniques[0] != "T1105" {
		t.Errorf("technique from tag: %v", res.Rule.Techniques)
	}
}

func TestSigma_TheStepPassesTheScenarioMarkerCheck(t *testing.T) {
	res := mustGen(t, certutilRule, "")
	sc := &scenario.Scenario{ID: "imp-test", Name: "t", Steps: []scenario.Step{*res.Step}}
	if err := sc.ValidateMarkers(); err != nil {
		t.Fatal(err)
	}
	if err := sc.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSigma_AFilterSelectionTheCarrierDoesNotMatchIsNotRequired(t *testing.T) {
	res := mustGen(t, certutilRule, "")
	if len(res.Coverage.Notes) != 0 {
		t.Errorf("no note expected, got %v", res.Coverage.Notes)
	}
}

func TestSigma_NeverPutsAShellMetacharacterFromTheRuleInTheCommand(t *testing.T) {
	src := `
title: Injection attempt
tags: [attack.t1059]
logsource: {product: windows, category: process_creation}
detection:
  selection:
    CommandLine|contains:
      - 'x" & calc.exe & echo "'
      - 'a; rm -rf /'
      - '$(reboot)'
      - 'safe-value'
  condition: selection
`
	res := mustGen(t, src, "")
	if !res.Coverage.Emulable {
		t.Fatalf("the safe alternative should be used: %+v", res.Coverage)
	}
	cmd := res.Step.Command
	for _, bad := range []string{"calc.exe", "rm -rf", "reboot", `"x"`} {
		if strings.Contains(cmd, bad) {
			t.Errorf("unsafe text %q reached the command: %s", bad, cmd)
		}
	}
	if !strings.Contains(cmd, "safe-value") {
		t.Errorf("the safe value should be carried: %s", cmd)
	}
}

func TestSigma_WhenNoValueIsSafeTheRuleIsNotEmulatedAndSaysWhy(t *testing.T) {
	src := `
title: Only unsafe
tags: [attack.t1059]
logsource: {product: windows, category: process_creation}
detection:
  selection:
    CommandLine|contains: 'a | b > c'
  condition: selection
`
	res := mustGen(t, src, "")
	if res.Coverage.Emulable || res.Step != nil {
		t.Fatal("a rule whose only value is unsafe must not produce a step")
	}
	if !strings.Contains(strings.Join(res.Coverage.NotEmulated, " "), "carried safely") {
		t.Errorf("reason missing: %v", res.Coverage.NotEmulated)
	}
}

func TestSigma_ARuleThatNeedsAParentProcessIsNotEmulated(t *testing.T) {
	src := `
title: Needs parent
tags: [attack.t1059]
logsource: {product: windows, category: process_creation}
detection:
  selection:
    ParentImage|endswith: '\winword.exe'
    CommandLine|contains: 'cmd'
  condition: selection
`
	res := mustGen(t, src, "")
	if res.Coverage.Emulable {
		t.Fatal("ParentImage cannot be reproduced; the draft would never fire the rule")
	}
	if !strings.Contains(strings.Join(res.Coverage.NotEmulated, " "), "ParentImage") {
		t.Errorf("should name the field: %v", res.Coverage.NotEmulated)
	}
}

func TestSigma_OneOfPatternPicksAnEmulableSelection(t *testing.T) {
	src := `
title: One of
tags: [attack.t1059]
logsource: {product: windows, category: process_creation}
detection:
  selection_a:
    ParentImage|endswith: '\winword.exe'
  selection_b:
    CommandLine|contains: 'mshta http'
  condition: 1 of selection*
`
	res := mustGen(t, src, "")
	if !res.Coverage.Emulable || !strings.Contains(res.Step.Command, "mshta http") {
		t.Fatalf("should fall back to selection_b: %+v / %v", res.Coverage, res.Step)
	}
	if len(res.Coverage.Emulated) != 1 || res.Coverage.Emulated[0] != "selection_b" {
		t.Errorf("emulated: %v", res.Coverage.Emulated)
	}
}

func TestSigma_UnsupportedLogsourceIsReportedNotGuessed(t *testing.T) {
	src := `
title: Registry
tags: [attack.t1547]
logsource: {product: windows, category: registry_set}
detection:
  selection: {TargetObject|endswith: '\Run\evil'}
  condition: selection
`
	res := mustGen(t, src, "")
	if res.Coverage.Emulable || !strings.Contains(res.Coverage.NotEmulated[0], "registry_set") {
		t.Errorf("%+v", res.Coverage)
	}
}

func TestSigma_NoTechniqueTagNeedsAnOverride(t *testing.T) {
	src := strings.Replace(certutilRule, "tags: [attack.command_and_control, attack.t1105]", "tags: []", 1)
	if res := mustGen(t, src, ""); res.Coverage.Emulable || !strings.Contains(res.Coverage.NotEmulated[0], "ATT&CK") {
		t.Errorf("should ask for a technique: %+v", res.Coverage)
	}
	if res := mustGen(t, src, "t1218"); !res.Coverage.Emulable || res.Step.TechniqueID != "T1218" {
		t.Errorf("override not used: %+v", res.Coverage)
	}
}

func TestSigma_LinuxProcessCreationUsesQuotedEchoArguments(t *testing.T) {
	src := `
title: Linux curl pipe
tags: [attack.t1059.004]
logsource: {product: linux, category: process_creation}
detection:
  selection:
    CommandLine|contains: 'curl http'
  condition: selection
`
	res := mustGen(t, src, "")
	if !res.Coverage.Emulable || res.Step.Executor != "bash" {
		t.Fatalf("%+v", res.Coverage)
	}
	if !strings.HasPrefix(res.Step.Command, "/bin/echo '") || !strings.Contains(res.Step.Command, "'curl http'") {
		t.Errorf("every word must be single-quoted: %s", res.Step.Command)
	}
}

func TestSigma_FileEventCreatesAnEmptyFileUnderTemp(t *testing.T) {
	src := `
title: Ransom note
tags: [attack.t1486]
logsource: {product: windows, category: file_event}
detection:
  selection:
    TargetFilename|endswith: '.locked'
  condition: selection
`
	res := mustGen(t, src, "")
	if !res.Coverage.Emulable {
		t.Fatalf("%+v", res.Coverage)
	}
	if !strings.Contains(res.Step.Command, `type nul >`) || !strings.Contains(res.Step.Command, `.locked"`) || !strings.Contains(res.Step.Command, `%TEMP%\audspect-`) {
		t.Errorf("%s", res.Step.Command)
	}
	if !strings.Contains(res.Step.Cleanup, "rmdir /s /q") {
		t.Errorf("cleanup: %s", res.Step.Cleanup)
	}
}

func TestSigma_AggregateConditionsAreRefused(t *testing.T) {
	src := `
title: Many
tags: [attack.t1110]
logsource: {product: windows, category: process_creation}
detection:
  selection: {CommandLine|contains: 'x'}
  condition: selection | count() > 5
`
	if _, err := ParseSigma([]byte(src)); err == nil || !strings.Contains(err.Error(), "aggregate") {
		t.Errorf("want an aggregate error, got %v", err)
	}
}

func TestSigma_SameRuleSameMarker(t *testing.T) {
	a, b := mustGen(t, certutilRule, ""), mustGen(t, certutilRule, "")
	if a.Step.Marker != b.Step.Marker || !strings.HasPrefix(a.Step.Marker, "imp-") {
		t.Errorf("marker must be stable: %s %s", a.Step.Marker, b.Step.Marker)
	}
}

func TestSigma_ConditionSolver(t *testing.T) {
	c, err := parseCondition("(a or b) and not c")
	if err != nil {
		t.Fatal(err)
	}
	sets, _ := satisfyingSets(c, []string{"a", "b", "c"})
	if len(sets) != 3 || len(sets[0]) != 1 {
		t.Errorf("smallest sets first: %v", sets)
	}
	c2, _ := parseCondition("all of them")
	sets2, _ := satisfyingSets(c2, []string{"x", "y"})
	if len(sets2) != 1 || len(sets2[0]) != 2 {
		t.Errorf("all of them: %v", sets2)
	}
}
