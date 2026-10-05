package contentregistry

import "testing"

func TestAnalyze_TechniquesSortedDedupedUpper(t *testing.T) {
	a, err := analyzeArtifact([]byte(`id: x
name: X
art_techniques: [t1082, T1059.001]
steps:
  - name: s
    technique_id: T1082
    framework: custom
    command: whoami
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := a.techniqueIDs; len(got) != 2 || got[0] != "T1059.001" || got[1] != "T1082" {
		t.Fatalf("technique ids = %v", got)
	}
	if a.structural.outcome != "PASS" {
		t.Fatalf("structural = %+v", a.structural)
	}
}

func TestAnalyze_DynamicScopeAndStructuralFailures(t *testing.T) {
	a, err := analyzeArtifact([]byte("id: sweep\nname: S\nart_all_platform: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if a.dynamicScope != "art_all_platform" || len(a.techniqueIDs) != 0 {
		t.Fatalf("scope=%q ids=%v", a.dynamicScope, a.techniqueIDs)
	}
	if a.structural.outcome != "PASS" {
		t.Fatalf("art_all_platform is a real execution mode: %+v", a.structural)
	}
	bad, err := analyzeArtifact([]byte("id: bad\nart_techniques: [T10]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if bad.structural.outcome != "FAIL" {
		t.Fatalf("missing name + malformed technique must FAIL: %+v", bad.structural)
	}
}

func TestAnalyze_RejectsUnparseableAndMissingID(t *testing.T) {
	if _, err := analyzeArtifact([]byte("id: [unclosed")); err == nil {
		t.Fatal("unparseable YAML must error")
	}
	if _, err := analyzeArtifact([]byte("name: no id\n")); err == nil {
		t.Fatal("missing id must error")
	}
}

func TestAnalyze_DynamicSafetyIsUnresolvedUnlessDestructive(t *testing.T) {
	cases := []struct{ name, yaml, want string }{
		{"dynamic only", "id: d\nname: D\nart_all_platform: true\n", "unresolved"},
		{"static safe plus art_techniques", `id: d
name: D
art_techniques: [T1082]
steps:
  - {name: a, technique_id: T1082, framework: custom, command: x}
`, "unresolved"},
		{"static destructive plus dynamic", `id: d
name: D
art_all_platform: true
steps:
  - {name: b, technique_id: T9999, framework: custom, command: y}
`, "destructive"},
		{"static only stays non_destructive", `id: d
name: D
steps:
  - {name: a, technique_id: T1082, framework: custom, command: x}
`, "non_destructive"},
	}
	for _, c := range cases {
		a, err := analyzeArtifact([]byte(c.yaml))
		if err != nil {
			t.Fatal(err)
		}
		if a.safety.verdict != c.want {
			t.Errorf("%s: verdict = %s, want %s", c.name, a.safety.verdict, c.want)
		}
	}
}

func TestAnalyze_CombinedDynamicModesAllRecorded(t *testing.T) {
	a, err := analyzeArtifact([]byte("id: c\nname: C\nart_all_windows: true\nart_techniques: [T1082]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.dynamicModes) != 2 || a.dynamicModes[0] != "art_all_windows" || a.dynamicModes[1] != "art_techniques" {
		t.Fatalf("modes = %v", a.dynamicModes)
	}
	if a.dynamicScope != "art_all_windows" {
		t.Fatalf("scope = %q", a.dynamicScope)
	}
	n := 0
	for _, d := range a.safety.detail {
		if d["dynamic"] == true {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("safety detail must record every mode: %v", a.safety.detail)
	}
}

func TestAnalyze_SafetyWorstStepWins(t *testing.T) {
	a, err := analyzeArtifact([]byte(`id: s
name: S
steps:
  - {name: a, technique_id: T1082, framework: custom, command: x}
  - {name: b, technique_id: T9999, framework: custom, command: y}
`))
	if err != nil {
		t.Fatal(err)
	}
	// T9999 has no execclass entry -> fails closed to destructive.
	if a.safety.verdict != "destructive" {
		t.Fatalf("verdict = %s", a.safety.verdict)
	}
}
