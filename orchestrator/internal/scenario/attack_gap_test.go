package scenario

import (
	"strings"
	"testing"
)

const attackGapScenario = `id: t-attack-gap
product_line: killchain
name: t
executable: true
supported_os: [windows]
steps:
  - name: s
    %s
    executor: powershell
    command: 'x'
`

func TestParseYAML_AttackGapAllowsEmptyTechnique(t *testing.T) {
	src := []byte(strings.Replace(attackGapScenario, "%s", "attack_gap: no_clean_attack_technique", 1))
	sc, err := ParseYAML(src)
	if err != nil {
		t.Fatalf("empty technique with attack_gap rejected: %v", err)
	}
	if sc.Steps[0].AttackGap != AttackGapNoCleanTechnique {
		t.Fatalf("AttackGap = %q, want %q", sc.Steps[0].AttackGap, AttackGapNoCleanTechnique)
	}
}

func TestParseYAML_EmptyTechniqueWithoutGapRejected(t *testing.T) {
	src := []byte(strings.Replace(attackGapScenario, "%s", "", 1))
	_, err := ParseYAML(src)
	if err == nil || !strings.Contains(err.Error(), "missing a technique_id") {
		t.Fatalf("expected missing technique_id error, got %v", err)
	}
}

func TestParseYAML_AttackGapUnknownValueRejected(t *testing.T) {
	src := []byte(strings.Replace(attackGapScenario, "%s", "attack_gap: whatever", 1))
	_, err := ParseYAML(src)
	if err == nil || !strings.Contains(err.Error(), "attack_gap") {
		t.Fatalf("expected attack_gap error, got %v", err)
	}
}
