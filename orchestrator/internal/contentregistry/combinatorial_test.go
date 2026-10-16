package contentregistry

import "testing"

// T1562 (Impair Defenses) -> defense-evasion; T1547 (Boot or Logon Autostart
// Execution) -> persistence, privilege-escalation. T1087 (Account Discovery)
// -> discovery. T1048 (Exfiltration Over Alternative Protocol) -> exfiltration;
// T1021 (Remote Services) -> lateral-movement -- both single-tactic, so the
// defense-evasion pairs below genuinely fire from two distinct components, not
// from one dual-tagged technique. All verified directly against
// internal/reporting/attackdata/attack_enrichment.json before writing this
// test, not guessed.

func TestCombinatorialRisk_FlagsDefenseEvasionPlusPersistence(t *testing.T) {
	components := []loadedComponent{
		{techniqueID: "T1562"},
		{techniqueID: "T1547"},
	}
	_, err := combinatorialRisk(components)
	if err == nil {
		t.Fatal("expected defense-evasion + persistence to be flagged as an elevated-risk combination")
	}
}

func TestCombinatorialRisk_FlagsDefenseEvasionPlusExecution(t *testing.T) {
	components := []loadedComponent{
		{techniqueID: "T1562"},
		{techniqueID: "T1059"},
	}
	_, err := combinatorialRisk(components)
	if err == nil {
		t.Fatal("expected defense-evasion + execution to be flagged as an elevated-risk combination")
	}
}

func TestCombinatorialRisk_FlagsDefenseEvasionPlusExfiltration(t *testing.T) {
	components := []loadedComponent{
		{techniqueID: "T1562"}, // defense-evasion
		{techniqueID: "T1048"}, // exfiltration
	}
	_, err := combinatorialRisk(components)
	if err == nil {
		t.Fatal("expected defense-evasion + exfiltration to be flagged as an elevated-risk combination")
	}
}

func TestCombinatorialRisk_FlagsDefenseEvasionPlusLateralMovement(t *testing.T) {
	components := []loadedComponent{
		{techniqueID: "T1562"}, // defense-evasion
		{techniqueID: "T1021"}, // lateral-movement
	}
	_, err := combinatorialRisk(components)
	if err == nil {
		t.Fatal("expected defense-evasion + lateral-movement to be flagged as an elevated-risk combination")
	}
}

func TestCombinatorialRisk_AllowsUnflaggedPair(t *testing.T) {
	components := []loadedComponent{
		{techniqueID: "T1562"}, // defense-evasion
		{techniqueID: "T1087"}, // discovery
	}
	tactics, err := combinatorialRisk(components)
	if err != nil {
		t.Fatalf("expected defense-evasion + discovery (not in the catalog) to succeed, got: %v", err)
	}
	if len(tactics) != 2 {
		t.Fatalf("expected 2 resolved tactics, got %v", tactics)
	}
}

func TestCombinatorialRisk_RefusesUnresolvableTechnique(t *testing.T) {
	components := []loadedComponent{
		{techniqueID: "T9999.999"}, // not a real ATT&CK technique -- confirmed absent from attack_enrichment.json
		{techniqueID: "T1059"},
	}
	_, err := combinatorialRisk(components)
	if err == nil {
		t.Fatal("expected an unresolvable technique_id to refuse the whole composition (fail-closed default)")
	}
}
