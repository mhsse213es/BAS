package killchain

import (
	"strings"
	"testing"
)

func modeDef(modes ...string) CampaignDef {
	d := CampaignDef{ID: "mode-test", Version: 1}
	for i, m := range modes {
		key := "s" + string(rune('a'+i))
		d.Stages = append(d.Stages, StageDef{Key: key, ScenarioID: "scn-" + key, Mode: m})
	}
	return d
}

// An unset mode is posture. Campaigns signed before modes existed keep their meaning.
func TestStageMode_UnsetIsPosture(t *testing.T) {
	st := StageDef{Key: "a", ScenarioID: "x"}
	if got := st.EffectiveMode(); got != ModePosture {
		t.Fatalf("effective mode = %q, want posture", got)
	}
}

func TestStageMode_RejectsUnknownMode(t *testing.T) {
	d := modeDef("posture", "bogus")
	if _, err := d.Validate(); err == nil || !strings.Contains(err.Error(), "mode") {
		t.Fatalf("err = %v, want the mode refusal", err)
	}
}

func TestStageMode_AcceptsEachKnownMode(t *testing.T) {
	d := modeDef("", "posture", "telemetry", "lab")
	if _, err := d.Validate(); err != nil {
		t.Fatalf("known modes refused: %v", err)
	}
}

// The mode is in the definition, so it parses from the signed bytes.
func TestStageMode_ParsesFromDefinition(t *testing.T) {
	raw := []byte(`{"id":"m","version":1,"stages":[{"key":"a","scenarioId":"x","mode":"lab","policy":{}}]}`)
	d, err := ParseCampaignDef(raw)
	if err != nil {
		t.Fatal(err)
	}
	if d.Stages[0].EffectiveMode() != ModeLab {
		t.Fatalf("mode = %q, want lab", d.Stages[0].EffectiveMode())
	}
}

// LiveStages reports the stages that need approval, and whether any needs lab approval.
func TestStageMode_LiveAndLabStagesAreListed(t *testing.T) {
	d := modeDef("posture", "telemetry", "lab")
	live, lab := d.LiveAndLabStages()
	if len(live) != 2 || live[0] != "sb" || live[1] != "sc" {
		t.Fatalf("live = %v, want sb and sc", live)
	}
	if len(lab) != 1 || lab[0] != "sc" {
		t.Fatalf("lab = %v, want sc", lab)
	}
}
