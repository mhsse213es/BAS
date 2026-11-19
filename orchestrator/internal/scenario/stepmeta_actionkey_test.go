package scenario

import "testing"

func TestBuildStepMeta_PersistsActionKey(t *testing.T) {
	steps := []ScenarioStep{{TaskID: "t1", TechniqueID: "T1003.006", Name: "negative stage", ActionKey: "negative"}}
	meta := BuildStepMeta(steps, nil, ComponentVersions{})
	m, ok := meta["t1"]
	if !ok {
		t.Fatal("no step meta for the dispatched step")
	}
	if m.ActionKey != "negative" {
		t.Fatalf("ActionKey = %q, want negative -- dropping it collapses distinct authorized actions", m.ActionKey)
	}
}
