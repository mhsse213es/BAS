package scenario

import "testing"

func TestResolvedTaskIDs_MatchesDispatchTimeDedupe(t *testing.T) {
	declared := []Step{
		{Name: "Export A", TechniqueID: "T1567.002"},
		{Name: "Export B", TechniqueID: "T1567.002"},
		{Name: "Export A", TechniqueID: "T1567.002"},
		{Name: "Export A", TechniqueID: "T1048.002"},
	}
	got := ResolvedTaskIDs(declared)

	dispatched := make([]ScenarioStep, len(declared))
	for i, s := range declared {
		dispatched[i] = ScenarioStep{Name: s.Name, TechniqueID: s.TechniqueID, TaskID: TaskID(s.TechniqueID, s.Name)}
	}
	dedupeStepIdentity(dispatched)

	for i := range declared {
		if got[i] != dispatched[i].TaskID {
			t.Errorf("step %d: ResolvedTaskIDs=%s, dispatch TaskID=%s", i, got[i], dispatched[i].TaskID)
		}
	}
	if got[0] == got[2] {
		t.Error("the duplicated (technique, name) pair must get distinct task IDs")
	}
}
