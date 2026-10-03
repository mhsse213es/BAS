package scenario

import "testing"

func TestFetchRawCalderaAbilities_ReportsRealPickedExecutor(t *testing.T) {
	// fetchAllCalderaAbilities hits a live Caldera; this test only exercises
	// the executor-selection logic FetchRawCalderaAbilities adds on top of
	// it, using a synthetic ability built directly (no network).
	ab := calderaAbilityFull{
		AbilityID:   "abc-123",
		Name:        "Clear Bash History",
		TechniqueID: "T1070.003",
		Executors: []calderaExecutor{
			{Name: "sh", Command: "cat /dev/null > ~/.bash_history"},
		},
	}
	raw := rawFromCalderaAbility(ab)
	if raw.Executor != "sh" {
		t.Errorf("Executor = %q, want %q (the real picked executor, not hardcoded)", raw.Executor, "sh")
	}
	if raw.Command != "cat /dev/null > ~/.bash_history" {
		t.Errorf("Command = %q, want the sh executor's real command", raw.Command)
	}
	if raw.AbilityID != "abc-123" || raw.TechniqueID != "T1070.003" {
		t.Errorf("provenance fields not carried through: %+v", raw)
	}
}
