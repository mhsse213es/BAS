package waforigin

import "fmt"

// BypassScenario is a Kind-A (bypass-pair) scenario: the claim that an
// existing, already-catalogued attack is prevented through a documented
// path, re-evaluated under a path that bypasses that documented control.
type BypassScenario struct {
	ID                      string
	Weakness                WeaknessType
	AttackVectorID          string
	BaselinePathDescription string
	BypassPathDescription   string
	Provenance              string
}

// NewBypassScenario validates at construction time, never at render time.
func NewBypassScenario(
	id string,
	weakness WeaknessType,
	attackVectorID string,
	baselinePathDescription string,
	bypassPathDescription string,
	provenance string,
) (BypassScenario, error) {
	if id == "" {
		return BypassScenario{}, fmt.Errorf("id must not be empty")
	}
	if weakness.Kind() != KindBypassPair {
		return BypassScenario{}, fmt.Errorf("weakness %q has Kind() %q, want %q", weakness, weakness.Kind(), KindBypassPair)
	}
	if attackVectorID == "" {
		return BypassScenario{}, fmt.Errorf("attackVectorID must not be empty")
	}
	if baselinePathDescription == "" {
		return BypassScenario{}, fmt.Errorf("baselinePathDescription must not be empty")
	}
	if bypassPathDescription == "" {
		return BypassScenario{}, fmt.Errorf("bypassPathDescription must not be empty")
	}
	if provenance == "" {
		return BypassScenario{}, fmt.Errorf("provenance must not be empty")
	}
	return BypassScenario{
		ID: id, Weakness: weakness, AttackVectorID: attackVectorID,
		BaselinePathDescription: baselinePathDescription, BypassPathDescription: bypassPathDescription,
		Provenance: provenance,
	}, nil
}
