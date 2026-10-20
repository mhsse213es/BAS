package contract

import (
	"strings"
	"testing"
)

// A clean-projection claim is only meaningful if the response adapter proves
// there was no leak. Declaring it without the response adapter must not load.
func TestCleanIsEnforcementRequiresResponseAdapter(t *testing.T) {
	doc := `id: API-BAS-DATA-001
name: x
category: DATA
claim: property_level
clean_is_enforcement: true
attack_objective: x
threat_model:
  objective: x
preconditions:
  fixture: f
  object: O
steps:
  - id: b
    role: baseline
    identity: a
    method: GET
    path: /p
    hypothesis: h
  - id: a
    role: attack
    identity: a
    method: GET
    path: /p
    hypothesis: h
denied_statuses: [403]
expected_control: x
ground_truth:
  adapters: [state]
detection_assertion:
  status: not_evaluated
  reason: r
side_effect_class: READ_ONLY
`
	_, err := Parse([]byte(doc))
	if err == nil || !strings.Contains(err.Error(), "response adapter") {
		t.Fatalf("Parse error = %v, want a response-adapter requirement", err)
	}
}
