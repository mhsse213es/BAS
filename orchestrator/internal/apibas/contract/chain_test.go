package contract

import (
	"strings"
	"testing"
)

// A setup step belongs to the attacker's chain. A setup step from a different
// identity, or with a different auth mode, must not load.
func TestSetupStepMustUseAttackerIdentity(t *testing.T) {
	doc := `id: API-BAS-AUTHZ-004
name: x
category: AUTHZ
claim: function_level
attack_objective: x
threat_model:
  objective: x
preconditions:
  fixture: f
  object: O
steps:
  - id: b
    role: baseline
    identity: customer-b
    method: GET
    path: /p
    hypothesis: h
  - id: s
    role: setup
    identity: customer-b
    method: PATCH
    path: /r
    body: '{"role": "admin"}'
    hypothesis: h
  - id: a
    role: attack
    identity: customer-a
    method: PATCH
    path: /p
    body: '{"status": "x"}'
    hypothesis: h
denied_statuses: [403]
expected_control: x
ground_truth:
  adapters: [state]
detection_assertion:
  status: not_evaluated
  reason: r
side_effect_class: STATE_CHANGE_SANDBOX
cleanup: [reset]
`
	_, err := Parse([]byte(doc))
	if err == nil || !strings.Contains(err.Error(), "attacker identity") {
		t.Fatalf("Parse error = %v, want an attacker-identity requirement", err)
	}
}
