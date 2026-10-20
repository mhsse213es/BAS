package contract

import (
	"strings"
	"testing"
)

// repeatDoc builds a scenario whose attack step repeats n times with the given
// max_accepted_attempts, optionally putting the repeat on the setup step instead.
func repeatDoc(attackRepeat int, maxAccepted int, setupRepeat int) string {
	return `id: API-BAS-ABUSE-001
name: x
category: ABUSE
claim: property_level
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
    method: POST
    path: /s
    body: '{"x": 1}'
    repeat: ` + itoa(setupRepeat) + `
    hypothesis: h
  - id: a
    role: attack
    identity: customer-b
    method: POST
    path: /p
    body: '{"x": 1}'
    repeat: ` + itoa(attackRepeat) + `
    hypothesis: h
denied_statuses: [429]
max_accepted_attempts: ` + itoa(maxAccepted) + `
expected_control: x
ground_truth:
  adapters: [state]
detection_assertion:
  status: not_evaluated
  reason: r
side_effect_class: STATE_CHANGE_SANDBOX
cleanup: [reset]
`
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

func TestRepeatNeedsAcceptedLimit(t *testing.T) {
	_, err := Parse([]byte(repeatDoc(5, 0, 0)))
	if err == nil || !strings.Contains(err.Error(), "max_accepted_attempts between") {
		t.Fatalf("Parse error = %v, want a limit requirement", err)
	}
}

func TestRepeatOnlyOnAttackStep(t *testing.T) {
	_, err := Parse([]byte(repeatDoc(1, 0, 3)))
	if err == nil || !strings.Contains(err.Error(), "only supported on the attack step") {
		t.Fatalf("Parse error = %v, want an attack-step restriction", err)
	}
}

func TestRepeatWithLimitParses(t *testing.T) {
	if _, err := Parse([]byte(repeatDoc(5, 3, 0))); err != nil {
		t.Fatalf("Parse error = %v, want nil", err)
	}
}
