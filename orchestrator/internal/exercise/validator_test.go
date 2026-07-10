package exercise

import (
	"strings"
	"testing"
)

// hasErrContaining reports whether any error string contains sub.
func hasErrContaining(errs ValidationErrors, sub string) bool {
	for _, e := range errs {
		if strings.Contains(e, sub) {
			return true
		}
	}
	return false
}

func step(id string, deps ...string) PlanStep {
	return PlanStep{ID: id, Type: StepTypeNotify, DependsOn: deps}
}

func TestValidationErrors_Error(t *testing.T) {
	if got := (ValidationErrors{"a", "b"}).Error(); got != "a; b" {
		t.Fatalf("Error() = %q, want %q", got, "a; b")
	}
	if got := (ValidationErrors{}).Error(); got != "" {
		t.Fatalf("empty Error() = %q, want empty", got)
	}
}

func TestValidatePlan_ValidLinearAndDiamond(t *testing.T) {
	linear := &Plan{Steps: []PlanStep{step("a"), step("b", "a"), step("c", "b")}}
	if errs := ValidatePlan(linear); len(errs) != 0 {
		t.Fatalf("valid linear plan reported errors: %v", errs)
	}
	diamond := &Plan{Steps: []PlanStep{
		step("a"), step("b", "a"), step("c", "a"), step("d", "b", "c"),
	}}
	if errs := ValidatePlan(diamond); len(errs) != 0 {
		t.Fatalf("valid diamond plan reported errors: %v", errs)
	}
}

func TestValidatePlan_IDErrorsShortCircuit(t *testing.T) {
	missing := &Plan{Steps: []PlanStep{{ID: ""}, step("b")}}
	if errs := ValidatePlan(missing); !hasErrContaining(errs, "missing an id") {
		t.Fatalf("expected missing-id error, got %v", errs)
	}
	dup := &Plan{Steps: []PlanStep{step("a"), step("a")}}
	errs := ValidatePlan(dup)
	if !hasErrContaining(errs, `duplicate step id "a"`) {
		t.Fatalf("expected duplicate-id error, got %v", errs)
	}
}

func TestValidatePlan_UnknownDependency(t *testing.T) {
	p := &Plan{Steps: []PlanStep{step("a"), step("b", "nope")}}
	if errs := ValidatePlan(p); !hasErrContaining(errs, `depends_on unknown step "nope"`) {
		t.Fatalf("expected unknown-dependency error, got %v", errs)
	}
}

func TestValidatePlan_CycleDetection(t *testing.T) {
	selfLoop := &Plan{Steps: []PlanStep{step("a", "a")}}
	if errs := ValidatePlan(selfLoop); !hasErrContaining(errs, "circular dependency") {
		t.Fatalf("expected cycle error for self-loop, got %v", errs)
	}
	twoNode := &Plan{Steps: []PlanStep{step("a", "b"), step("b", "a")}}
	if errs := ValidatePlan(twoNode); !hasErrContaining(errs, "circular dependency") {
		t.Fatalf("expected cycle error for 2-node cycle, got %v", errs)
	}
}

func TestValidatePlan_ConditionSyntaxMatrix(t *testing.T) {
	cases := []struct {
		name    string
		cond    string
		wantErr bool
	}{
		{"empty", "", false},
		{"always", "always", false},
		{"true", "true", false},
		{"false", "false", false},
		{"never", "never", false},
		{"valid predicate", "step:a:clicked", false},
		{"wrong arity", "step:a", true},
		{"non-step prefix", "foo:a:clicked", true},
		{"empty step id", "step::clicked", true},
		{"unknown step", "step:zzz:clicked", true},
		{"unknown predicate", "step:a:exploded", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Plan{Steps: []PlanStep{step("a"), {ID: "b", Type: StepTypeNotify, Condition: tc.cond}}}
			errs := ValidatePlan(p)
			got := hasErrContaining(errs, "invalid condition")
			if got != tc.wantErr {
				t.Fatalf("cond %q: got invalid-condition=%v want %v (errs=%v)", tc.cond, got, tc.wantErr, errs)
			}
		})
	}
}

func TestValidatePlan_TimeoutAndDuration(t *testing.T) {
	neg := &Plan{Steps: []PlanStep{{ID: "a", Type: StepTypeWait, TimeoutSecs: -1}}}
	if errs := ValidatePlan(neg); !hasErrContaining(errs, "negative timeout_secs") {
		t.Fatalf("expected negative-timeout error, got %v", errs)
	}
	badDur := &Plan{Steps: []PlanStep{{ID: "a", Type: StepTypeWait, Config: StepConfig{WaitDuration: "notaduration"}}}}
	if errs := ValidatePlan(badDur); !hasErrContaining(errs, "invalid wait_duration") {
		t.Fatalf("expected bad-duration error, got %v", errs)
	}
	varDur := &Plan{Steps: []PlanStep{{ID: "a", Type: StepTypeWait, Config: StepConfig{WaitDuration: "${Wait}"}}}}
	if errs := ValidatePlan(varDur); hasErrContaining(errs, "invalid wait_duration") {
		t.Fatalf("${...} wait_duration must be skipped, got %v", errs)
	}
}

func TestValidatePlan_VariableReferences(t *testing.T) {
	// Undeclared ref flagged only when the plan declares variables.
	undeclared := &Plan{
		Variables: []VarDef{{Name: "Known", Type: VarTypeString}},
		Steps: []PlanStep{{ID: "a", Type: StepTypeNotify,
			Config: StepConfig{NotifyMsg: "hi ${Unknown}"}}},
	}
	if errs := ValidatePlan(undeclared); !hasErrContaining(errs, "undeclared variable ${Unknown}") {
		t.Fatalf("expected undeclared-variable error, got %v", errs)
	}
	// System variables are always allowed.
	sysVar := &Plan{
		Variables: []VarDef{{Name: "Known", Type: VarTypeString}},
		Steps: []PlanStep{{ID: "a", Type: StepTypeNotify,
			Config: StepConfig{NotifyMsg: "run ${ExecutionID} at ${Timestamp} by ${CurrentUser}"}}},
	}
	if errs := ValidatePlan(sysVar); hasErrContaining(errs, "undeclared variable") {
		t.Fatalf("system variables must not be flagged, got %v", errs)
	}
	// Duplicate variable name flagged.
	dupVar := &Plan{
		Variables: []VarDef{{Name: "X", Type: VarTypeString}, {Name: "X", Type: VarTypeString}},
		Steps:     []PlanStep{step("a")},
	}
	if errs := ValidatePlan(dupVar); !hasErrContaining(errs, `duplicate variable name "X"`) {
		t.Fatalf("expected duplicate-variable error, got %v", errs)
	}
}
