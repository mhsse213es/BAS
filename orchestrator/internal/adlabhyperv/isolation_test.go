package adlabhyperv

import (
	"strings"
	"testing"
)

func allPass() map[CheckKind]ProbeResult {
	m := map[CheckKind]ProbeResult{}
	for _, c := range RequiredChecks() {
		m[c] = ProbeResult{Passed: true, Determinate: true}
	}
	return m
}

func TestEvaluateIsolation_AllChecksPassAndDeterminateVerifies(t *testing.T) {
	res := EvaluateIsolation(RequiredChecks(), allPass())
	if !res.Verified {
		t.Fatalf("all-pass must verify, got %+v", res)
	}
	if !strings.Contains(res.Method, string(CheckNoExternalRoute)) {
		t.Errorf("Method must record the checks run, got %q", res.Method)
	}
}

func TestEvaluateIsolation_EmptyResultsFailClosed(t *testing.T) {
	res := EvaluateIsolation(RequiredChecks(), map[CheckKind]ProbeResult{})
	if res.Verified {
		t.Fatal("no probe results must fail closed, never verify")
	}
}

func TestEvaluateIsolation_IndeterminateIsNotIsolated(t *testing.T) {
	m := allPass()
	m[CheckNoExternalRoute] = ProbeResult{Passed: true, Determinate: false, Detail: "probe timed out"}
	res := EvaluateIsolation(RequiredChecks(), m)
	if res.Verified {
		t.Fatal("an indeterminate check must be treated as not isolated")
	}
	if !strings.Contains(res.Detail, string(CheckNoExternalRoute)) {
		t.Errorf("Detail should name the failing check, got %q", res.Detail)
	}
}

func TestEvaluateIsolation_FailedCheckDenies(t *testing.T) {
	m := allPass()
	m[CheckPrivateSwitch] = ProbeResult{Passed: false, Determinate: true, Detail: "adapter on External switch"}
	if EvaluateIsolation(RequiredChecks(), m).Verified {
		t.Fatal("a failed check must deny")
	}
}

func TestEvaluateIsolation_MissingOneRequiredCheckDenies(t *testing.T) {
	m := allPass()
	delete(m, CheckDistinctIdentity)
	if EvaluateIsolation(RequiredChecks(), m).Verified {
		t.Fatal("a missing required check must deny (fail closed)")
	}
}
