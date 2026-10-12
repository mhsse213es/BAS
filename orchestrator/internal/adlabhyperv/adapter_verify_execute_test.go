package adlabhyperv

import (
	"context"
	"errors"
	"testing"

	"github.com/audspect/bas/internal/adlabrt"
)

func TestVerifyIsolation_AllProbesPassVerifies(t *testing.T) {
	h := &HyperV{Cmd: newFakeCommander()}
	res, err := h.VerifyIsolation(context.Background(), adlabrt.Target{ID: "dc-only/run1"})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.Verified {
		t.Fatalf("all probes passing must verify, got %+v", res)
	}
}

func TestVerifyIsolation_OneIndeterminateProbeDenies(t *testing.T) {
	f := newFakeCommander()
	f.probe = func(cmd Command) (Output, error) {
		if cmd.Args["check"] == string(CheckNoExternalRoute) {
			return Output{Passed: true, Determinate: false, Detail: "probe timed out"}, nil
		}
		return Output{Passed: true, Determinate: true}, nil
	}
	h := &HyperV{Cmd: f}
	res, _ := h.VerifyIsolation(context.Background(), adlabrt.Target{ID: "dc-only/run1"})
	if res.Verified {
		t.Fatal("an indeterminate probe must leave the lab unverified")
	}
}

func TestVerifyIsolation_ProbeErrorIsUnverifiedNotFatal(t *testing.T) {
	f := newFakeCommander()
	f.probe = func(Command) (Output, error) { return Output{}, errors.New("probe exec failed") }
	h := &HyperV{Cmd: f}
	res, err := h.VerifyIsolation(context.Background(), adlabrt.Target{ID: "dc-only/run1"})
	if err != nil {
		t.Fatalf("a probe error should be recorded as unverified, not returned as error: %v", err)
	}
	if res.Verified {
		t.Fatal("a probe error must leave the lab unverified (fail closed)")
	}
}

func TestExecute_IncompleteObservationIsInconclusive(t *testing.T) {
	f := newFakeCommander()
	f.execute = func(Command) (Output, error) {
		return Output{PostconditionObserved: false, Complete: false, Detail: "garbled"}, nil
	}
	h := &HyperV{Cmd: f}
	obs, err := h.Execute(context.Background(), adlabrt.Target{ID: "dc-only/run1"}, adlabrt.ValidationCase{Name: "dcsync-pos"})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if obs.Complete {
		t.Fatal("an incomplete commander output must map to Complete=false")
	}
}

func TestExecute_CommanderErrorSurfaces(t *testing.T) {
	f := newFakeCommander()
	f.execute = func(Command) (Output, error) { return Output{}, errors.New("exec failed") }
	h := &HyperV{Cmd: f}
	if _, err := h.Execute(context.Background(), adlabrt.Target{ID: "dc-only/run1"}, adlabrt.ValidationCase{Name: "x"}); err == nil {
		t.Fatal("a commander execute error must surface")
	}
}
