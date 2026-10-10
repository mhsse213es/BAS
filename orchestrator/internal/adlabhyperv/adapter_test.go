package adlabhyperv

import (
	"context"
	"errors"
	"testing"

	"github.com/audspect/bas/internal/adlabrt"
)

func TestProvision_UnknownTopologyErrors(t *testing.T) {
	h := &HyperV{Cmd: newFakeCommander()}
	if _, err := h.Provision(context.Background(), adlabrt.LabSpec{Name: "nope"}); err == nil {
		t.Fatal("unknown topology must error, never silently provision nothing")
	}
}

func TestProvision_HappyPathReturnsTarget(t *testing.T) {
	h := &HyperV{Cmd: newFakeCommander()}
	tgt, err := h.Provision(context.Background(), adlabrt.LabSpec{Name: "dc-only"})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if tgt.ID == "" {
		t.Fatal("provision must return a non-empty Target handle")
	}
}

func TestProvision_CommanderErrorSurfaces(t *testing.T) {
	f := newFakeCommander()
	f.provision = func(Command) (Output, error) { return Output{}, errors.New("hyper-v down") }
	h := &HyperV{Cmd: f}
	if _, err := h.Provision(context.Background(), adlabrt.LabSpec{Name: "dc-only"}); err == nil {
		t.Fatal("a commander error must surface as a provision error")
	}
}

func TestTeardown_IdempotentOnCommanderDone(t *testing.T) {
	h := &HyperV{Cmd: newFakeCommander()}
	if err := h.Teardown(context.Background(), adlabrt.Target{ID: "dc-only/run1"}); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	// Safe to call again (half-provisioned / already-gone target).
	if err := h.Teardown(context.Background(), adlabrt.Target{ID: ""}); err != nil {
		t.Fatalf("second teardown on empty target must not error: %v", err)
	}
}
