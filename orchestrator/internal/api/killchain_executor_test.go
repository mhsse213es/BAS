package api

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/killchain"
	"github.com/audspect/bas/internal/scenario"
)

type fakeResolver struct {
	executable map[string]bool
	calls      int
}

func (f *fakeResolver) ResolveExecutable(_ context.Context, id string) (scenario.ExecutableVersion, error) {
	f.calls++
	if f.executable[id] {
		return scenario.ExecutableVersion{}, nil
	}
	return scenario.ExecutableVersion{}, errors.New("not registered")
}

func stageFor(id string) killchain.StageDef {
	return killchain.StageDef{Key: "s", ScenarioID: id}
}

// A scenario the gate refuses must never reach dispatch.
func TestEngineExecutor_RefusedScenarioNamesTheGate(t *testing.T) {
	x := EngineStageExecutor{Resolver: &fakeResolver{}, AgentID: "agent-1"}
	_, err := x.Start(context.Background(), "c", stageFor("missing"))
	if err == nil || !strings.Contains(err.Error(), "not executable") {
		t.Fatalf("err = %v, want a 'not executable' refusal", err)
	}
}

// An executable scenario with no agent bound is refused with the precise reason.
func TestEngineExecutor_ExecutableWithoutAgentSaysSo(t *testing.T) {
	fr := &fakeResolver{executable: map[string]bool{"credential-access": true}}
	x := EngineStageExecutor{Resolver: fr}
	_, err := x.Start(context.Background(), "c", stageFor("credential-access"))
	if !errors.Is(err, ErrNoAgentBinding) {
		t.Fatalf("err = %v, want ErrNoAgentBinding", err)
	}
	if fr.calls != 1 {
		t.Fatalf("the gate was consulted %d times, want exactly 1", fr.calls)
	}
}

// Even with an agent bound, dispatch is not wired, so Start refuses. Nothing is faked.
func TestEngineExecutor_AgentBoundStillRefusesUntilDispatchIsWired(t *testing.T) {
	x := EngineStageExecutor{Resolver: &fakeResolver{executable: map[string]bool{"lolbin-execution": true}}, AgentID: "agent-1"}
	if _, err := x.Start(context.Background(), "c", stageFor("lolbin-execution")); !errors.Is(err, killchain.ErrNoExecutor) {
		t.Fatalf("err = %v, want ErrNoExecutor", err)
	}
}

func TestEngineExecutor_NilResolverRefuses(t *testing.T) {
	x := EngineStageExecutor{}
	if _, err := x.Start(context.Background(), "c", stageFor("x")); !errors.Is(err, killchain.ErrNoExecutor) {
		t.Fatalf("err = %v, want ErrNoExecutor", err)
	}
}
