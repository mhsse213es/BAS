package api

import (
	"context"
	"errors"
	"fmt"

	"github.com/audspect/bas/internal/killchain"
	"github.com/audspect/bas/internal/scenario"
)

// ErrNoAgentBinding is returned when a stage's scenario resolves as executable
// but the campaign has no agent to run it on. Dispatch needs an agent and
// operator confirmations, which a campaign cannot supply on its own, so this is
// the honest end state until that binding exists.
var ErrNoAgentBinding = errors.New("no agent is bound to this campaign; dispatch is not wired")

// scenarioResolver is the one way a scenario may be obtained for execution.
// *scenario.Engine satisfies it.
type scenarioResolver interface {
	ResolveExecutable(ctx context.Context, id string) (scenario.ExecutableVersion, error)
}

// EngineStageExecutor runs campaign stages through the scenario engine's
// executable gate. It never runs a scenario the gate refuses, and it never
// fabricates evidence. Until an agent is bound, every stage ends in ERROR with
// the precise reason.
type EngineStageExecutor struct {
	Resolver scenarioResolver
	// AgentID is the agent a campaign runs on. Empty means no binding.
	AgentID string
}

// Start checks the scenario through the executable gate, then refuses to
// dispatch because no agent is bound.
func (x EngineStageExecutor) Start(ctx context.Context, campaignID string, st killchain.StageDef) (string, error) {
	if x.Resolver == nil {
		return "", fmt.Errorf("scenario %s: %w", st.ScenarioID, killchain.ErrNoExecutor)
	}
	if _, err := x.Resolver.ResolveExecutable(ctx, st.ScenarioID); err != nil {
		return "", fmt.Errorf("scenario %s is not executable: %w", st.ScenarioID, err)
	}
	if x.AgentID == "" {
		return "", fmt.Errorf("scenario %s resolves as executable, but campaign %s: %w", st.ScenarioID, campaignID, ErrNoAgentBinding)
	}
	return "", fmt.Errorf("scenario %s: %w", st.ScenarioID, killchain.ErrNoExecutor)
}

// Collect is never reached, because Start never returns an execution ID.
func (x EngineStageExecutor) Collect(context.Context, string) (killchain.StageEvidence, bool, bool, error) {
	return killchain.StageEvidence{}, false, true, killchain.ErrNoExecutor
}
