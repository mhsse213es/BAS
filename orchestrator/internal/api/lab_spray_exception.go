package api

import "github.com/audspect/bas/internal/scenario"

// labExceptionScenarios are the only scenarios that may receive the lab exemption.
// Each scenario's destructive attack steps are listed in the agent's
// labExemptActions map (agent/spray_interlock.go); the server only decides which
// dispatches are eligible, and the agent re-checks scenario and action key.
var labExceptionScenarios = map[string]bool{
	"ad-password-spray-lab":    true,
	"ad-password-guessing-lab": true,
}

// labExceptionScenario reports whether a scenario is eligible for the exemption.
func labExceptionScenario(scenarioID string) bool {
	return labExceptionScenarios[scenarioID]
}

// labExemptPolicy returns the LivePolicy to send for a dispatch. LabException on
// the wire always equals exempt, the server's eligibility decision, so no value
// carried by the scenario itself can grant the exemption. A nil base stays nil
// unless the dispatch is exempt.
func labExemptPolicy(base *scenario.LivePolicy, exempt bool) *scenario.LivePolicy {
	if base == nil && !exempt {
		return nil
	}
	p := &scenario.LivePolicy{}
	if base != nil {
		*p = *base
	}
	p.LabException = exempt
	return p
}

// labExceptionFor reports whether a dispatch may carry the lab exemption. Both
// must hold: the target agent is the designated lab agent (is_spray_lab) and the
// scenario is eligible. Anything else gets false, so the destructive veto applies.
func labExceptionFor(scenarioID string, agentIsSprayLab bool) bool {
	return agentIsSprayLab && labExceptionScenario(scenarioID)
}
