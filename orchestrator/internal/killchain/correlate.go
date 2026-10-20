package killchain

import (
	"fmt"
	"sort"
	"time"
)

// Ancestors returns every stage that is upstream of key, directly or through
// other stages. A stage is never its own ancestor.
func (c CampaignDef) Ancestors(key string) map[string]bool {
	direct := map[string][]string{}
	for _, s := range c.Stages {
		direct[s.Key] = s.Requires
	}
	out := map[string]bool{}
	var walk func(string)
	walk = func(k string) {
		for _, r := range direct[k] {
			if !out[r] {
				out[r] = true
				walk(r)
			}
		}
	}
	walk(key)
	return out
}

// CheckCausedBy reports an error when ev names a causal parent that is not
// upstream of its stage. Evidence may only cite an upstream stage.
func CheckCausedBy(def CampaignDef, stageKey string, causedBy string) error {
	if causedBy == "" {
		return nil
	}
	if !def.Ancestors(stageKey)[causedBy] {
		return fmt.Errorf("causedBy %q is not an upstream stage of %q", causedBy, stageKey)
	}
	return nil
}

// TimelineEvent is one stage's outcome placed on the campaign timeline.
type TimelineEvent struct {
	Stage       string          `json:"stage"`
	ScenarioID  string          `json:"scenarioId"`
	Verdict     Verdict         `json:"verdict"`
	Prevention  PreventionValue `json:"prevention,omitempty"`
	Detection   DetectionValue  `json:"detection,omitempty"`
	Response    ResponseValue   `json:"response,omitempty"`
	ActionAt    time.Time       `json:"actionAt,omitempty"`
	CausedBy    string          `json:"causedBy,omitempty"`
	ExecutionID string          `json:"executionId,omitempty"`
}

// BuildTimeline produces the ordered evidence timeline for a campaign. It is
// built from stored stage records alone. Events are ordered by action time when
// a stage has one, and by topological order otherwise, so the result is the
// same on every read. Stages with no verdict yet are not on the timeline.
func BuildTimeline(def CampaignDef, stages map[string]StageRecord) ([]TimelineEvent, error) {
	order, err := def.Validate()
	if err != nil {
		return nil, err
	}
	rank := map[string]int{}
	for i, k := range order {
		rank[k] = i
	}
	var events []TimelineEvent
	for _, k := range order {
		sr, ok := stages[k]
		if !ok || sr.Verdict == "" {
			continue
		}
		st, _ := def.Stage(k)
		ev := TimelineEvent{Stage: k, ScenarioID: st.ScenarioID, Verdict: sr.Verdict, ExecutionID: sr.ExecutionID}
		if sr.Evidence != nil {
			ev.Prevention = sr.Evidence.Prevention.Value
			ev.Detection = sr.Evidence.Detection.Value
			ev.Response = sr.Evidence.Response.Value
			ev.ActionAt = sr.Evidence.Timestamps.ActionAt
			ev.CausedBy = sr.Evidence.CausedBy
		}
		events = append(events, ev)
	}
	sort.SliceStable(events, func(i, j int) bool {
		a, b := events[i], events[j]
		if !a.ActionAt.IsZero() && !b.ActionAt.IsZero() && !a.ActionAt.Equal(b.ActionAt) {
			return a.ActionAt.Before(b.ActionAt)
		}
		return rank[a.Stage] < rank[b.Stage]
	})
	return events, nil
}
