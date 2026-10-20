// Package killchain holds the pure model for Full Kill Chain campaigns: a
// directed acyclic graph of stages, the evidence contract for each stage,
// and a deterministic verdict engine. It has no database, network or vendor
// dependencies. Design: docs/fullkillchain-foundation-audit.md.
package killchain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
)

// StageState is the execution state of one stage. It records what happened to
// the stage, not what the stage proved. Verdicts are derived in verdict.go.
type StageState string

const (
	StatePending    StageState = "pending"
	StateDispatched StageState = "dispatched"
	StateCompleted  StageState = "completed"
	// StateNotReached: an upstream verdict closed the path, so the stage was
	// never executed. Its verdict is NOT_TESTED, never a pass.
	StateNotReached StageState = "not_reached"
	StateFailed     StageState = "failed"
	// StateInterrupted: the process stopped while the stage was dispatched.
	// Partial evidence is kept and the stage is not re-executed.
	StateInterrupted StageState = "interrupted"
	StateCancelled   StageState = "cancelled"
)

// Verdict is the stage verdict. The eight values are the mandatory vocabulary
// from fullkillchain.txt section 5.
type Verdict string

const (
	VerdictBlocked              Verdict = "BLOCKED"
	VerdictDetected             Verdict = "DETECTED"
	VerdictAllowed              Verdict = "ALLOWED"
	VerdictDetectedNotContained Verdict = "DETECTED_NOT_CONTAINED"
	VerdictNotDetected          Verdict = "NOT_DETECTED"
	VerdictNotTested            Verdict = "NOT_TESTED"
	VerdictInconclusive         Verdict = "INCONCLUSIVE"
	VerdictError                Verdict = "ERROR"
)

// AllVerdicts lists the eight verdicts in the order used for reporting.
var AllVerdicts = []Verdict{
	VerdictBlocked, VerdictDetected, VerdictAllowed, VerdictDetectedNotContained,
	VerdictNotDetected, VerdictNotTested, VerdictInconclusive, VerdictError,
}

// defaultContinueOn is the set of upstream verdicts that let a downstream stage
// run. BLOCKED closes the path, because the attack did not progress. ERROR and
// NOT_TESTED close it too, so no downstream result is reported as tested.
// INCONCLUSIVE continues, because the attack may have progressed.
var defaultContinueOn = map[Verdict]bool{
	VerdictAllowed:              true,
	VerdictDetected:             true,
	VerdictDetectedNotContained: true,
	VerdictNotDetected:          true,
	VerdictInconclusive:         true,
}

// StagePolicy states the verified control expectation for a stage. The verdict
// engine uses it to decide whether an observed outcome is a violation. It
// comes from the campaign definition, which is authored and reviewed, never
// from a finding.
type StagePolicy struct {
	// ShouldBlock: a verified policy says this action must be prevented.
	ShouldBlock bool `json:"shouldBlock"`
	// ContainmentRequired: detection alone is not enough; containment must be verified.
	ContainmentRequired bool `json:"containmentRequired"`
	// Source names the policy document or control baseline it came from.
	Source string `json:"source"`
}

// StageDef is one node in a campaign graph.
type StageDef struct {
	Key        string      `json:"key"`
	ScenarioID string      `json:"scenarioId"`
	Variant    string      `json:"variant,omitempty"`
	Requires   []string    `json:"requires,omitempty"`
	ContinueOn []Verdict   `json:"continueOn,omitempty"`
	Policy     StagePolicy `json:"policy"`
}

// CampaignDef is an authored, versioned campaign graph.
type CampaignDef struct {
	ID      string     `json:"id"`
	Name    string     `json:"name"`
	Version int        `json:"version"`
	Stages  []StageDef `json:"stages"`
}

var keyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// Validate checks the graph and returns the stage keys in a deterministic
// topological order (ties broken by key). It rejects a graph with a cycle, an
// unknown or self-referencing requirement, a duplicate or malformed key, a
// missing scenario, or an invalid continue-on verdict.
func (c CampaignDef) Validate() ([]string, error) {
	if c.ID == "" {
		return nil, fmt.Errorf("killchain: campaign id is required")
	}
	if c.Version < 1 {
		return nil, fmt.Errorf("killchain: campaign %s version must be at least 1", c.ID)
	}
	if len(c.Stages) == 0 {
		return nil, fmt.Errorf("killchain: campaign %s has no stages", c.ID)
	}
	byKey := map[string]StageDef{}
	for _, s := range c.Stages {
		if !keyPattern.MatchString(s.Key) {
			return nil, fmt.Errorf("killchain: stage key %q must be lowercase letters, digits or hyphens", s.Key)
		}
		if _, dup := byKey[s.Key]; dup {
			return nil, fmt.Errorf("killchain: stage key %q appears twice", s.Key)
		}
		if s.ScenarioID == "" {
			return nil, fmt.Errorf("killchain: stage %q has no scenario id", s.Key)
		}
		for _, v := range s.ContinueOn {
			if !isVerdict(v) {
				return nil, fmt.Errorf("killchain: stage %q continueOn has unknown verdict %q", s.Key, v)
			}
		}
		byKey[s.Key] = s
	}
	indeg := map[string]int{}
	children := map[string][]string{}
	for _, s := range c.Stages {
		indeg[s.Key] += 0
		for _, r := range s.Requires {
			if r == s.Key {
				return nil, fmt.Errorf("killchain: stage %q requires itself", s.Key)
			}
			if _, ok := byKey[r]; !ok {
				return nil, fmt.Errorf("killchain: stage %q requires unknown stage %q", s.Key, r)
			}
			indeg[s.Key]++
			children[r] = append(children[r], s.Key)
		}
	}
	var ready []string
	for k, d := range indeg {
		if d == 0 {
			ready = append(ready, k)
		}
	}
	sort.Strings(ready)
	var order []string
	for len(ready) > 0 {
		k := ready[0]
		ready = ready[1:]
		order = append(order, k)
		next := append([]string(nil), children[k]...)
		sort.Strings(next)
		for _, ch := range next {
			indeg[ch]--
			if indeg[ch] == 0 {
				ready = append(ready, ch)
				sort.Strings(ready)
			}
		}
	}
	if len(order) != len(c.Stages) {
		return nil, fmt.Errorf("killchain: campaign %s contains a cycle", c.ID)
	}
	return order, nil
}

// Stage returns the definition for key.
func (c CampaignDef) Stage(key string) (StageDef, bool) {
	for _, s := range c.Stages {
		if s.Key == key {
			return s, true
		}
	}
	return StageDef{}, false
}

// Continues reports whether an upstream verdict lets stage s run.
func (s StageDef) Continues(upstream Verdict) bool {
	if len(s.ContinueOn) > 0 {
		for _, v := range s.ContinueOn {
			if v == upstream {
				return true
			}
		}
		return false
	}
	return defaultContinueOn[upstream]
}

func isVerdict(v Verdict) bool {
	for _, a := range AllVerdicts {
		if a == v {
			return true
		}
	}
	return false
}

// ParseCampaignDef decodes and validates one campaign definition. Unknown
// fields are refused, so a misspelt policy field can never silently become a
// default. Trailing data is refused too.
func ParseCampaignDef(data []byte) (CampaignDef, error) {
	var def CampaignDef
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&def); err != nil {
		return CampaignDef{}, fmt.Errorf("killchain: invalid campaign JSON: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return CampaignDef{}, fmt.Errorf("killchain: unexpected data after the campaign object")
	}
	if _, err := def.Validate(); err != nil {
		return CampaignDef{}, err
	}
	return def, nil
}
