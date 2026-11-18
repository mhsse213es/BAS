// Package exfilchain builds a per-run report of the collection, staging and
// exfiltration chain from existing step results. It reads only what a run
// already recorded: it does not query telemetry, so "linked" means the stages
// carry the same run tag in their own output, not that a SIEM correlated them.
package exfilchain

import (
	"fmt"
	"regexp"
	"strings"
)

// Phase is one stage of the data-theft lifecycle.
type Phase string

const (
	PhaseDiscovery  Phase = "discovery"
	PhaseCollection Phase = "collection"
	PhaseStaging    Phase = "staging"
	PhaseArchive    Phase = "archive"
	PhaseTransfer   Phase = "transfer"
	PhaseOther      Phase = "other"
)

// chainOrder is the canonical lifecycle a complete chain should cover.
var chainOrder = []Phase{PhaseCollection, PhaseStaging, PhaseArchive, PhaseTransfer}

// PhaseOf maps a MITRE technique ID to its lifecycle phase. Unknown techniques
// are PhaseOther, never guessed into a phase.
func PhaseOf(technique string) Phase {
	t := strings.ToUpper(strings.TrimSpace(technique))
	switch {
	case hasPrefixAny(t, "T1083", "T1135", "T1217", "T1619"):
		return PhaseDiscovery
	case hasPrefixAny(t, "T1005", "T1039", "T1114", "T1115"):
		return PhaseCollection
	case hasPrefixAny(t, "T1074"):
		return PhaseStaging
	case hasPrefixAny(t, "T1560"):
		return PhaseArchive
	case hasPrefixAny(t, "T1041", "T1048", "T1567", "T1029", "T1052"):
		return PhaseTransfer
	}
	return PhaseOther
}

func hasPrefixAny(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// Input is one step's result as recorded for the run, in step order.
type Input struct {
	TechniqueID string
	StepName    string
	Result      string
	Details     string
}

// Stage is one step placed in the chain.
type Stage struct {
	Order       int    `json:"order"`
	Phase       Phase  `json:"phase"`
	TechniqueID string `json:"techniqueId"`
	StepName    string `json:"stepName"`
	Result      string `json:"result"`
	RunTag      string `json:"runTag,omitempty"`
}

// Report is the chain for one run.
type Report struct {
	Stages   []Stage  `json:"stages"`
	Missing  []Phase  `json:"missing"`
	Linked   bool     `json:"linked"`
	Findings []string `json:"findings"`
}

// runTagPattern matches the run tag a stage prints, either as part of a
// per-run folder name (bas_<name>_<8 hex>) or as run=<8 hex>.
var runTagPattern = regexp.MustCompile(`(?:bas_[a-z0-9]+_|run=)([0-9a-f]{8})`)

// Build places the run's steps in the chain and reports what is missing.
func Build(inputs []Input) Report {
	rep := Report{Stages: []Stage{}, Missing: []Phase{}, Findings: []string{}}
	seen := map[Phase]bool{}
	var tags []string
	for i, in := range inputs {
		ph := PhaseOf(in.TechniqueID)
		seen[ph] = true
		tag := ""
		if m := runTagPattern.FindStringSubmatch(in.Details); m != nil {
			tag = m[1]
			tags = append(tags, tag)
		}
		rep.Stages = append(rep.Stages, Stage{
			Order: i + 1, Phase: ph, TechniqueID: in.TechniqueID,
			StepName: in.StepName, Result: in.Result, RunTag: tag,
		})
	}

	for _, p := range chainOrder {
		if !seen[p] {
			rep.Missing = append(rep.Missing, p)
		}
	}

	// A transfer before any collection is a finding: the data had to come from somewhere.
	collected := false
	for _, s := range rep.Stages {
		if s.Phase == PhaseCollection || s.Phase == PhaseDiscovery {
			collected = true
		}
		if s.Phase == PhaseTransfer && !collected {
			rep.Findings = append(rep.Findings, "transfer ran before any collection step")
			break
		}
	}

	switch {
	case len(tags) == 0:
		rep.Findings = append(rep.Findings, "no run tag found in any stage output, so stages cannot be tied to one run")
	default:
		distinct := map[string]bool{}
		for _, t := range tags {
			distinct[t] = true
		}
		if len(distinct) > 1 {
			rep.Findings = append(rep.Findings, fmt.Sprintf("stages carry different run tags (%d distinct)", len(distinct)))
		} else {
			rep.Linked = true
		}
	}
	return rep
}

// Summary is the one-line reading of a report, for the console.
func (r Report) Summary() string {
	if r.Linked && len(r.Missing) == 0 && len(r.Findings) == 0 {
		return "Chain complete and linked to one run"
	}
	if r.Linked {
		return fmt.Sprintf("Linked to one run; missing: %d phase(s)", len(r.Missing))
	}
	return "Not linked to one run"
}
