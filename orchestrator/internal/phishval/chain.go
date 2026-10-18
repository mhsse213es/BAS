package phishval

// ChainStageStatus mirrors emailgwcampaign.StageStatus's own shape for the
// two states a chain-reporting consumer needs -- independently declared,
// never imported, per this package's own "borrow a pattern, never a
// shared type" rule.
type ChainStageStatus string

const (
	ChainStageCompleted ChainStageStatus = "completed"
	// ChainStageBlocked mirrors emailgwcampaign.StageBlockedByPrerequisite's
	// own non-fabrication guarantee: a stage in this state has no Outcome
	// and no ReadDimension, always -- there is nothing to grade, nothing
	// that could be mistaken for an executed result.
	ChainStageBlocked ChainStageStatus = "blocked_by_prerequisite"
)

// ChainStage is one stage of a multi-stage Phishing BAS Chain. Exactly one
// of Outcome (an injected stage that actually dispatched) or ReadDimension
// (a derived stage that only reads an upstream stage's own dimension,
// without a new dispatch) is set when Status is ChainStageCompleted;
// neither is set when Status is ChainStageBlocked.
type ChainStage struct {
	Key           string
	Label         string
	Status        ChainStageStatus
	BlockedReason string
	Outcome       *Outcome
	ReadDimension *DimensionResult
}

// Chain is an ordered, gated sequence of stage results sharing one RunID
// -- phishing.txt's capability #1 ("multi-stage attack-chain scenarios"):
// "Implement linked stages with shared run IDs and explicit dependencies
// ... Each stage gets its own verdict; the chain gets a separate overall
// verdict."
type Chain struct {
	RunID      string
	ScenarioID string
	Stages     []ChainStage
}

// StageByKey resolves one stage within the chain, or false if unknown.
func (c Chain) StageByKey(key string) (ChainStage, bool) {
	for _, s := range c.Stages {
		if s.Key == key {
			return s, true
		}
	}
	return ChainStage{}, false
}

// StoppedAtStage identifies the first completed stage whose Enforcement
// dimension graded Pass -- the chain's own answer to phishing.txt
// capability #1's acceptance bar: "Audspect can identify the exact stage
// and control where the attack was stopped." A blocked stage is skipped:
// it never ran, so it did not stop anything -- its own upstream gate did,
// and that upstream stage is what this method reports.
func (c Chain) StoppedAtStage() (key string, stopped bool) {
	for _, s := range c.Stages {
		if s.Status != ChainStageCompleted || s.Outcome == nil {
			continue
		}
		if s.Outcome.Enforcement.Verdict == VerdictPass {
			return s.Key, true
		}
	}
	return "", false
}
