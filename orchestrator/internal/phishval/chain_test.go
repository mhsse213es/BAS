package phishval

import "testing"

func TestChain_StoppedAtStage_FindsFirstEnforcementPass(t *testing.T) {
	chain := Chain{
		RunID: "run-1", ScenarioID: "PH-TEST-CHAIN",
		Stages: []ChainStage{
			{Key: "stage-1", Status: ChainStageCompleted, Outcome: &Outcome{
				Enforcement: DimensionResult{Verdict: VerdictFail},
			}},
			{Key: "stage-2", Status: ChainStageCompleted, Outcome: &Outcome{
				Enforcement: DimensionResult{Verdict: VerdictPass},
			}},
			{Key: "stage-3", Status: ChainStageCompleted, Outcome: &Outcome{
				Enforcement: DimensionResult{Verdict: VerdictPass},
			}},
		},
	}
	key, stopped := chain.StoppedAtStage()
	if !stopped || key != "stage-2" {
		t.Errorf("StoppedAtStage() = (%q, %v), want (%q, true)", key, stopped, "stage-2")
	}
}

func TestChain_StoppedAtStage_SkipsBlockedStages(t *testing.T) {
	chain := Chain{
		RunID: "run-1", ScenarioID: "PH-TEST-CHAIN",
		Stages: []ChainStage{
			{Key: "stage-1", Status: ChainStageCompleted, Outcome: &Outcome{
				Enforcement: DimensionResult{Verdict: VerdictFail},
			}},
			{Key: "stage-2", Status: ChainStageBlocked, BlockedReason: "upstream gate did not permit this stage"},
		},
	}
	_, stopped := chain.StoppedAtStage()
	if stopped {
		t.Error("StoppedAtStage() reported stopped=true, want false (no completed stage ever enforced a block)")
	}
}

func TestChain_StageByKey_ResolvesAndReportsUnknown(t *testing.T) {
	chain := Chain{Stages: []ChainStage{{Key: "stage-1", Status: ChainStageCompleted}}}
	if _, ok := chain.StageByKey("stage-1"); !ok {
		t.Error("StageByKey(\"stage-1\") ok = false, want true")
	}
	if _, ok := chain.StageByKey("does-not-exist"); ok {
		t.Error("StageByKey(\"does-not-exist\") ok = true, want false")
	}
}
