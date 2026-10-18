package phishbridge

import (
	"slices"

	"github.com/audspect/bas/internal/emailgwcampaign"
	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/phishval"
)

// mapEmailGWVerdict translates an emailgwefficacy.EmailGWVerdict into
// phishval.Verdict directly -- used only for a DERIVED stage's read-out
// of an upstream dimension's own verdict, which is a descriptive
// pass-through, never re-graded against a separate expectation (an
// emailgwcampaign derived stage's own fate "cascades directly from the
// stage it reads," per emailgwcampaign/types.go's own doc comment -- this
// mirrors that exactly, one level down).
func mapEmailGWVerdict(v emailgwefficacy.EmailGWVerdict) phishval.Verdict {
	switch v {
	case emailgwefficacy.VerdictConfirmedSuccess:
		return phishval.VerdictPass
	case emailgwefficacy.VerdictConfirmedFailure:
		return phishval.VerdictFail
	case emailgwefficacy.VerdictNotTested:
		return phishval.VerdictNotTested
	case emailgwefficacy.VerdictNotApplicable:
		return phishval.VerdictNotApplicable
	default:
		return phishval.VerdictInconclusive
	}
}

// gatePermits reports whether upstream's own VerdictDetail for
// gate.UpstreamDimension is one of gate.PermittedVerdicts -- the literal
// semantics emailgwcampaign.GateCondition's own doc comment specifies:
// "Any verdict not in PermittedVerdicts blocks."
func gatePermits(gate emailgwcampaign.GateCondition, upstream emailgwefficacy.EfficacyResult) bool {
	var verdict emailgwefficacy.EmailGWVerdict
	switch gate.UpstreamDimension {
	case emailgwcampaign.DimensionPrevention:
		verdict = upstream.Prevention.Verdict
	case emailgwcampaign.DimensionDetection:
		verdict = upstream.DetectionVerdict.Verdict
	case emailgwcampaign.DimensionResponse:
		verdict = upstream.ResponseVerdict.Verdict
	default:
		return false
	}
	return slices.Contains(gate.PermittedVerdicts, string(verdict))
}

// readDimensionVerdict extracts upstream's own VerdictDetail.Verdict for
// dim, for a StageKindDerived stage's read-out.
func readDimensionVerdict(upstream emailgwefficacy.EfficacyResult, dim emailgwcampaign.Dimension) (emailgwefficacy.VerdictDetail, bool) {
	switch dim {
	case emailgwcampaign.DimensionPrevention:
		return upstream.Prevention, true
	case emailgwcampaign.DimensionDetection:
		return upstream.DetectionVerdict, true
	case emailgwcampaign.DimensionResponse:
		return upstream.ResponseVerdict, true
	default:
		return emailgwefficacy.VerdictDetail{}, false
	}
}

// BuildCampaignChain replays tmpl's own stage sequence and gate
// conditions -- phishing.txt capability #1 ("multi-stage attack-chain
// scenarios") wrapped around emailgwcampaign's already-shipped mechanism,
// no new orchestration engine. stageResults supplies each
// StageKindInjected stage's already-computed EfficacyResult (as a real
// production run would persist per email_gw_campaign_stages.RunID,
// resolved via emailgwrun); this function performs no dispatch, no
// persistence, and no I/O of its own -- it only replays the gate logic
// and bridges each stage's own result into phishval terms.
//
// A StageKindInjected stage whose upstream gate does not permit it is
// ChainStageBlocked, with no Outcome -- mirroring
// emailgwcampaign.StageBlockedByPrerequisite's own "RunID is nil, always"
// guarantee: there is nothing to bridge, nothing that could be mistaken
// for an executed result. A StageKindDerived stage cascades the same way
// when its own ReadsFromStageKey was itself blocked.
func BuildCampaignChain(runID string, tmpl emailgwcampaign.CampaignTemplate, stageResults map[string]emailgwefficacy.EfficacyResult) phishval.Chain {
	chain := phishval.Chain{RunID: runID, ScenarioID: tmpl.ID}
	ran := make(map[string]emailgwefficacy.EfficacyResult, len(tmpl.Stages))

	for _, st := range tmpl.Stages {
		if st.Gate != nil {
			upstream, ok := ran[st.Gate.UpstreamStageKey]
			if !ok || !gatePermits(*st.Gate, upstream) {
				reason := "upstream stage never ran"
				if ok {
					reason = "upstream stage's own verdict is not in this gate's permitted set"
				}
				chain.Stages = append(chain.Stages, phishval.ChainStage{
					Key: st.Key, Label: st.Label, Status: phishval.ChainStageBlocked, BlockedReason: reason,
				})
				continue
			}
		}

		switch st.Kind {
		case emailgwcampaign.StageKindInjected:
			result, ok := stageResults[st.Key]
			if !ok {
				chain.Stages = append(chain.Stages, phishval.ChainStage{
					Key: st.Key, Label: st.Label, Status: phishval.ChainStageBlocked, BlockedReason: "no result supplied for this stage",
				})
				continue
			}
			ran[st.Key] = result
			// The stage's EXPECTED outcome comes from its own declared
			// MailExpectation.ExpectedAction (carried on the result
			// itself) -- never from the observed evidence this same
			// result also carries, which would make every stage
			// trivially agree with whatever was actually observed.
			delivery, enforcement := mapAction(string(result.Expectation.ExpectedAction))
			exp := phishval.Expectation{ScenarioID: st.Key, Delivery: &delivery, Enforcement: &enforcement}
			obs := FromEmailGWEfficacyResult(result)
			outcome := phishval.Evaluate(runID, st.Key, exp, obs)
			chain.Stages = append(chain.Stages, phishval.ChainStage{
				Key: st.Key, Label: st.Label, Status: phishval.ChainStageCompleted, Outcome: &outcome,
			})

		case emailgwcampaign.StageKindDerived:
			upstream, ok := ran[st.ReadsFromStageKey]
			if !ok {
				chain.Stages = append(chain.Stages, phishval.ChainStage{
					Key: st.Key, Label: st.Label, Status: phishval.ChainStageBlocked, BlockedReason: "upstream stage it reads from never ran",
				})
				continue
			}
			detail, known := readDimensionVerdict(upstream, st.ReadsDimension)
			if !known {
				chain.Stages = append(chain.Stages, phishval.ChainStage{
					Key: st.Key, Label: st.Label, Status: phishval.ChainStageBlocked, BlockedReason: "unrecognized ReadsDimension",
				})
				continue
			}
			dim := phishval.DimensionResult{Verdict: mapEmailGWVerdict(detail.Verdict), Reason: detail.Reason}
			chain.Stages = append(chain.Stages, phishval.ChainStage{
				Key: st.Key, Label: st.Label, Status: phishval.ChainStageCompleted, ReadDimension: &dim,
			})
		}
	}
	return chain
}
