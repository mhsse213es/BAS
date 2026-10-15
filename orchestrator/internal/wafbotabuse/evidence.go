package wafbotabuse

import "github.com/audspect/bas/internal/wafval"

// BotAbuseLeg names which half of a BotAbuseVector a leg's expectation
// came from.
type BotAbuseLeg string

const (
	LegMalicious BotAbuseLeg = "malicious"
	LegBenign    BotAbuseLeg = "benign"
)

// BotAbuseLegExpectation pairs one leg's request template with the
// wafval.Expectation it resolves to, so a test harness can collect
// evidence and call wafval.EvaluateClaim without re-deriving the claim
// mapping itself.
type BotAbuseLegExpectation struct {
	VectorID    string
	Leg         BotAbuseLeg
	Request     RequestTemplate
	Expectation wafval.Expectation
}

// Expectations returns the malicious leg's BotAbuseLegExpectation, plus
// the benign leg's when BenignCounterpart is set -- never a padded slice.
// policyBasis is caller-supplied: the catalog is deployment-neutral and
// does not know what policy is actually in force, so PolicyVerified is
// always false here; only the evidence-collecting caller can confirm a
// policy was in force.
func (v BotAbuseVector) Expectations(policyBasis string) []BotAbuseLegExpectation {
	legs := []BotAbuseLegExpectation{
		{
			VectorID: v.ID,
			Leg:      LegMalicious,
			Request:  v.Malicious,
			Expectation: wafval.Expectation{
				Claim: wafval.ClaimPrevention, PolicyBasis: policyBasis, PolicyVerified: false,
			},
		},
	}
	if v.BenignCounterpart != nil {
		legs = append(legs, BotAbuseLegExpectation{
			VectorID: v.ID,
			Leg:      LegBenign,
			Request:  *v.BenignCounterpart,
			Expectation: wafval.Expectation{
				Claim: wafval.ClaimFalsePositive, PolicyBasis: policyBasis, PolicyVerified: false,
			},
		})
	}
	return legs
}
