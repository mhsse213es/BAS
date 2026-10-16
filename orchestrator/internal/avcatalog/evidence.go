package avcatalog

import "github.com/audspect/bas/internal/avval"

// VectorLeg names which half of a Vector a LegExpectation came from.
type VectorLeg string

const (
	LegPrimary     VectorLeg = "primary"
	LegCounterpart VectorLeg = "counterpart"
)

// LegExpectation pairs one leg's execution template with the
// avval.Expectation it resolves to, so a test harness can collect evidence
// and call avval.EvaluateClaim without re-deriving the claim mapping itself.
type LegExpectation struct {
	VectorID    string
	Leg         VectorLeg
	Execution   ExecutionTemplate
	Expectation avval.Expectation
}

// opposite returns the other claim: ClaimPrevention <-> ClaimFalsePositive.
func opposite(c avval.ClaimType) avval.ClaimType {
	if c == avval.ClaimFalsePositive {
		return avval.ClaimPrevention
	}
	return avval.ClaimFalsePositive
}

// Expectations returns the primary leg's LegExpectation, plus the
// counterpart leg's when Counterpart is set -- never a padded slice.
// policyBasis is caller-supplied: the catalog is deployment-neutral and does
// not know what policy is actually in force, so PolicyVerified is always
// false here; only the evidence-collecting caller can confirm a policy was
// in force.
func (v Vector) Expectations(policyBasis string) []LegExpectation {
	legs := []LegExpectation{
		{
			VectorID:  v.ID,
			Leg:       LegPrimary,
			Execution: v.Primary,
			Expectation: avval.Expectation{
				Claim: v.PrimaryClaim, PolicyBasis: policyBasis, PolicyVerified: false,
			},
		},
	}
	if v.Counterpart != nil {
		legs = append(legs, LegExpectation{
			VectorID:  v.ID,
			Leg:       LegCounterpart,
			Execution: *v.Counterpart,
			Expectation: avval.Expectation{
				Claim: opposite(v.PrimaryClaim), PolicyBasis: policyBasis, PolicyVerified: false,
			},
		})
	}
	return legs
}
