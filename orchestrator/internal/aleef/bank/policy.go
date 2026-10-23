package bank

// DocRoute identifies which KYC document endpoint is being served.
type DocRoute string

const (
	DocRoutePrimary   DocRoute = "primary"
	DocRouteAlternate DocRoute = "alternate"
)

// Policy holds every authorization and state-transition decision the bank
// makes. Handlers call these functions at each decision point and do not
// repeat the rules inline. Each hook owns exactly one decision, so that
// replacing one hook changes only the operations listed for it below.
// FixedPolicy supplies the correct behaviour for all of them.
//
// Hook                      Owns (property)                          Arguments
//
//	CanReadAccount            account and transaction reads (H1)       p, ownerID
//	CanModifyBeneficiary      beneficiary PATCH (H2, beneficiary)      p, ownerID
//	CanModifyPayment          payment PATCH (H2, payment)              p, ownerID
//	ApprovalStillValid        approval after a payment change (H3)     pay, newAmount, newBeneficiaryID
//	DedupeIdempotency         transaction replay by key (H4)           p, key, prior (nil when none)
//	CanSettle                 settlement preconditions (H5)            pay
//	CanApprove                payment approval, maker-checker (H6)     p, pay
//	CanReadDocument           KYC document read, both routes (H7)      p, document, route
//	LegacyAuthorize           /v1 reads (H8)                           p, kind, ownerID
//	CanReadBeneficiary        beneficiary read (not a benchmark target)  p, ownerID
//	CanReadPayment            payment read (not a benchmark target)      p, ownerID
//	CanUseAccount             naming an account when creating a
//	                          transaction or payment (not a target)      p, ownerID
//	CanReferenceBeneficiary   naming a beneficiary on a payment
//	                          create or patch (not a target)             p, ownerID
//	CanRequestSettle          who may call settle (not a target)         p, ownerID
//
// ownerID is the owner of the object being touched. For ApprovalStillValid,
// the new values equal the current ones when a field is not being changed.
// LegacyAuthorize kind is "account", "transaction" or "document". For
// CanReadDocument the fixed policy authorizes on the document's owner on both
// routes, whatever customer id the alternate path carries.
type Policy struct {
	CanReadAccount          func(p Principal, ownerID string) bool
	CanReadBeneficiary      func(p Principal, ownerID string) bool
	CanReadPayment          func(p Principal, ownerID string) bool
	CanUseAccount           func(p Principal, ownerID string) bool
	CanReferenceBeneficiary func(p Principal, ownerID string) bool
	CanModifyBeneficiary    func(p Principal, ownerID string) bool
	CanModifyPayment        func(p Principal, ownerID string) bool
	CanRequestSettle        func(p Principal, ownerID string) bool
	ApprovalStillValid      func(pay Payment, newAmount int64, newBeneficiaryID string) bool
	DedupeIdempotency       func(p Principal, key string, prior *Transaction) bool
	CanSettle               func(pay Payment) bool
	CanApprove              func(p Principal, pay Payment) bool
	CanReadDocument         func(p Principal, d Document, route DocRoute) bool
	LegacyAuthorize         func(p Principal, kind, ownerID string) bool
}

// FixedPolicy returns the correct rule for every decision point.
func FixedPolicy() Policy {
	owner := func(p Principal, ownerID string) bool { return p.ID != "" && p.ID == ownerID }
	return Policy{
		CanReadAccount:          owner,
		CanReadBeneficiary:      owner,
		CanReadPayment:          owner,
		CanUseAccount:           owner,
		CanReferenceBeneficiary: owner,
		CanModifyBeneficiary:    owner,
		CanModifyPayment:        owner,
		CanRequestSettle:        owner,
		ApprovalStillValid: func(pay Payment, newAmount int64, newBeneficiaryID string) bool {
			return newAmount == pay.Amount && newBeneficiaryID == pay.BeneficiaryID
		},
		DedupeIdempotency: func(p Principal, key string, prior *Transaction) bool {
			return key != "" && prior != nil && prior.OwnerID == p.ID
		},
		CanSettle: func(pay Payment) bool {
			return pay.State == StateApproved && len(pay.Approvals) >= pay.RequiredApprovals
		},
		CanApprove: func(p Principal, pay Payment) bool {
			for _, a := range pay.Approvals {
				if a == p.ID {
					return false
				}
			}
			if p.Role == RoleApprover {
				return p.ID != pay.OwnerID
			}
			return !pay.DualControl && p.ID == pay.OwnerID
		},
		CanReadDocument: func(p Principal, d Document, _ DocRoute) bool { return owner(p, d.OwnerID) },
		LegacyAuthorize: func(p Principal, kind, ownerID string) bool { return owner(p, ownerID) },
	}
}
