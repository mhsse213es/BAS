package bank

// Policy holds every authorization and state-transition decision the bank
// makes. Handlers call these functions at each decision point and do not
// repeat the rules inline. FixedPolicy supplies the correct behaviour for all
// of them.
//
// Argument conventions:
//
//	CanReadAccount(p, ownerID)         p may read an account, transaction, payment or
//	                                   beneficiary owned by ownerID. Also used to scope
//	                                   which accounts a transaction may be created on.
//	CanModifyBeneficiary(p, ownerID)   p may modify (or reference in a payment, or settle)
//	                                   a beneficiary or payment owned by ownerID.
//	ApprovalStillValid(pay, amt, ben)  a payment that already holds approvals is being
//	                                   changed to amount amt and beneficiary ben (equal to
//	                                   the current values when a field is not being
//	                                   changed). Reports whether the approvals survive.
//	DedupeIdempotency(p, key, prior)   prior is the transaction previously stored under
//	                                   key (nil when none). Reports whether the request
//	                                   must be answered with prior instead of creating a
//	                                   new transaction.
//	CanSettle(pay)                     the payment has satisfied every step required
//	                                   before settlement.
//	CanApprove(p, pay)                 p may add an approval to pay.
//	CanReadDocument(p, ownerID)        p may read a KYC document owned by ownerID, on
//	                                   both the primary and the alternate endpoint.
//	LegacyAuthorize(p, kind, ownerID)  authorization for /v1 reads. kind is one of
//	                                   "account", "transaction", "document".
type Policy struct {
	CanReadAccount       func(p Principal, ownerID string) bool
	CanModifyBeneficiary func(p Principal, ownerID string) bool
	ApprovalStillValid   func(pay Payment, newAmount int64, newBeneficiaryID string) bool
	DedupeIdempotency    func(p Principal, key string, prior *Transaction) bool
	CanSettle            func(pay Payment) bool
	CanApprove           func(p Principal, pay Payment) bool
	CanReadDocument      func(p Principal, ownerID string) bool
	LegacyAuthorize      func(p Principal, kind, ownerID string) bool
}

// FixedPolicy returns the correct rule for every decision point.
func FixedPolicy() Policy {
	owner := func(p Principal, ownerID string) bool { return p.ID != "" && p.ID == ownerID }
	return Policy{
		CanReadAccount:       owner,
		CanModifyBeneficiary: owner,
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
		CanReadDocument: owner,
		LegacyAuthorize: func(p Principal, kind, ownerID string) bool { return owner(p, ownerID) },
	}
}
