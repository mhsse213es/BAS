package detect

import (
	"slices"
	"strings"
)

// Disclosure classes name a kind of protected data that a response emits. The set is closed: a class not listed here is
// never allowed on any resource. The lab records classes and field names only, never values (see lab/disclosure.go).
const (
	DisclosureKYCIdentity       = "kyc_identity"       // identity evidence: PAN, Aadhaar reference
	DisclosurePaymentCredential = "payment_credential" // a repayment debit mandate
	DisclosureAccountIdentifier = "account_identifier" // a loan's disbursement account
	DisclosureClinicalRecord    = "clinical_record"    // a patient's diagnosis or insurance number
)

// disclosurePolicy lists, for each class, the resource kinds it may appear on. Nothing is allowed by default: a class on a
// resource that is not listed is a policy violation. Ownership is not part of this policy; a caller who owns a record can
// still receive a class it may not receive through that resource (REL-020).
var disclosurePolicy = map[string][]string{
	DisclosureKYCIdentity:       {"kyc"},
	DisclosurePaymentCredential: {"statement"},
	DisclosureAccountIdentifier: {"loan"},
	DisclosureClinicalRecord:    {"patient_record", "health_export"},
}

// disclosureResource names the resource kind an action reads, from the action's path. The query is not part of an action.
// Administrative KYC reads belong to the KYC resource family; the administrative loan route is its own resource, so an
// account identifier there is outside the policy.
func disclosureResource(action string) string {
	path := action
	if _, rest, ok := strings.Cut(action, " "); ok {
		path = rest
	}
	switch {
	case strings.HasPrefix(path, "/api/health/records/"):
		return "patient_record"
	case strings.HasPrefix(path, "/api/health/export"):
		return "health_export"
	case strings.HasPrefix(path, "/api/nbfc/kyc/"), strings.HasPrefix(path, "/api/nbfc/admin/kyc/"):
		return "kyc"
	case strings.HasSuffix(path, "/statement"):
		return "statement"
	case strings.HasPrefix(path, "/api/nbfc/loans/"):
		return "loan"
	case strings.HasPrefix(path, "/api/nbfc/admin/loans/"):
		return "admin_loan"
	}
	return "other"
}

// disclosureAllowed reports whether a class may appear on the resource the action reads.
func disclosureAllowed(class, action string) bool {
	return slices.Contains(disclosurePolicy[class], disclosureResource(action))
}

// disclosureOutsidePolicy is the REL-020 predicate: the event records a class on a resource where the policy does not allow
// it. An event with no disclosure has nothing to judge and does not match.
func disclosureOutsidePolicy(e Event) bool {
	for _, c := range e.DisclosedClasses {
		if !disclosureAllowed(c, e.Action) {
			return true
		}
	}
	return false
}
