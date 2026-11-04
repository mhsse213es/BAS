package lab

import (
	"net/http"
	"sort"

	"github.com/audspect/bas/internal/apibas/detect"
)

// disclosedFieldClass maps each protected NBFC field to its disclosure class. A protected field with no entry here fails the
// drift test in disclosure_test.go, so a new protected field cannot skip classification.
var disclosedFieldClass = map[string]string{
	"pan_number":           detect.DisclosureKYCIdentity,
	"aadhaar_ref":          detect.DisclosureKYCIdentity,
	"debit_mandate":        detect.DisclosurePaymentCredential,
	"disbursement_account": detect.DisclosureAccountIdentifier,
}

// emittedDisclosureFields walks a response body as it is serialised and returns the protected field names it contains,
// distinct and sorted. It returns names only: a value is never read into the result. Nested objects and lists are walked,
// so a KYC record carried inside a loan body is found.
func emittedDisclosureFields(v any) []string {
	seen := map[string]bool{}
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			for k, val := range t {
				if _, ok := disclosedFieldClass[k]; ok {
					seen[k] = true
				}
				walk(val)
			}
		case []map[string]any:
			for _, m := range t {
				walk(m)
			}
		case []any:
			for _, val := range t {
				walk(val)
			}
		}
	}
	walk(v)
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// disclosureClasses returns the distinct classes of the named fields, sorted.
func disclosureClasses(fields []string) []string {
	seen := map[string]bool{}
	for _, f := range fields {
		if c, ok := disclosedFieldClass[f]; ok {
			seen[c] = true
		}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// writeNBFCJSON writes an NBFC response and records the protected fields the body emits, so the access event for this
// request carries what was actually sent. The walk runs on the same value that is serialised.
func writeNBFCJSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	noteDisclosedFields(r, emittedDisclosureFields(v)...)
	writeJSON(w, status, v)
}
