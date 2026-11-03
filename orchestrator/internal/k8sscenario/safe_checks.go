package k8sscenario

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/audspect/bas/internal/controlval"
)

// SafeCheck is a read-only Kubernetes check. It asks the API server's authorizer what a probe subject may do, using
// SubjectAccessReview. Nothing is created, changed or deleted. Its result is a decision of the authorizer, not proof
// of an exploitable path (docs/k8s-bas/SPEC-first-wave.md section 4).
type SafeCheck struct {
	ID          string
	Title       string
	Technique   string
	Domain      string
	Remediation string
	// Specs returns the review requests for a subject and target namespace. A check passes only when every one is denied.
	Specs func(subject, namespace string) []SARSpec
}

// SARSpec is the resource attributes of one SubjectAccessReview.
type SARSpec struct {
	User      string
	Verb      string
	Group     string
	Resource  string
	Namespace string
}

// SARResult is the authorizer's answer to one review.
type SARResult struct {
	StatusCode int
	Allowed    bool
	Denied     bool
	Reason     string
}

// SARReviewer sends one SubjectAccessReview. The real implementation is SARClient; tests use a fake.
type SARReviewer interface {
	Review(ctx context.Context, spec SARSpec) (SARResult, error)
}

// SafeEvidence is one review sent and what came back.
type SafeEvidence struct {
	Spec       SARSpec `json:"spec"`
	StatusCode int     `json:"statusCode"`
	Allowed    bool    `json:"allowed"`
	Reason     string  `json:"reason"`
}

// SafeCheckResult is the recorded result of a safe check.
type SafeCheckResult struct {
	CheckID     string             `json:"checkId"`
	Title       string             `json:"title"`
	Technique   string             `json:"technique"`
	Profile     string             `json:"profile"`
	Subject     string             `json:"subject"`
	Outcome     controlval.Outcome `json:"outcome"`
	Verdict     controlval.Verdict `json:"verdict"`
	Evidence    []SafeEvidence     `json:"evidence"`
	Remediation string             `json:"remediation"`
	Source      string             `json:"source"`     // always "sar" for these checks
	Confidence  string             `json:"confidence"` // "observed": the authorizer answered directly
	Error       string             `json:"error,omitempty"`
	ExecutedAt  time.Time          `json:"executedAt"`
}

// defaultLabEscalationNamespace is the namespace named by the specification for S6.
const defaultLabEscalationNamespace = "lab-escalation-test"

// SafeChecks is the catalogue of safe checks in this wave (docs/k8s-bas/SPEC-first-wave.md section 7.1).
var SafeChecks = []SafeCheck{
	{
		ID:        "impersonate-serviceaccounts",
		Title:     "Impersonation check",
		Technique: "Unauthorized service account impersonation",
		Domain:    "Identity and RBAC",
		Remediation: "Remove the impersonate verb from every role bound to the probe subject. " +
			"List the bindings that grant it with the RBAC review.",
		Specs: func(subject, _ string) []SARSpec {
			return []SARSpec{
				{User: subject, Verb: "impersonate", Resource: "serviceaccounts"},
				{User: subject, Verb: "impersonate", Resource: "users"},
			}
		},
	},
	{
		ID:        "rolebinding-create-foreign-namespace",
		Title:     "RoleBinding escalation check",
		Technique: "RoleBinding manipulation",
		Domain:    "Identity and RBAC",
		Remediation: "Restrict rolebindings create and escalate to cluster administrators. " +
			"Remove any grant of those verbs to the probe subject.",
		Specs: func(subject, namespace string) []SARSpec {
			if namespace == "" {
				namespace = defaultLabEscalationNamespace
			}
			return []SARSpec{{User: subject, Verb: "create", Group: "rbac.authorization.k8s.io",
				Resource: "rolebindings", Namespace: namespace}}
		},
	},
}

// SafeCheckByID returns the check with the given ID.
func SafeCheckByID(id string) (SafeCheck, bool) {
	for _, c := range SafeChecks {
		if c.ID == id {
			return c, true
		}
	}
	return SafeCheck{}, false
}

// ValidateSubject refuses an empty, oversized or spaced subject name. It is the username the authorizer sees,
// for example system:serviceaccount:<namespace>:<name>.
func ValidateSubject(subject string) error {
	s := strings.TrimSpace(subject)
	if s == "" || len(s) > 253 || strings.ContainsAny(s, " \t\r\n") {
		return errors.New("subject must be a non-empty username without spaces, up to 253 characters")
	}
	return nil
}

// RunSafeCheck sends the check's reviews and maps the answers to an outcome and a verdict.
//
//	any review allowed  -> Allowed, FAIL (the control did not stop the access)
//	every review denied -> Blocked, PASS
//	a review failed     -> Unknown, ERROR (the result cannot be established)
//
// A review answered with HTTP 200 is not a pass by itself: only the allowed or denied decision counts.
func RunSafeCheck(ctx context.Context, rev SARReviewer, check SafeCheck, subject, namespace string, now time.Time) SafeCheckResult {
	res := SafeCheckResult{CheckID: check.ID, Title: check.Title, Technique: check.Technique,
		Profile: "safe", Subject: subject, Remediation: check.Remediation, Source: "sar",
		Confidence: "observed", ExecutedAt: now.UTC()}
	anyAllowed := false
	for _, spec := range check.Specs(subject, namespace) {
		r, err := rev.Review(ctx, spec)
		if err != nil {
			res.Outcome, res.Verdict, res.Error = controlval.OutcomeUnknown, controlval.VerdictError, err.Error()
			return res
		}
		res.Evidence = append(res.Evidence, SafeEvidence{Spec: spec, StatusCode: r.StatusCode, Allowed: r.Allowed, Reason: r.Reason})
		if r.Allowed {
			anyAllowed = true
		}
	}
	if anyAllowed {
		res.Outcome, res.Verdict = controlval.OutcomeAllowed, controlval.VerdictFail
	} else {
		res.Outcome, res.Verdict = controlval.OutcomeBlocked, controlval.VerdictPass
	}
	return res
}
