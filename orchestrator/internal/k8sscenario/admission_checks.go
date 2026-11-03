package k8sscenario

import (
	"context"
	"strings"
	"time"

	"github.com/audspect/bas/internal/controlval"
)

// PSAEnforceLabel is the Pod Security Admission label that sets the enforced level of a namespace.
const PSAEnforceLabel = "pod-security.kubernetes.io/enforce"

// DryRunResult is the API server's answer to a server-side dry-run create.
type DryRunResult struct {
	StatusCode int
	Allowed    bool
	Reason     string
	Message    string
}

// AdmissionClient reads a namespace's Pod Security level, sends server-side dry-run creates, and lists webhook
// side effects. Nothing is persisted by any of these calls.
type AdmissionClient interface {
	NamespacePSALevel(ctx context.Context, namespace string) (level string, found bool, err error)
	DryRunPod(ctx context.Context, namespace string, pod map[string]any) (DryRunResult, error)
	// WebhookSideEffects returns the sideEffects value of every admission webhook in the cluster.
	WebhookSideEffects(ctx context.Context) ([]string, error)
}

// AdmissionCheck is a dry-run check of the admission layer (docs/k8s-bas/SPEC-first-wave.md section 7).
type AdmissionCheck struct {
	ID          string
	Title       string
	Technique   string
	Domain      string
	Remediation string
	// RequiredLevels are the enforced Pod Security levels for which the check applies. Any other level is SKIPPED.
	RequiredLevels []string
	// Pod returns the pod to dry-run create.
	Pod func() map[string]any
}

// AdmissionEvidence is what the dry-run returned.
type AdmissionEvidence struct {
	StatusCode       int      `json:"statusCode"`
	Allowed          bool     `json:"allowed"`
	Reason           string   `json:"reason"`
	Message          string   `json:"message"`
	PSAViolation     bool     `json:"psaViolation"`
	WebhookSideNotes []string `json:"webhookSideNotes,omitempty"`
}

// AdmissionCheckResult is the recorded result of a dry-run admission check.
type AdmissionCheckResult struct {
	CheckID        string             `json:"checkId"`
	Title          string             `json:"title"`
	Technique      string             `json:"technique"`
	Profile        string             `json:"profile"`
	Namespace      string             `json:"namespace"`
	NamespaceLevel string             `json:"namespaceLevel"`
	Outcome        controlval.Outcome `json:"outcome"`
	Verdict        controlval.Verdict `json:"verdict"`
	Note           string             `json:"note,omitempty"`
	Evidence       AdmissionEvidence  `json:"evidence"`
	Remediation    string             `json:"remediation"`
	Source         string             `json:"source"`     // "admission-dry-run"
	Confidence     string             `json:"confidence"` // "observed"
	Error          string             `json:"error,omitempty"`
	ExecutedAt     time.Time          `json:"executedAt"`
}

const probeImage = "registry.k8s.io/pause:3.9"

// AdmissionChecks is the catalogue of dry-run admission checks in this wave.
var AdmissionChecks = []AdmissionCheck{
	{
		ID:             "privileged-pod-restricted-namespace",
		Title:          "Privileged pod against a restricted namespace",
		Technique:      "Privileged container creation",
		Domain:         "Admission and policy",
		Remediation:    "Set pod-security.kubernetes.io/enforce: restricted on namespaces that run untrusted workloads, or move the workload.",
		RequiredLevels: []string{"restricted"},
		Pod: func() map[string]any {
			return map[string]any{
				"apiVersion": "v1", "kind": "Pod",
				"metadata": map[string]any{"generateName": "bas-s7-probe-"},
				"spec": map[string]any{"containers": []any{map[string]any{
					"name": "probe", "image": probeImage,
					"securityContext": map[string]any{"privileged": true},
				}}},
			}
		},
	},
	{
		ID:             "host-namespaces-hostpath-policy",
		Title:          "Host namespace and hostPath pod against policy",
		Technique:      "Host PID, host network and hostPath mounting",
		Domain:         "Admission and policy",
		Remediation:    "Enforce baseline or higher on the namespace, or add a validating policy that refuses host namespaces and hostPath.",
		RequiredLevels: []string{"baseline", "restricted"},
		Pod: func() map[string]any {
			return map[string]any{
				"apiVersion": "v1", "kind": "Pod",
				"metadata": map[string]any{"generateName": "bas-s8-probe-"},
				"spec": map[string]any{
					"hostPID":     true,
					"hostNetwork": true,
					"containers": []any{map[string]any{
						"name": "probe", "image": probeImage,
						"volumeMounts": []any{map[string]any{"name": "host-root", "mountPath": "/host"}},
					}},
					"volumes": []any{map[string]any{"name": "host-root", "hostPath": map[string]any{"path": "/"}}},
				},
			}
		},
	},
}

// AdmissionCheckByID returns the check with the given ID.
func AdmissionCheckByID(id string) (AdmissionCheck, bool) {
	for _, c := range AdmissionChecks {
		if c.ID == id {
			return c, true
		}
	}
	return AdmissionCheck{}, false
}

// webhookSideEffectsSafe reports whether a webhook's sideEffects value is safe for a dry-run request.
func webhookSideEffectsSafe(v string) bool {
	return v == "None" || v == "NoneOnDryRun"
}

// RunAdmissionCheck sends the dry-run and maps the answer to an outcome and a verdict.
//
//	namespace not at a required level -> SKIPPED (not applicable)
//	refused by admission              -> Blocked, PASS
//	allowed, every webhook dry-run safe -> Allowed, FAIL (the control did not stop the request)
//	allowed, a webhook is not dry-run safe -> Unknown, ERROR (an allowed dry-run cannot be trusted)
//	the check could not be run         -> Unknown, ERROR
func RunAdmissionCheck(ctx context.Context, c AdmissionClient, check AdmissionCheck, namespace string, now time.Time) AdmissionCheckResult {
	res := AdmissionCheckResult{CheckID: check.ID, Title: check.Title, Technique: check.Technique, Profile: "safe",
		Namespace: namespace, Remediation: check.Remediation, Source: "admission-dry-run", Confidence: "observed",
		ExecutedAt: now.UTC()}

	level, found, err := c.NamespacePSALevel(ctx, namespace)
	if err != nil {
		res.Outcome, res.Verdict, res.Error = controlval.OutcomeUnknown, controlval.VerdictError, err.Error()
		return res
	}
	if !found {
		res.Outcome, res.Verdict, res.Error = controlval.OutcomeUnknown, controlval.VerdictError, "namespace not found"
		return res
	}
	res.NamespaceLevel = level
	if !containsLevel(check.RequiredLevels, level) {
		res.Outcome, res.Verdict = controlval.OutcomeUnknown, controlval.VerdictSkipped
		res.Note = "namespace enforces '" + level + "'; this check applies to " + strings.Join(check.RequiredLevels, " or ")
		return res
	}

	dr, err := c.DryRunPod(ctx, namespace, check.Pod())
	if err != nil {
		res.Outcome, res.Verdict, res.Error = controlval.OutcomeUnknown, controlval.VerdictError, err.Error()
		return res
	}
	res.Evidence = AdmissionEvidence{StatusCode: dr.StatusCode, Allowed: dr.Allowed, Reason: dr.Reason, Message: dr.Message,
		PSAViolation: strings.Contains(dr.Message, "violates PodSecurity")}

	if !dr.Allowed {
		res.Outcome, res.Verdict = controlval.OutcomeBlocked, controlval.VerdictPass
		return res
	}

	sides, err := c.WebhookSideEffects(ctx)
	if err != nil {
		res.Outcome, res.Verdict, res.Error = controlval.OutcomeUnknown, controlval.VerdictError,
			"allowed, but the webhook configuration could not be read: "+err.Error()
		return res
	}
	for _, s := range sides {
		if !webhookSideEffectsSafe(s) {
			res.Evidence.WebhookSideNotes = append(res.Evidence.WebhookSideNotes, s)
		}
	}
	if len(res.Evidence.WebhookSideNotes) > 0 {
		res.Outcome, res.Verdict = controlval.OutcomeUnknown, controlval.VerdictError
		res.Error = "allowed, but an admission webhook does not declare dry-run safe side effects; the dry-run result cannot be trusted"
		return res
	}
	res.Outcome, res.Verdict = controlval.OutcomeAllowed, controlval.VerdictFail
	return res
}

func containsLevel(levels []string, level string) bool {
	for _, l := range levels {
		if l == level {
			return true
		}
	}
	return false
}
