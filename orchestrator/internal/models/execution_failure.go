package models

// ExecutionFailure separates "the simulation did not run to a result" from any security verdict. An unexecuted
// simulation proves nothing about the customer's controls, so SecurityVerdict is always "not_assessed" and the step is
// left out of the prevention and detection scores.
type ExecutionFailure struct {
	// ExecutionStatus is the customer-facing outcome: not_executed | timed_out | execution_error | cancelled.
	ExecutionStatus string `json:"executionStatus"`
	// SecurityVerdict is always "not_assessed": a failed execution is never a control pass or fail.
	SecurityVerdict string `json:"securityVerdict"`
	// Category groups failures for coverage reporting: missing_dependency, missing_prerequisite, external_dependency,
	// environment_conflict, content_defect, timeout, host_problem, cancelled, execution_error.
	Category string `json:"category"`
	// Code is the stable machine identifier (the server's ErrorReason).
	Code string `json:"code"`
	// Reason is the plain-language explanation shown to the customer.
	Reason string `json:"reason"`
	// Stage is where it failed: prerequisite_validation, launch, execution or supervision.
	Stage string `json:"stage"`
	// Owner says who can fix it: "audspect" for a content or agent defect, "environment" for the customer's endpoint.
	Owner string `json:"owner"`
	// EvidenceConfidence is "none" for every execution failure: no evidence about the control was produced.
	EvidenceConfidence string `json:"evidenceConfidence"`
	// Remediation is the action that would let the simulation run.
	Remediation string `json:"remediation"`
	// RawError is the original diagnostic line, kept verbatim for engineers.
	RawError string `json:"rawError,omitempty"`
}
