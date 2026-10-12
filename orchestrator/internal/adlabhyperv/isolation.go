package adlabhyperv

import (
	"fmt"
	"strings"

	"github.com/audspect/bas/internal/adlabrt"
)

// CheckKind is one isolation check. All are required for M1.
type CheckKind string

const (
	CheckPrivateSwitch    CheckKind = "private_switch"    // every adapter on the dedicated private switch
	CheckNoExternalRoute  CheckKind = "no_external_route" // active probe: cannot reach host net / internet / non-lab host
	CheckNoProductionAD   CheckKind = "no_production_ad"  // no trust path to any real directory
	CheckDistinctIdentity CheckKind = "distinct_identity" // lab SIDs/creds are the lab's own
)

// ProbeResult is one check's outcome. Determinate=false means the check could
// not be conclusively evaluated and MUST be treated as not isolated.
type ProbeResult struct {
	Passed      bool
	Determinate bool
	Detail      string
}

// RequiredChecks is the full M1 isolation checklist.
func RequiredChecks() []CheckKind {
	return []CheckKind{CheckPrivateSwitch, CheckNoExternalRoute, CheckNoProductionAD, CheckDistinctIdentity}
}

// EvaluateIsolation aggregates probe results FAIL-CLOSED: Verified is true only
// when every required check has a Determinate, Passed result. A missing or
// indeterminate result denies. Method records which checks ran and their
// outcomes; Detail names the first failing/missing check.
func EvaluateIsolation(required []CheckKind, results map[CheckKind]ProbeResult) adlabrt.IsolationResult {
	// Fail-closed: a lab with no required checks is never "isolated". An empty
	// requirement set must deny, not vacuously verify.
	if len(required) == 0 {
		return adlabrt.IsolationResult{Verified: false, Method: "checks[]", Detail: "no isolation checks required"}
	}
	var method []string
	verified := true
	detail := ""
	for _, c := range required {
		r, present := results[c]
		status := "ok"
		switch {
		case !present:
			status = "missing"
		case !r.Determinate:
			status = "indeterminate"
		case !r.Passed:
			status = "failed"
		}
		method = append(method, fmt.Sprintf("%s=%s", c, status))
		if status != "ok" && verified {
			verified = false
			detail = fmt.Sprintf("%s: %s (%s)", c, status, r.Detail)
		}
	}
	return adlabrt.IsolationResult{
		Verified: verified,
		Method:   "checks[" + strings.Join(method, ",") + "]",
		Detail:   detail,
	}
}
