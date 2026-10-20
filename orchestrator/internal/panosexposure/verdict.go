package panosexposure

import (
	"fmt"
	"time"
)

// standardLimitation is attached to every verdict so the scope is never lost.
const standardLimitation = "Verdict reflects the supplied advisory and asset facts only. It is not an exploitation check and does not confirm compromise."

// Assess returns the exposure verdict for one asset against one advisory.
// It stamps the result with the current UTC time. Use AssessAt for a
// repeatable result with a fixed timestamp.
func Assess(a Asset, adv Advisory) Result {
	return AssessAt(a, adv, time.Now().UTC())
}

// AssessAt is Assess with the timestamp supplied by the caller. The verdict
// depends only on the asset, the advisory and that timestamp.
//
// Order of decision:
//  1. Not PAN-OS -> not applicable.
//  2. Version unparseable, or the advisory has no usable range -> unknown.
//  3. Release in the advisory's unresolved list -> unknown.
//  4. Version outside every affected range -> not affected, or unknown when
//     its branch is not covered by the advisory.
//  5. Affected version: any named condition confirmed absent -> mitigated.
//  6. Affected version: any named condition unknown -> unknown (never safe).
//  7. Affected version and every named condition confirmed present -> vulnerable.
//
// Conditions the advisory does not name are not checked at all.
func AssessAt(a Asset, adv Advisory, at time.Time) Result {
	r := Result{
		AssetID:         a.ID,
		CVE:             adv.CVE,
		ReasonCodes:     []string{},
		MissingEvidence: []string{},
		Evidence:        []string{},
		Limitations:     []string{standardLimitation},
		AdvisoryVersion: adv.Version,
		AssessedAt:      at.UTC(),
	}
	if adv.Source != "" {
		r.Evidence = append(r.Evidence, "advisory: "+adv.Source)
	}

	if a.Product != Product {
		r.Verdict = VerdictNotApplicable
		r.Reason = fmt.Sprintf("asset product is %q, not %q", a.Product, Product)
		r.ReasonCodes = append(r.ReasonCodes, CodeNotPANOS)
		return r
	}

	v, err := parseVersion(a.Version)
	if err != nil {
		r.Verdict = VerdictUnknown
		r.Reason = "cannot assess: " + err.Error()
		r.ReasonCodes = append(r.ReasonCodes, CodeVersionUnparseable)
		r.MissingEvidence = append(r.MissingEvidence, EvidenceVersion)
		return r
	}
	r.Evidence = append(r.Evidence, "reported version: "+a.Version)

	for _, u := range adv.Unresolved {
		if u == a.Version {
			r.Verdict = VerdictUnknown
			r.Reason = fmt.Sprintf("the advisory's own statements conflict for %s; confirm with the vendor", a.Version)
			r.ReasonCodes = append(r.ReasonCodes, CodeReleaseUnresolved)
			r.Evidence = append(r.Evidence, "advisory: unresolved for this release")
			return r
		}
	}

	if len(adv.Affected) == 0 {
		r.Verdict = VerdictUnknown
		r.Reason = "advisory supplies no affected version ranges"
		r.ReasonCodes = append(r.ReasonCodes, CodeNoAffectedRanges)
		return r
	}

	affected := false
	for _, rg := range adv.Affected {
		if rg.FixedIn == "" {
			r.Verdict = VerdictUnknown
			r.Reason = fmt.Sprintf("advisory range from %q gives no fixed release", rg.Introduced)
			r.ReasonCodes = append(r.ReasonCodes, CodeRangeNoFixedRelease)
			return r
		}
		intro, err := parseVersion(rg.Introduced)
		if err != nil {
			r.Verdict = VerdictUnknown
			r.Reason = "advisory range invalid: " + err.Error()
			r.ReasonCodes = append(r.ReasonCodes, CodeRangeInvalid)
			return r
		}
		fixed, err := parseVersion(rg.FixedIn)
		if err != nil {
			r.Verdict = VerdictUnknown
			r.Reason = "advisory range invalid: " + err.Error()
			r.ReasonCodes = append(r.ReasonCodes, CodeRangeInvalid)
			return r
		}
		if v.compare(intro) >= 0 && v.compare(fixed) < 0 {
			affected = true
			r.Evidence = append(r.Evidence, fmt.Sprintf("in affected range [%s, %s)", rg.Introduced, rg.FixedIn))
		}
	}
	if !affected {
		branch := fmt.Sprintf("%d.%d", v.major, v.minor)
		if len(adv.Coverage) > 0 && !contains(adv.Coverage, branch) {
			r.Verdict = VerdictUnknown
			r.Reason = fmt.Sprintf("release branch %s is not covered by the advisory, so absence from its ranges proves nothing", branch)
			r.ReasonCodes = append(r.ReasonCodes, CodeBranchNotCovered)
			return r
		}
		r.Verdict = VerdictNotAffected
		r.Reason = fmt.Sprintf("version %s is outside every affected range in the advisory", a.Version)
		r.ReasonCodes = append(r.ReasonCodes, CodeOutsideAffectedRanges)
		return r
	}
	r.ReasonCodes = append(r.ReasonCodes, CodeInAffectedRange)

	type check struct {
		name     string
		evidence string
		required bool
		value    Tri
	}
	checks := []check{
		{"GlobalProtect enabled", EvidenceGlobalProtect, adv.Conditions.RequireGlobalProtect, a.GlobalProtect},
		{"authentication override enabled", EvidenceAuthOverride, adv.Conditions.RequireAuthOverride, a.AuthOverride},
		{"override cookie shares the GlobalProtect certificate", EvidenceSharedOverride, adv.Conditions.RequireSharedCert, a.SharedOverrideCert},
	}

	// Pass 1: any confirmed-absent condition mitigates. This runs before the
	// unknown check, so a confirmed "no" is not hidden by another missing fact.
	for _, c := range checks {
		if c.required && normalise(c.value) == TriNo {
			r.Verdict = VerdictMitigated
			r.Reason = fmt.Sprintf("affected version, but %s is not in place", c.name)
			r.ReasonCodes = append(r.ReasonCodes, CodeConditionAbsent)
			r.Evidence = append(r.Evidence, c.name+": no")
			return r
		}
	}

	// Pass 2: any named condition we cannot confirm is unknown, never safe.
	// Every such condition is listed as missing evidence.
	var unknowns []string
	for _, c := range checks {
		if c.required && normalise(c.value) == TriUnknown {
			unknowns = append(unknowns, c.evidence)
		}
	}
	if len(unknowns) > 0 {
		r.Verdict = VerdictUnknown
		r.Reason = fmt.Sprintf("affected version, but %d exposure condition(s) cannot be established", len(unknowns))
		r.ReasonCodes = append(r.ReasonCodes, CodeConditionUnknown)
		r.MissingEvidence = append(r.MissingEvidence, unknowns...)
		return r
	}

	for _, c := range checks {
		if c.required {
			r.Evidence = append(r.Evidence, c.name+": yes")
			r.ReasonCodes = append(r.ReasonCodes, CodeConditionPresent)
		}
	}
	r.Verdict = VerdictVulnerable
	if !adv.Conditions.RequireGlobalProtect && !adv.Conditions.RequireAuthOverride && !adv.Conditions.RequireSharedCert {
		r.Reason = "affected version; the advisory names no exposure conditions, so the version alone decides"
		r.ReasonCodes = append(r.ReasonCodes, CodeNoConditionsNamed)
		r.Limitations = append(r.Limitations, "advisory names no exposure conditions")
	} else {
		r.Reason = "affected version and every exposure condition the advisory names is confirmed"
	}
	return r
}

// normalise maps an invalid Tri value to Unknown, so a typo never reads as yes or no.
func normalise(t Tri) Tri {
	switch t {
	case TriYes, TriNo:
		return t
	default:
		return TriUnknown
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
