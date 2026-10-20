package panosexposure

import "fmt"

// standardLimitation is attached to every verdict so the scope is never lost.
const standardLimitation = "Verdict reflects the supplied advisory and asset facts only. It is not an exploitation check and does not confirm compromise."

// Assess returns the exposure verdict for one asset against one advisory.
//
// Order of decision:
//  1. Not PAN-OS -> not applicable.
//  2. Version unparseable, or the advisory has no usable range -> unknown.
//  3. Version outside every affected range -> not affected.
//  4. Affected version: any named condition confirmed absent -> mitigated.
//  5. Affected version: any named condition unknown -> unknown (never safe).
//  6. Affected version and every named condition confirmed present -> vulnerable.
//
// Conditions the advisory does not name are not checked at all.
func Assess(a Asset, adv Advisory) Result {
	r := Result{AssetID: a.ID, CVE: adv.CVE, Evidence: []string{}}
	r.Limitations = []string{standardLimitation}
	if adv.Source != "" {
		r.Evidence = append(r.Evidence, "advisory: "+adv.Source)
	}

	if a.Product != Product {
		r.Verdict = VerdictNotApplicable
		r.Reason = fmt.Sprintf("asset product is %q, not %q", a.Product, Product)
		return r
	}

	v, err := parseVersion(a.Version)
	if err != nil {
		r.Verdict = VerdictUnknown
		r.Reason = "cannot assess: " + err.Error()
		return r
	}
	r.Evidence = append(r.Evidence, "reported version: "+a.Version)

	if len(adv.Affected) == 0 {
		r.Verdict = VerdictUnknown
		r.Reason = "advisory supplies no affected version ranges"
		return r
	}

	affected := false
	for _, rg := range adv.Affected {
		if rg.FixedIn == "" {
			r.Verdict = VerdictUnknown
			r.Reason = fmt.Sprintf("advisory range from %q gives no fixed release", rg.Introduced)
			return r
		}
		intro, err := parseVersion(rg.Introduced)
		if err != nil {
			r.Verdict = VerdictUnknown
			r.Reason = "advisory range invalid: " + err.Error()
			return r
		}
		fixed, err := parseVersion(rg.FixedIn)
		if err != nil {
			r.Verdict = VerdictUnknown
			r.Reason = "advisory range invalid: " + err.Error()
			return r
		}
		if v.compare(intro) >= 0 && v.compare(fixed) < 0 {
			affected = true
			r.Evidence = append(r.Evidence, fmt.Sprintf("in affected range [%s, %s)", rg.Introduced, rg.FixedIn))
		}
	}
	if !affected {
		r.Verdict = VerdictNotAffected
		r.Reason = fmt.Sprintf("version %s is outside every affected range in the advisory", a.Version)
		return r
	}

	type check struct {
		name     string
		required bool
		value    Tri
	}
	checks := []check{
		{"GlobalProtect enabled", adv.Conditions.RequireGlobalProtect, a.GlobalProtect},
		{"authentication override enabled", adv.Conditions.RequireAuthOverride, a.AuthOverride},
		{"override cookie shares the GlobalProtect certificate", adv.Conditions.RequireSharedCert, a.SharedOverrideCert},
	}

	// Pass 1: any confirmed-absent condition mitigates. This runs before the
	// unknown check, so a confirmed "no" is not hidden by another missing fact.
	for _, c := range checks {
		if c.required && normalise(c.value) == TriNo {
			r.Verdict = VerdictMitigated
			r.Reason = fmt.Sprintf("affected version, but %s is not in place", c.name)
			r.Evidence = append(r.Evidence, c.name+": no")
			return r
		}
	}

	// Pass 2: any named condition we cannot confirm is unknown, never safe.
	for _, c := range checks {
		if c.required && normalise(c.value) == TriUnknown {
			r.Verdict = VerdictUnknown
			r.Reason = fmt.Sprintf("affected version, but %s cannot be established", c.name)
			r.Evidence = append(r.Evidence, c.name+": unknown")
			return r
		}
	}

	for _, c := range checks {
		if c.required {
			r.Evidence = append(r.Evidence, c.name+": yes")
		}
	}
	r.Verdict = VerdictVulnerable
	if !adv.Conditions.RequireGlobalProtect && !adv.Conditions.RequireAuthOverride && !adv.Conditions.RequireSharedCert {
		r.Reason = "affected version; the advisory names no exposure conditions, so the version alone decides"
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
