package reporting

import "regexp"

var (
	appCtlCoverageRe = regexp.MustCompile(`(?m)^APPCTL_COVERAGE:\s*(\S+)`)
	appCtlAddTypeRe  = regexp.MustCompile(`\bhost_addtype=(\S+)`)
	appCtlPolicyRe   = regexp.MustCompile(`\bpolicy=(\S*)`)
	appCtlBuildRe    = regexp.MustCompile(`(?m)^APPCTL_HOST:.*\bos_build=(\d+)`)
)

// ParseAppControlObserved returns what the step measured, from its
// APPCTL_COVERAGE line. For the in-process host it appends the Add-Type result,
// so the report shows both the language mode and the probe's outcome.
func ParseAppControlObserved(output string) string {
	m := appCtlCoverageRe.FindStringSubmatch(output)
	if m == nil {
		return ""
	}
	observed := m[1]
	if a := appCtlAddTypeRe.FindStringSubmatch(output); a != nil {
		observed += "; Add-Type " + a[1]
	}
	// The Windows build the path ran on. Results hold only for the builds that
	// were tested, so the build is part of what the report must show.
	if b := appCtlBuildRe.FindStringSubmatch(output); b != nil {
		observed += "; build " + b[1]
	}
	return observed
}

// appCtlPolicyFor returns the intended policy a verdict was judged against.
// Only the in-process family takes a policy input. For it, a policy field with
// no value is "not stated", which makes the verdict UNVERIFIED. No policy field
// at all means the step did not reach the verdict, so it is "not recorded".
// Families without a policy input return empty.
func appCtlPolicyFor(family, output string) string {
	if family != "inprocess_hosting" {
		return ""
	}
	m := appCtlPolicyRe.FindStringSubmatch(output)
	if m == nil {
		return "not recorded"
	}
	if m[1] == "" {
		return "not stated"
	}
	return m[1]
}
