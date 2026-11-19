package reporting

import "regexp"

// Observed outcomes emitted by an application-control behavioral step as an
// APPCTL_OUTCOME line. Expected intents come from the test contract.
const (
	AppCtlBlockedAsExpected = "blocked_as_expected"
	AppCtlAllowedUnexpected = "allowed_unexpectedly"
	AppCtlAllowedByPolicy   = "allowed_by_policy"
	AppCtlNotEnforced       = "not_enforced"
	AppCtlAuditedOnly       = "audited_only"
	AppCtlInconclusive      = "inconclusive"
	AppCtlNotApplicable     = "not_applicable"

	AppCtlExpectBlocked = "blocked"
	AppCtlExpectAllowed = "allowed"
)

var appCtlObservedValues = map[string]bool{
	AppCtlBlockedAsExpected: true, AppCtlAllowedUnexpected: true,
	AppCtlAllowedByPolicy: true, AppCtlNotEnforced: true, AppCtlAuditedOnly: true,
	AppCtlInconclusive: true, AppCtlNotApplicable: true,
}

var appCtlOutcomeRe = regexp.MustCompile(`(?m)^APPCTL_OUTCOME:\s*(\S+)\s*$`)

// ParseAppControlOutcome returns the single observed outcome a step emitted.
// Missing, malformed, or multiple differing markers are not parseable: an
// ambiguous result must not reach the comparator as a verdict.
func ParseAppControlOutcome(output string) (string, bool) {
	matches := appCtlOutcomeRe.FindAllStringSubmatch(output, -1)
	if len(matches) == 0 {
		return "", false
	}
	value := matches[0][1]
	for _, m := range matches[1:] {
		if m[1] != value {
			return "", false
		}
	}
	if !appCtlObservedValues[value] {
		return "", false
	}
	return value, true
}

// appcontrolComparator maps a contract's declared intent against an observed
// outcome. Inconclusive is never a Match, and blocked-as-expected only
// matches a contract that expected a block.
type appcontrolComparator struct{}

func (appcontrolComparator) Compare(expected, observed string) ComparisonResult {
	if !appCtlObservedValues[observed] {
		return Unknown
	}
	switch observed {
	case AppCtlInconclusive:
		return MissingEvidence
	case AppCtlNotApplicable:
		return NotApplicable
	}
	switch expected {
	case AppCtlExpectBlocked:
		if observed == AppCtlBlockedAsExpected {
			return Match
		}
		return Mismatch
	case AppCtlExpectAllowed:
		if observed == AppCtlAllowedByPolicy {
			return Match
		}
		return Mismatch
	}
	return Unknown
}

func init() {
	RegisterComparator("appcontrol", appcontrolComparator{})
}

// AppControlEvidence is the evidence a behavioral application-control result
// carries. Mirrors DLPEvidence: Limitations is always populated.
type AppControlEvidence struct {
	CollectionMethod        string
	CorrelationID           string
	FixtureID               string
	EffectivePolicySnapshot string
	CaptureTimestamp        string
	PolicyEvaluated         bool
	Limitations             string
}

const appControlDefaultLimitations = "Results hold only for the tested Windows build, policy version, and execution path. They do not generalize to other paths, policy scopes, or products. Attribution depends on the control's event log being retained and readable."

// NewAppControlEvidence builds evidence with the standard limitations text.
func NewAppControlEvidence(method, correlationID, fixtureID, policySnapshot, capturedAt string, evaluated bool) AppControlEvidence {
	return AppControlEvidence{
		CollectionMethod:        method,
		CorrelationID:           correlationID,
		FixtureID:               fixtureID,
		EffectivePolicySnapshot: policySnapshot,
		CaptureTimestamp:        capturedAt,
		PolicyEvaluated:         evaluated,
		Limitations:             appControlDefaultLimitations,
	}
}

// Path families an application-control step can report under APPCTL_FAMILY.
var appCtlFamilies = map[string]bool{
	"indirect_execution": true, "alternate_binary": true,
	"script_host_proxy": true, "alternate_ps_host": true,
	"parent_child_asr": true, "inprocess_hosting": true,
}

// Families emitted by the Application Control Mastery scenarios. They share
// the outcome vocabulary above and are listed in a report only when a run
// produced them, so older runs keep their six-family view.
var appCtlMasteryFamilies = []string{
	"regsvr32_proxy", "rundll32_proxy", "mshta_proxy", "msiexec_proxy", "installutil_proxy",
	"control_panel_cpl", "cmstp_proxy", "xsl_script_processing", "msbuild_proxy",
	"wscript_host", "cmd_batch_script", "wsf_script_host", "user_writable_script_host",
	"powershell_script_signing", "powershell_language_mode", "wmi_process_create", "alternate_interpreters",
	"unsigned_executable", "tampered_signature", "publisher_trust", "exec_from_temp",
	"exec_from_appdata", "exec_from_downloads", "renamed_extension", "dll_loading",
	"ocx_module_loading", "msi_installation",
	"policy_service_interruption", "policy_modification", "policy_downgrade",
	"supplemental_policy", "managed_installer", "policy_after_reboot", "policy_lifecycle",
	"packaged_app_rules", "sideloading_policy", "always_install_elevated", "writable_allowed_paths",
	"dll_search_order", "com_activation", "scheduled_task_launch", "service_launch",
	"enforcement_log_health", "identity_service_reliability", "overbroad_allow_rules",
}

func init() {
	for _, f := range appCtlMasteryFamilies {
		appCtlFamilies[f] = true
	}
}

// Telemetry visibility values reported under APPCTL_DETECTION. Visibility is
// a separate fact from prevention: it says whether the attempt reached
// telemetry, not whether it was blocked.
var appCtlVisibilityValues = map[string]bool{
	"visible": true, "not_visible": true, "unknown": true,
}

var (
	appCtlFamilyRe    = regexp.MustCompile(`(?m)^APPCTL_FAMILY:\s*(\S+)\s*$`)
	appCtlDetectionRe = regexp.MustCompile(`(?m)^APPCTL_DETECTION:.*\bresult=(\S+)\s*$`)
)

// ParseAppControlFamily returns the path family a step declared.
func ParseAppControlFamily(output string) (string, bool) {
	m := appCtlFamilyRe.FindStringSubmatch(output)
	if m == nil || !appCtlFamilies[m[1]] {
		return "", false
	}
	return m[1], true
}

// ParseAppControlVisibility returns the telemetry visibility a step reported.
func ParseAppControlVisibility(output string) (string, bool) {
	m := appCtlDetectionRe.FindStringSubmatch(output)
	if m == nil || !appCtlVisibilityValues[m[1]] {
		return "", false
	}
	return m[1], true
}

// AppControlPathResult is one evaluated path in the coverage matrix.
// Prevention (Outcome) and telemetry (Visibility) are kept as separate facts.
type AppControlPathResult struct {
	Family     string
	Technique  string
	Outcome    string
	Visibility string
}
