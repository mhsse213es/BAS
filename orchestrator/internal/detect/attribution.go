package detect

import "strings"

// Attribution decides whether an alert is evidence that a security control
// reacted, as opposed to something that merely happened at the same time.
//
// WHY THIS EXISTS. Correlate finds an alert inside a step's time window. That
// match is co-occurrence, not causation: on a general-purpose system log,
// something is almost always being written. Treating co-occurrence as proof of
// detection produced a 100% detection rate from a single unrelated
// `apt-daily.service` failure -- a fabricated score, and the kind of number
// that must never reach a client.
//
// So the window match decides only WHICH alert is relevant. This file decides
// whether that alert says a control did anything. Nothing here inspects free
// text for badness; every signal is either a structured field the producer set,
// or a classification the producer itself made.
//
// This is the server side of the agent/server split. The agent ships raw
// records and never classifies. Interpreting them is this package's job.

// attributionSignals returns the names of every reason this alert counts as
// evidence of a control reacting. An empty result means the alert is worth
// showing an analyst but is not a detection.
func attributionSignals(a AlertRecord, detectIDs map[int]bool) []string {
	var out []string

	// A Defender detect ID is Defender stating it acted on a threat.
	if detectIDs[a.EventID] {
		out = append(out, "defenderDetectId")
	}

	// A threat name is a defender's own verdict string. No POSIX source sets
	// one, so this signal is Windows-only in practice.
	if a.ThreatName != "" {
		out = append(out, "threatName")
	}

	// An EDR daemon writing during the window is attributable on its own.
	//
	// This deliberately does NOT also require a threat name. That pairing was
	// the reason a genuine falcon-sensor quarantine scored no higher than
	// background noise: POSIX collectors cannot populate ThreatName at all, so
	// demanding it discarded the only provider evidence those platforms have.
	if IsEDRProvider(a.Provider) {
		out = append(out, "edrProvider")
	}

	// The kernel denied the action. That is an enforcement event the kernel
	// classified itself, by record type -- not our reading of the message.
	if isKernelDenial(a) {
		out = append(out, "kernelDenial")
	}

	// The alert came from a log stream whose entire purpose is security
	// decisions, so an entry in it is a decision.
	if isSecuritySubsystem(a.Channel) {
		out = append(out, "securitySubsystem")
	}

	// A simulated-phishing recipient reported it through the exercise's own
	// tracking/report mechanism (internal/exercise's phishing_reported
	// evidence, translated into this shape) -- a real, human-confirmed
	// control reaction, just not an endpoint one. Distinct from the five
	// signals above (all endpoint/EDR/kernel-audit concepts) but
	// participates in the exact same attribution/verdict/scoring model.
	if a.Channel == "exercise-report" {
		out = append(out, "userReported")
	}

	return out
}

// auditDenialTypes are the audit record types that report a denial or an
// anomaly. This mirrors the agent's collection filter, but the two serve
// different jobs and are deliberately not shared: the agent's list decides what
// is worth carrying, this one decides what counts as a reaction. An
// operator-keyed SYSCALL is carried by the agent and is absent here, because a
// watch rule firing means someone chose to watch, not that anything reacted.
var auditDenialTypes = map[string]bool{
	"AVC":              true,
	"USER_AVC":         true,
	"AVC_PATH":         true,
	"SELINUX_ERR":      true,
	"USER_SELINUX_ERR": true,
	"APPARMOR_DENIED":  true,
	"ANOM_ABEND":       true,
	"ANOM_ACCESS_FS":   true,
	"ANOM_EXEC":        true,
	"ANOM_LINK":        true,
	"ANOM_PROMISCUOUS": true,
	"SECCOMP":          true,
	"INTEGRITY_DATA":   true,
	"INTEGRITY_RULE":   true,
	"FANOTIFY":         true,
}

// isKernelDenial reads the leading `type=` token the audit subsystem writes on
// every record. The agent preserves the raw line precisely so this stays
// possible without the agent having to interpret it.
func isKernelDenial(a AlertRecord) bool {
	if a.Channel != "auditd" {
		return false
	}
	rest, ok := strings.CutPrefix(a.Message, "type=")
	if !ok {
		return false
	}
	if i := strings.IndexAny(rest, " \t"); i >= 0 {
		rest = rest[:i]
	}
	return auditDenialTypes[rest]
}

// securitySubsystems are macOS unified-log subsystems that exist to record
// security decisions: policy evaluation, code signing, malware remediation and
// privacy consent. An entry in one of these is a verdict, not chatter.
var securitySubsystems = map[string]bool{
	"com.apple.syspolicy":         true,
	"com.apple.securityd":         true,
	"com.apple.security":          true,
	"com.apple.xprotect":          true,
	"com.apple.XProtectFramework": true,
	"com.apple.TCC":               true,
	"com.apple.endpointsecurity":  true,
	"com.apple.SystemPolicy":      true,
}

func isSecuritySubsystem(channel string) bool { return securitySubsystems[channel] }

// confidenceFor ranks how firmly the signals support a detection.
//
// A named threat or a vendor detect ID is the control telling us what it found.
// A provider, a kernel denial or a security subsystem tells us a control acted
// but not what it concluded -- real evidence, held one step lower so a report
// can distinguish the two.
func confidenceFor(signals []string) string {
	for _, s := range signals {
		if s == "defenderDetectId" || s == "threatName" {
			return "high"
		}
	}
	return "medium"
}

// IsAttributable reports whether an alert is evidence that a security control
// acted, as opposed to something that merely co-occurred. Exported so callers
// scoring alert quality use the same rule Correlate does, rather than keeping a
// second copy that drifts.
func IsAttributable(a AlertRecord, detectIDs map[int]bool) bool {
	return len(attributionSignals(a, detectIDs)) > 0
}
