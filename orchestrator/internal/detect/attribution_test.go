package detect

import (
	"testing"
	"time"
)

// A technique is "detected" only when something attributable to a security
// control fired. An alert that merely happens to land in the same five minutes
// is co-occurrence, and calling it a detection inflates the client's score.

func mkStep(id string, at time.Time) ExecutedStep {
	return ExecutedStep{TechniqueID: id, Verdict: "fail", ExecutedAt: at}
}

func correlateOne(t *testing.T, a AlertRecord) TechniqueDetection {
	t.Helper()
	base := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	a.Timestamp = base.Add(30 * time.Second)
	dets := Correlate([]ExecutedStep{mkStep("T1059", base)}, []AlertRecord{a},
		5*time.Minute, defaultDefenderDetectIDs())
	if len(dets) != 1 {
		t.Fatalf("want 1 detection, got %d", len(dets))
	}
	return dets[0]
}

// The regression that motivated this: an ordinary Linux housekeeping failure
// used to mark every in-window technique as detected.
func TestCorrelate_JournalNoiseIsLoggedNotDetected(t *testing.T) {
	d := correlateOne(t, AlertRecord{
		Channel: "journal", Provider: "systemd", Level: "Warning",
		Message: "apt-daily.service: Failed with result 'exit-code'.",
	})
	if d.Verdict != "logged" {
		t.Errorf("Verdict = %q, want logged: nothing attributes this to a control", d.Verdict)
	}
	if d.Alert == nil {
		t.Error("the alert must still be attached so an analyst can see what co-occurred")
	}
}

// The same rule applies on Windows. A service-install event is not a detection
// just because it landed in the window.
func TestCorrelate_WindowsNoiseIsLoggedNotDetected(t *testing.T) {
	d := correlateOne(t, AlertRecord{
		Channel: "System", Provider: "Service Control Manager", EventID: 7045,
	})
	if d.Verdict != "logged" {
		t.Errorf("Verdict = %q, want logged", d.Verdict)
	}
}

// An EDR daemon logging during the window IS attributable. On POSIX it is the
// only signal available, because no POSIX source populates ThreatName -- so
// requiring a threat name here would discard the evidence entirely.
func TestCorrelate_EDRProviderAloneIsADetection(t *testing.T) {
	d := correlateOne(t, AlertRecord{
		Channel: "journal", Provider: "falcon-sensor", Level: "Error",
		Message: "Detection: malicious script quarantined",
	})
	if d.Verdict != "detected" {
		t.Fatalf("Verdict = %q, want detected", d.Verdict)
	}
	if !hasMatch(d.MatchedBy, "edrProvider") {
		t.Errorf("MatchedBy = %v, want it to record edrProvider", d.MatchedBy)
	}
}

// A kernel denial is an enforcement action the kernel itself classified. The
// agent ships the raw record; deciding it counts is the server's job.
func TestCorrelate_AuditDenialIsADetection(t *testing.T) {
	d := correlateOne(t, AlertRecord{
		Channel: "auditd", Provider: "curl", Level: "Warning",
		Message: `type=AVC msg=audit(1757000553.123:4567): avc:  denied  { execute } for  pid=1 comm="curl"`,
	})
	if d.Verdict != "detected" {
		t.Fatalf("Verdict = %q, want detected for an AVC denial", d.Verdict)
	}
	if !hasMatch(d.MatchedBy, "kernelDenial") {
		t.Errorf("MatchedBy = %v, want kernelDenial", d.MatchedBy)
	}
}

// An operator-keyed audit rule is a watch, not a denial. It is worth surfacing
// but it is not evidence that anything reacted.
func TestCorrelate_AuditKeyedSyscallIsLogged(t *testing.T) {
	d := correlateOne(t, AlertRecord{
		Channel: "auditd", Provider: "bash", Level: "Information",
		Message: `type=SYSCALL msg=audit(1757000554.500:4568): comm="bash" key="susp_exec"`,
	})
	if d.Verdict != "logged" {
		t.Errorf("Verdict = %q, want logged: a watch rule firing is not a reaction", d.Verdict)
	}
}

// Gatekeeper and XProtect write verdicts into their own subsystems. Those are
// security decisions, so co-occurrence there is attributable.
func TestCorrelate_AppleSecuritySubsystemIsADetection(t *testing.T) {
	d := correlateOne(t, AlertRecord{
		Channel: "com.apple.syspolicy", Provider: "syspolicyd", Level: "Error",
		Message: "GK evaluateScanResult: blocked",
	})
	if d.Verdict != "detected" {
		t.Fatalf("Verdict = %q, want detected", d.Verdict)
	}
	if !hasMatch(d.MatchedBy, "securitySubsystem") {
		t.Errorf("MatchedBy = %v, want securitySubsystem", d.MatchedBy)
	}
}

// A Mac application crashing is not a security decision.
func TestCorrelate_NonSecurityAppleSubsystemIsLogged(t *testing.T) {
	d := correlateOne(t, AlertRecord{
		Channel: "com.apple.mail", Provider: "Mail", Level: "Error",
		Message: "failed to fetch mailbox",
	})
	if d.Verdict != "logged" {
		t.Errorf("Verdict = %q, want logged", d.Verdict)
	}
}

// Windows detections must be untouched by all of the above.
func TestCorrelate_WindowsDefenderDetectionStillDetected(t *testing.T) {
	d := correlateOne(t, AlertRecord{
		Channel:  "Microsoft-Windows-Windows Defender/Operational",
		Provider: "Microsoft-Windows-Windows Defender", EventID: 1116,
		ThreatName: "Trojan:Win32/Meterpreter",
	})
	if d.Verdict != "detected" || d.Confidence != "high" {
		t.Fatalf("want detected/high, got %+v", d)
	}
}

// Score must keep logged out of the detection numerator while still counting
// the step as executed -- it ran, and something was logged; neither fact may
// silently vanish.
func TestScore_LoggedIsNotADetection(t *testing.T) {
	sum := Score([]TechniqueDetection{
		{TechniqueID: "T1", Verdict: "detected"},
		{TechniqueID: "T2", Verdict: "logged"},
		{TechniqueID: "T3", Verdict: "logged"},
		{TechniqueID: "T4", Verdict: "undetected"},
	})
	if sum.Executed != 4 {
		t.Errorf("Executed = %d, want 4", sum.Executed)
	}
	if sum.Detected != 1 || sum.Logged != 2 || sum.Undetected != 1 {
		t.Errorf("counts = detected %d / logged %d / undetected %d",
			sum.Detected, sum.Logged, sum.Undetected)
	}
	if sum.DetectionRate != 25 {
		t.Errorf("DetectionRate = %d, want 25 (1 of 4), not 75", sum.DetectionRate)
	}
	if got := sum.DetectionRate + sum.LoggedRate + sum.UndetectedRate; got != 100 {
		t.Errorf("rates sum to %d, want 100", got)
	}
}

// The whole point, end to end: background noise must not produce a detection
// rate at all.
func TestScore_NoiseAloneScoresZeroDetectionRate(t *testing.T) {
	base := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	steps := []ExecutedStep{mkStep("T1059", base), mkStep("T1070", base)}
	noise := []AlertRecord{{
		Channel: "journal", Provider: "systemd", Level: "Warning",
		Timestamp: base.Add(30 * time.Second),
		Message:   "apt-daily.service: Failed with result 'exit-code'.",
	}}
	sum := Score(Correlate(steps, noise, 5*time.Minute, defaultDefenderDetectIDs()))
	if sum.DetectionRate != 0 {
		t.Fatalf("DetectionRate = %d, want 0 for pure noise", sum.DetectionRate)
	}
	if sum.Logged != 2 {
		t.Errorf("Logged = %d, want 2", sum.Logged)
	}
}

// A recipient reporting a simulated phishing email through the exercise's own
// tracking is a real, human-confirmed control reaction -- just not an
// endpoint one. It must attribute the same way the five endpoint signals do.
func TestCorrelate_UserReportIsADetection(t *testing.T) {
	d := correlateOne(t, AlertRecord{
		Channel: "exercise-report", Provider: "exercise-tracking",
	})
	if d.Verdict != "detected" {
		t.Fatalf("Verdict = %q, want detected", d.Verdict)
	}
	if !hasMatch(d.MatchedBy, "userReported") {
		t.Errorf("MatchedBy = %v, want userReported", d.MatchedBy)
	}
}

// An ordinary endpoint alert must never gain userReported just because it
// happens to land in the window -- that signal is exclusively for the
// exercise's own report channel.
func TestCorrelate_EndpointAlertNeverGetsUserReported(t *testing.T) {
	d := correlateOne(t, AlertRecord{
		Channel: "Microsoft-Windows-Windows Defender/Operational",
		Provider: "Microsoft-Windows-Windows Defender", EventID: 1116,
		ThreatName: "Trojan:Win32/Meterpreter",
	})
	if hasMatch(d.MatchedBy, "userReported") {
		t.Errorf("MatchedBy = %v, unexpectedly included userReported", d.MatchedBy)
	}
}

func hasMatch(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
