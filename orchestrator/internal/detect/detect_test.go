package detect

import (
	"testing"
	"time"
)

func TestIsEDRProvider(t *testing.T) {
	hits := []string{"Microsoft Defender Antivirus", "Trellix Endpoint Security",
		"CrowdStrike Falcon Sensor", "SentinelOne Agent", "Sophos Intercept X",
		"Trend Micro Apex One", "Cortex XDR", "Elastic Endpoint", "FortiEDR"}
	for _, p := range hits {
		if !IsEDRProvider(p) {
			t.Errorf("expected EDR provider match: %q", p)
		}
	}
	for _, p := range []string{"Microsoft-Windows-Kernel-General", "Service Control Manager"} {
		if IsEDRProvider(p) {
			t.Errorf("unexpected EDR match: %q", p)
		}
	}
}

func mkResult(id, verdict string, at time.Time) ExecutedStep {
	return ExecutedStep{TechniqueID: id, Verdict: verdict, ExecutedAt: at, DurationMs: 1000}
}

func TestCorrelateAndScore(t *testing.T) {
	base := time.Date(2026, 6, 16, 10, 0, 0, 0, time.UTC)
	steps := []ExecutedStep{
		mkResult("T1486", "pass", base),                        // prevented
		mkResult("T1059.001", "fail", base.Add(time.Minute)),   // detected (alert in window)
		mkResult("T1003.001", "fail", base.Add(2*time.Minute)), // undetected (no alert)
		mkResult("T1018", "error", base.Add(3*time.Minute)),    // excluded
	}
	alerts := []AlertRecord{{
		Provider: "Microsoft Defender Antivirus", EventID: 1116,
		ThreatName: "PowerShell/Amsi.A", Timestamp: base.Add(time.Minute + 4*time.Second),
	}}
	dets := Correlate(steps, alerts, 5*time.Minute, defaultDefenderDetectIDs())
	sum := Score(dets)
	if sum.Executed != 3 || sum.Prevented != 1 || sum.Detected != 1 || sum.Undetected != 1 {
		t.Fatalf("counts wrong: %+v", sum)
	}
	if sum.DetectionRate != 50 || sum.UndetectedRate != 50 || sum.PreventionRate != 33 {
		t.Fatalf("rates wrong: %+v", sum)
	}
	if sum.MTTDMs != 4000 {
		t.Fatalf("mttd = %d, want 4000", sum.MTTDMs)
	}
	// detected technique must be high confidence (Defender detect id + threat name)
	for _, d := range dets {
		if d.TechniqueID == "T1059.001" {
			if d.Verdict != "detected" || d.Confidence != "high" {
				t.Fatalf("T1059.001 = %+v", d)
			}
			if d.TimeToDetectMs != 4000 {
				t.Fatalf("ttd = %d", d.TimeToDetectMs)
			}
		}
		if d.TechniqueID == "T1486" && d.Verdict != "prevented" {
			t.Fatalf("prevented step misclassified: %+v", d)
		}
	}
}

func TestCorrelateUnattributedIsLogged(t *testing.T) {
	base := time.Date(2026, 6, 16, 10, 0, 0, 0, time.UTC)
	steps := []ExecutedStep{mkResult("T1059", "fail", base)}
	alerts := []AlertRecord{{Provider: "Service Control Manager", EventID: 7045,
		Timestamp: base.Add(2 * time.Second)}} // in window, not a detection
	dets := Correlate(steps, alerts, 5*time.Minute, defaultDefenderDetectIDs())
	// It lands in the window and nothing else, which is what this test always
	// described. "logged" now says that instead of overstating it as a detection.
	if dets[0].Verdict != "logged" {
		t.Fatalf("expected logged, got %+v", dets[0])
	}
	if dets[0].Alert == nil {
		t.Fatal("the co-occurring alert must still be attached for review")
	}
}
