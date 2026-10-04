package detect

import (
	"time"
)

// AlertRecord mirrors the agent's wire shape (agent/types.go AlertRecord).
type AlertRecord struct {
	Channel     string    `json:"channel"`
	Provider    string    `json:"provider"`
	EventID     int       `json:"eventId"`
	Level       string    `json:"level"`
	Timestamp   time.Time `json:"timestamp"`
	ThreatName  string    `json:"threatName,omitempty"`
	ProcessName string    `json:"processName,omitempty"`
	ProcessPath string    `json:"processPath,omitempty"`
	CommandLine string    `json:"commandLine,omitempty"`
	User        string    `json:"user,omitempty"`
	Message     string    `json:"message,omitempty"`
}

// ExecutedStep is the minimal projection of a run result needed for correlation.
type ExecutedStep struct {
	TechniqueID string
	Verdict     string // pass|fail|blocked|skipped|error
	ExecutedAt  time.Time
	DurationMs  int64
}

type TechniqueDetection struct {
	TechniqueID     string           `json:"techniqueId"`
	Verdict         string           `json:"verdict"`              // prevented|detected|logged|undetected
	Confidence      string           `json:"confidence,omitempty"` // high|medium when detected
	MatchedBy       []string         `json:"matchedBy,omitempty"`
	Alert           *AlertRecord     `json:"alert,omitempty"`
	TimeToDetectMs  int64            `json:"timeToDetectMs,omitempty"`
	BlockingControl *BlockingControl `json:"blockingControl,omitempty"` // which control prevented the technique
}

type DetectionSummary struct {
	Executed       int   `json:"executed"`
	Prevented      int   `json:"prevented"`
	Detected       int   `json:"detected"`
	Undetected     int   `json:"undetected"`
	Logged         int   `json:"logged"`
	PreventionRate int   `json:"preventionRate"`
	DetectionRate  int   `json:"detectionRate"`
	UndetectedRate int   `json:"undetectedRate"`
	LoggedRate     int   `json:"loggedRate"`
	MTTDMs         int64 `json:"mttdMs"`
}

func isPrevented(v string) bool { return v == "pass" || v == "blocked" }
func isExecuted(v string) bool  { return v == "pass" || v == "blocked" || v == "fail" }

// defaultDefenderDetectIDs returns Defender Operational event IDs that mean a
// threat was detected/acted on. Kept in sync with reporting.defenderDetectIDs.
func defaultDefenderDetectIDs() map[int]bool {
	return map[int]bool{1006: true, 1007: true, 1008: true, 1009: true, 1010: true,
		1011: true, 1012: true, 1015: true, 1116: true, 1117: true, 1118: true, 1119: true}
}

// DefenderDetectIDs is the exported Defender detect-ID set for callers.
func DefenderDetectIDs() map[int]bool { return defaultDefenderDetectIDs() }

// Correlate maps alerts to executed steps by time window. A step matches an alert
// when alert.ts ∈ [step.ExecutedAt, step.ExecutedAt+window]. Prevented steps are
// never detected. The first matching alert wins (earliest). error/skipped steps
// are excluded entirely.
//
// The window decides WHICH alert is relevant; it does not decide that a
// detection occurred. That takes an attribution signal (see attribution.go) --
// a vendor detect ID, a threat name, an EDR provider, a kernel denial or a
// security subsystem. A match with no such signal is "logged": worth showing an
// analyst, but not counted as a detection, because on a general-purpose system
// log something is almost always being written inside any five-minute window.
func Correlate(steps []ExecutedStep, alerts []AlertRecord, window time.Duration, detectIDs map[int]bool) []TechniqueDetection {
	out := make([]TechniqueDetection, 0, len(steps))
	for _, s := range steps {
		if !isExecuted(s.Verdict) {
			continue
		}
		if isPrevented(s.Verdict) {
			// Scan alerts in a wider window (block events fire at or just after
			// process-create denial) to identify which control blocked the technique.
			blockWinStart := s.ExecutedAt.Add(-10 * time.Second)
			blockWinEnd := s.ExecutedAt.Add(60 * time.Second)
			var ctrl *BlockingControl
			for i := range alerts {
				ts := alerts[i].Timestamp
				if (ts.Equal(blockWinStart) || ts.After(blockWinStart)) && !ts.After(blockWinEnd) {
					if c := AttributeControl(alerts[i]); c != nil {
						ctrl = c
						break
					}
				}
			}
			out = append(out, TechniqueDetection{
				TechniqueID: s.TechniqueID, Verdict: "prevented",
				BlockingControl: ctrl,
			})
			continue
		}
		// not prevented (fail) → look for an in-window alert
		winEnd := s.ExecutedAt.Add(window)
		var best *AlertRecord
		for i := range alerts {
			ts := alerts[i].Timestamp
			if (ts.Equal(s.ExecutedAt) || ts.After(s.ExecutedAt)) && !ts.After(winEnd) {
				if best == nil || ts.Before(best.Timestamp) {
					best = &alerts[i]
				}
			}
		}
		if best == nil {
			out = append(out, TechniqueDetection{TechniqueID: s.TechniqueID, Verdict: "undetected"})
			continue
		}
		signals := attributionSignals(*best, detectIDs)
		matchedBy := append([]string{"timestamp"}, signals...)
		alertCopy := *best
		if len(signals) == 0 {
			// In the window, but nothing attributes it to a control acting.
			// "logged" says exactly that, and the alert rides along so an
			// analyst can judge it. Calling this "detected" is what produced a
			// 100% detection rate from unrelated background noise.
			out = append(out, TechniqueDetection{
				TechniqueID: s.TechniqueID, Verdict: "logged",
				MatchedBy: matchedBy, Alert: &alertCopy,
			})
			continue
		}
		out = append(out, TechniqueDetection{
			TechniqueID: s.TechniqueID, Verdict: "detected", Confidence: confidenceFor(signals),
			MatchedBy: matchedBy, Alert: &alertCopy,
			TimeToDetectMs: best.Timestamp.Sub(s.ExecutedAt).Milliseconds(),
		})
	}
	return out
}

// Score computes counts, the three rates, and MTTD. Prevented techniques are
// EXCLUDED from the detection/undetected denominator (executed-and-not-prevented).
func Score(dets []TechniqueDetection) DetectionSummary {
	var s DetectionSummary
	var ttdSum, ttdN int64
	for _, d := range dets {
		switch d.Verdict {
		case "prevented":
			s.Executed++
			s.Prevented++
		case "detected":
			s.Executed++
			s.Detected++
			ttdSum += d.TimeToDetectMs
			ttdN++
		case "logged":
			// The step ran and something was logged, but nothing attributed it
			// to a control. It is executed and it is NOT a detection; counting
			// it anywhere else would either inflate the rate or hide the step.
			s.Executed++
			s.Logged++
		case "undetected":
			s.Executed++
			s.Undetected++
		}
	}
	notPrevented := s.Detected + s.Undetected + s.Logged
	if s.Executed > 0 {
		s.PreventionRate = pct(s.Prevented, s.Executed)
	}
	if notPrevented > 0 {
		s.DetectionRate = pct(s.Detected, notPrevented)
		s.UndetectedRate = pct(s.Undetected, notPrevented)
		s.LoggedRate = pct(s.Logged, notPrevented)
	}
	if ttdN > 0 {
		s.MTTDMs = ttdSum / ttdN
	}
	return s
}

func pct(n, d int) int {
	if d == 0 {
		return 0
	}
	return int((float64(n)/float64(d))*100 + 0.5)
}
