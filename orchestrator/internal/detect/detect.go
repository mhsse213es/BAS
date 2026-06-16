package detect

import "time"

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
	TechniqueID    string       `json:"techniqueId"`
	Verdict        string       `json:"verdict"`              // prevented|detected|undetected (logged handled by report classifier)
	Confidence     string       `json:"confidence,omitempty"` // high|low when detected
	MatchedBy      []string     `json:"matchedBy,omitempty"`
	Alert          *AlertRecord `json:"alert,omitempty"`
	TimeToDetectMs int64        `json:"timeToDetectMs,omitempty"`
}

type DetectionSummary struct {
	Executed       int   `json:"executed"`
	Prevented      int   `json:"prevented"`
	Detected       int   `json:"detected"`
	Undetected     int   `json:"undetected"`
	PreventionRate int   `json:"preventionRate"`
	DetectionRate  int   `json:"detectionRate"`
	UndetectedRate int   `json:"undetectedRate"`
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
// never detected. The first matching alert wins (earliest). Confidence is high
// when the alert is a bona-fide detection (Defender detect id / non-empty threat
// name / EDR provider), else low. error/skipped steps are excluded entirely.
func Correlate(steps []ExecutedStep, alerts []AlertRecord, window time.Duration, detectIDs map[int]bool) []TechniqueDetection {
	out := make([]TechniqueDetection, 0, len(steps))
	for _, s := range steps {
		if !isExecuted(s.Verdict) {
			continue
		}
		if isPrevented(s.Verdict) {
			out = append(out, TechniqueDetection{TechniqueID: s.TechniqueID, Verdict: "prevented"})
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
		matchedBy := []string{"timestamp"}
		conf := "low"
		if detectIDs[best.EventID] {
			matchedBy = append(matchedBy, "defenderDetectId")
			conf = "high"
		}
		if best.ThreatName != "" {
			matchedBy = append(matchedBy, "threatName")
			conf = "high"
		}
		if IsEDRProvider(best.Provider) && best.ThreatName != "" {
			matchedBy = append(matchedBy, "edrProvider")
			conf = "high"
		}
		alertCopy := *best
		out = append(out, TechniqueDetection{
			TechniqueID: s.TechniqueID, Verdict: "detected", Confidence: conf,
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
		case "undetected":
			s.Executed++
			s.Undetected++
		}
	}
	notPrevented := s.Detected + s.Undetected
	if s.Executed > 0 {
		s.PreventionRate = pct(s.Prevented, s.Executed)
	}
	if notPrevented > 0 {
		s.DetectionRate = pct(s.Detected, notPrevented)
		s.UndetectedRate = pct(s.Undetected, notPrevented)
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
