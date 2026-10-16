package api

// Workstream 1 of the EmailGW mastery roadmap: time-based metrics
// (MTTD/MTTR) and sample-quality controls, computed purely over
// already-persisted email_gw_runs rows -- same compute-on-read
// posture as buildEmailGWRunsSummary, never a separately maintained
// running total.
//
// Two rules this file exists specifically to enforce:
//
//  1. MTTD/MTTR are never CompletedAt-InjectedAt. CompletedAt is only
//     "when this run's async dwell-window poll happened to finish" --
//     it has no relationship to when a detection alert or a response
//     action actually completed. MTTD instead uses the EARLIEST
//     DetectionEvidence with AlertGenerated=true (a first-detection,
//     i.e. speed, metric); MTTR reuses ResponseEvidence's own
//     DurationToComplete from the earliest Completed=true record,
//     already computed by the vendor adapter itself from the alert's
//     real creation/resolution timestamps (see defender.go) -- never
//     re-derived from this package's own run-lifecycle timestamps.
//  2. A metric with too little data, or none at all, reports an
//     explicit unavailable/insufficient state -- never a fabricated
//     zero, and never silently mixes runs from different
//     emailgwrun.Environment values into one number.
import (
	"encoding/json"
	"sort"
	"time"

	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/emailgwrun"
)

// DefaultEmailGWMinimumSampleSize is the floor below which a latency
// metric is reported as present-but-insufficient rather than a mean
// over too few points to mean anything -- configurable per call
// (ComputeEmailGWTimeBasedMetrics takes it as a parameter) so a test
// can exercise the insufficient-data path without needing this many
// real runs.
const DefaultEmailGWMinimumSampleSize = 5

// EmailGWRunOutcomeCounts classifies every run considered for a
// metrics computation into mutually exclusive buckets. This is the
// sample-quality/data-completeness indicator the latency metrics
// below are computed against -- a caller sees the counts behind a
// metric, never just a number with no visible denominator.
type EmailGWRunOutcomeCounts struct {
	// Pending: still in flight, the run's own dwell window has not
	// yet closed. Excluded from every verdict/latency computation --
	// not yet decided, never counted as a failure or a success.
	Pending int `json:"pending"`
	// Timeout: the dwell window closed (WindowEnd has passed) but the
	// run never reached a terminal status -- a real operational gap
	// (the recovery sweep has not yet caught it, or the process is
	// mid-restart), not a dimension verdict.
	Timeout int `json:"timeout"`
	// Failed: injection itself failed (StatusFailed) -- no evidence
	// was ever gathered for any dimension.
	Failed int `json:"failed"`
	// MissingEvidence: the run reached a terminal status but its
	// Result column could not be decoded at all.
	MissingEvidence int `json:"missingEvidence"`
	// The remaining five mirror emailgwefficacy.EmailGWVerdict
	// exactly, for the one dimension this count set was built for.
	ConfirmedSuccess int `json:"confirmedSuccess"`
	ConfirmedFailure int `json:"confirmedFailure"`
	Inconclusive     int `json:"inconclusive"`
	NotTested        int `json:"notTested"`
	NotApplicable    int `json:"notApplicable"`
}

// EmailGWLatencyMetric is one time-based metric (MTTD or MTTR)
// computed over a set of real runs, restricted to one
// emailgwrun.Environment. Unavailable is true whenever there is no
// eligible sample at all; Sufficient is false whenever SampleCount is
// below MinimumSampleSize -- both cases leave every numeric field nil
// rather than reporting a misleading number.
type EmailGWLatencyMetric struct {
	Environment       emailgwrun.Environment `json:"environment"`
	SampleCount       int                    `json:"sampleCount"`
	MinimumSampleSize int                    `json:"minimumSampleSize"`
	Unavailable       bool                   `json:"unavailable"`
	Sufficient        bool                   `json:"sufficient"`
	MeanSeconds       *float64               `json:"meanSeconds,omitempty"`
	MedianSeconds     *float64               `json:"medianSeconds,omitempty"`
	MinSeconds        *float64               `json:"minSeconds,omitempty"`
	MaxSeconds        *float64               `json:"maxSeconds,omitempty"`
	// WindowStart/WindowEnd are the earliest/latest StartedAt among
	// the runs this metric actually drew a sample from -- the
	// measurement window a consumer needs to judge how current (or
	// stale) this metric is, never the request's own time range.
	WindowStart *time.Time `json:"windowStart,omitempty"`
	WindowEnd   *time.Time `json:"windowEnd,omitempty"`
}

// EmailGWDimensionMetrics pairs one dimension's outcome counts with
// its own latency metric. Latency is nil for Prevention: emailGW.txt
// defines no time-based concept for prevention (a message is blocked
// or not at submission time, not "eventually" blocked), so there is
// nothing real to compute there -- never filled with a fabricated
// value just to keep the shape uniform.
type EmailGWDimensionMetrics struct {
	Outcomes EmailGWRunOutcomeCounts `json:"outcomes"`
	Latency  *EmailGWLatencyMetric   `json:"latency,omitempty"`
}

// EmailGWTimeBasedMetrics is Workstream 1's full result: one
// Environment's worth of real runs, split by dimension. A caller
// wanting both lab and customer numbers calls this twice -- the two
// are never combined into one response.
type EmailGWTimeBasedMetrics struct {
	Environment    emailgwrun.Environment  `json:"environment"`
	ComputedAt     time.Time               `json:"computedAt"`
	RunsConsidered int                     `json:"runsConsidered"`
	Prevention     EmailGWDimensionMetrics `json:"prevention"`
	Detection      EmailGWDimensionMetrics `json:"detection"`
	Response       EmailGWDimensionMetrics `json:"response"`
}

// emailGWLatencySample is one run's own contribution to a latency
// metric, kept as a (runID, duration, startedAt) triple purely so
// ComputeEmailGWTimeBasedMetrics can derive WindowStart/WindowEnd
// from the same runs it actually drew samples from.
type emailGWLatencySample struct {
	duration  time.Duration
	startedAt time.Time
}

// ComputeEmailGWTimeBasedMetrics is the pure computation core: no
// I/O, so a test can hand it fixture runs directly. runs need not be
// pre-filtered by environment -- this filters to exactly environment
// itself, so a caller can pass every run it has and call this once
// per environment without duplicating the filter.
func ComputeEmailGWTimeBasedMetrics(runs []*emailgwrun.EmailGWRun, environment emailgwrun.Environment, minimumSampleSize int, now time.Time) EmailGWTimeBasedMetrics {
	if minimumSampleSize <= 0 {
		minimumSampleSize = DefaultEmailGWMinimumSampleSize
	}

	var preventionCounts, detectionCounts, responseCounts EmailGWRunOutcomeCounts
	var detectionSamples, responseSamples []emailGWLatencySample
	runsConsidered := 0

	for _, run := range runs {
		runEnv := run.Environment
		if runEnv == "" {
			runEnv = emailgwrun.EnvironmentLab // never leave this unset -- see emailgwrun.Environment's own doc comment
		}
		if runEnv != environment {
			continue
		}
		runsConsidered++

		switch run.Status {
		case emailgwrun.StatusPending, emailgwrun.StatusRunning:
			overdue := run.WindowEnd != nil && now.After(*run.WindowEnd)
			if overdue {
				preventionCounts.Timeout++
				detectionCounts.Timeout++
				responseCounts.Timeout++
			} else {
				preventionCounts.Pending++
				detectionCounts.Pending++
				responseCounts.Pending++
			}
			continue
		case emailgwrun.StatusFailed:
			preventionCounts.Failed++
			detectionCounts.Failed++
			responseCounts.Failed++
			continue
		}

		// StatusCompleted or StatusPartial from here on.
		result, ok := decodeEmailGWRunResult(run.Result)
		if !ok {
			preventionCounts.MissingEvidence++
			detectionCounts.MissingEvidence++
			responseCounts.MissingEvidence++
			continue
		}

		countVerdict(&preventionCounts, result.Prevention.Verdict)
		countVerdict(&detectionCounts, result.DetectionVerdict.Verdict)
		countVerdict(&responseCounts, result.ResponseVerdict.Verdict)

		if result.DetectionVerdict.Verdict == emailgwefficacy.VerdictConfirmedSuccess {
			if d, ok := earliestDetectionLatency(result); ok {
				detectionSamples = append(detectionSamples, emailGWLatencySample{duration: d, startedAt: run.StartedAt})
			}
		}
		if result.ResponseVerdict.Verdict == emailgwefficacy.VerdictConfirmedSuccess {
			if d, ok := earliestResponseLatency(result); ok {
				responseSamples = append(responseSamples, emailGWLatencySample{duration: d, startedAt: run.StartedAt})
			}
		}
	}

	return EmailGWTimeBasedMetrics{
		Environment:    environment,
		ComputedAt:     now,
		RunsConsidered: runsConsidered,
		Prevention:     EmailGWDimensionMetrics{Outcomes: preventionCounts},
		Detection:      EmailGWDimensionMetrics{Outcomes: detectionCounts, Latency: buildLatencyMetric(environment, detectionSamples, minimumSampleSize)},
		Response:       EmailGWDimensionMetrics{Outcomes: responseCounts, Latency: buildLatencyMetric(environment, responseSamples, minimumSampleSize)},
	}
}

func decodeEmailGWRunResult(raw []byte) (emailgwefficacy.EfficacyResult, bool) {
	if len(raw) == 0 {
		return emailgwefficacy.EfficacyResult{}, false
	}
	var result emailgwefficacy.EfficacyResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return emailgwefficacy.EfficacyResult{}, false
	}
	return result, true
}

func countVerdict(counts *EmailGWRunOutcomeCounts, v emailgwefficacy.EmailGWVerdict) {
	switch v {
	case emailgwefficacy.VerdictConfirmedSuccess:
		counts.ConfirmedSuccess++
	case emailgwefficacy.VerdictConfirmedFailure:
		counts.ConfirmedFailure++
	case emailgwefficacy.VerdictInconclusive:
		counts.Inconclusive++
	case emailgwefficacy.VerdictNotTested:
		counts.NotTested++
	case emailgwefficacy.VerdictNotApplicable:
		counts.NotApplicable++
	}
}

// earliestDetectionLatency returns the earliest AlertGenerated=true
// DetectionEvidence's own Timestamp minus the real send/delivery
// moment (Observation.Timestamp) -- MTTD. Returns ok=false when the
// verdict says ConfirmedSuccess but no such record is actually
// present (an internal inconsistency this never papers over with a
// fabricated duration) or the computed duration would be negative.
func earliestDetectionLatency(result emailgwefficacy.EfficacyResult) (time.Duration, bool) {
	var earliest time.Time
	found := false
	for _, d := range result.Detection {
		if !d.AlertGenerated {
			continue
		}
		if !found || d.Timestamp.Before(earliest) {
			earliest = d.Timestamp
			found = true
		}
	}
	if !found {
		return 0, false
	}
	mttd := earliest.Sub(result.Observation.Timestamp)
	if mttd < 0 {
		return 0, false
	}
	return mttd, true
}

// earliestResponseLatency returns the earliest Completed=true
// ResponseEvidence's own already-computed DurationToComplete -- MTTR.
// Never re-derived from this package's own timestamps; see this
// file's own package comment for why.
func earliestResponseLatency(result emailgwefficacy.EfficacyResult) (time.Duration, bool) {
	var earliestTimestamp time.Time
	var duration time.Duration
	found := false
	for _, resp := range result.Response {
		if !resp.Completed {
			continue
		}
		if !found || resp.Timestamp.Before(earliestTimestamp) {
			earliestTimestamp = resp.Timestamp
			duration = resp.DurationToComplete
			found = true
		}
	}
	if !found || duration < 0 {
		return 0, false
	}
	return duration, true
}

func buildLatencyMetric(environment emailgwrun.Environment, samples []emailGWLatencySample, minimumSampleSize int) *EmailGWLatencyMetric {
	m := &EmailGWLatencyMetric{
		Environment:       environment,
		SampleCount:       len(samples),
		MinimumSampleSize: minimumSampleSize,
	}
	if len(samples) == 0 {
		m.Unavailable = true
		return m
	}
	m.Sufficient = len(samples) >= minimumSampleSize

	seconds := make([]float64, len(samples))
	var sum float64
	minStarted, maxStarted := samples[0].startedAt, samples[0].startedAt
	for i, s := range samples {
		seconds[i] = s.duration.Seconds()
		sum += seconds[i]
		if s.startedAt.Before(minStarted) {
			minStarted = s.startedAt
		}
		if s.startedAt.After(maxStarted) {
			maxStarted = s.startedAt
		}
	}
	sort.Float64s(seconds)

	mean := sum / float64(len(seconds))
	min := seconds[0]
	max := seconds[len(seconds)-1]
	median := medianOf(seconds)

	m.MeanSeconds = &mean
	m.MinSeconds = &min
	m.MaxSeconds = &max
	m.MedianSeconds = &median
	m.WindowStart = &minStarted
	m.WindowEnd = &maxStarted
	return m
}

func medianOf(sorted []float64) float64 {
	n := len(sorted)
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}
