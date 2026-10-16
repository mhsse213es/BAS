package api

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/emailgwrun"
)

func TestComputeEmailGWTimeBasedMetrics_EmptyInput_ReturnsUnavailableNotZero(t *testing.T) {
	got := ComputeEmailGWTimeBasedMetrics(nil, emailgwrun.EnvironmentLab, 5, time.Now())
	if got.RunsConsidered != 0 {
		t.Fatalf("runsConsidered = %d, want 0", got.RunsConsidered)
	}
	if got.Detection.Latency == nil || !got.Detection.Latency.Unavailable {
		t.Fatalf("detection latency = %+v, want Unavailable=true", got.Detection.Latency)
	}
	if got.Detection.Latency.MeanSeconds != nil {
		t.Errorf("detection latency MeanSeconds = %v, want nil (never a fabricated zero)", *got.Detection.Latency.MeanSeconds)
	}
	if got.Response.Latency == nil || !got.Response.Latency.Unavailable {
		t.Fatalf("response latency = %+v, want Unavailable=true", got.Response.Latency)
	}
	if got.Prevention.Latency != nil {
		t.Errorf("prevention latency = %+v, want nil (no time-based concept defined for prevention)", got.Prevention.Latency)
	}
}

func TestComputeEmailGWTimeBasedMetrics_FiltersByEnvironment_NeverMixesLabAndCustomer(t *testing.T) {
	now := time.Now().UTC()
	observedAt := now.Add(-time.Hour)
	labResult := emailgwefficacy.EfficacyResult{
		Observation:      emailgwefficacy.OriginDeliveryObservation{Timestamp: observedAt},
		DetectionVerdict: emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictConfirmedSuccess},
		Detection:        []emailgwefficacy.DetectionEvidence{{AlertGenerated: true, Timestamp: observedAt.Add(2 * time.Minute)}},
	}
	customerResult := emailgwefficacy.EfficacyResult{
		Observation:      emailgwefficacy.OriginDeliveryObservation{Timestamp: observedAt},
		DetectionVerdict: emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictConfirmedSuccess},
		Detection:        []emailgwefficacy.DetectionEvidence{{AlertGenerated: true, Timestamp: observedAt.Add(99 * time.Minute)}},
	}
	runs := []*emailgwrun.EmailGWRun{
		{ID: "lab-1", Environment: emailgwrun.EnvironmentLab, Status: emailgwrun.StatusCompleted, Result: marshalResult(t, labResult), StartedAt: now},
		{ID: "customer-1", Environment: emailgwrun.EnvironmentCustomer, Status: emailgwrun.StatusCompleted, Result: marshalResult(t, customerResult), StartedAt: now},
	}

	lab := ComputeEmailGWTimeBasedMetrics(runs, emailgwrun.EnvironmentLab, 1, now)
	if lab.RunsConsidered != 1 {
		t.Fatalf("lab runsConsidered = %d, want 1", lab.RunsConsidered)
	}
	if lab.Detection.Latency.SampleCount != 1 || *lab.Detection.Latency.MeanSeconds != 120 {
		t.Fatalf("lab detection latency = %+v, want 1 sample at 120s", lab.Detection.Latency)
	}

	customer := ComputeEmailGWTimeBasedMetrics(runs, emailgwrun.EnvironmentCustomer, 1, now)
	if customer.RunsConsidered != 1 {
		t.Fatalf("customer runsConsidered = %d, want 1", customer.RunsConsidered)
	}
	if customer.Detection.Latency.SampleCount != 1 || *customer.Detection.Latency.MeanSeconds != 99*60 {
		t.Fatalf("customer detection latency = %+v, want 1 sample at %ds", customer.Detection.Latency, 99*60)
	}
}

func TestComputeEmailGWTimeBasedMetrics_RunEnvironmentEmpty_TreatedAsLab(t *testing.T) {
	now := time.Now().UTC()
	runs := []*emailgwrun.EmailGWRun{
		{ID: "unset-env", Environment: "", Status: emailgwrun.StatusFailed, StartedAt: now},
	}
	lab := ComputeEmailGWTimeBasedMetrics(runs, emailgwrun.EnvironmentLab, 1, now)
	if lab.RunsConsidered != 1 || lab.Detection.Outcomes.Failed != 1 {
		t.Fatalf("lab = %+v, want the unset-environment run counted as lab", lab)
	}
	customer := ComputeEmailGWTimeBasedMetrics(runs, emailgwrun.EnvironmentCustomer, 1, now)
	if customer.RunsConsidered != 0 {
		t.Fatalf("customer runsConsidered = %d, want 0 -- unset environment must never leak into customer", customer.RunsConsidered)
	}
}

func TestComputeEmailGWTimeBasedMetrics_PendingVsTimeout_SplitByWindowEnd(t *testing.T) {
	now := time.Now().UTC()
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)
	runs := []*emailgwrun.EmailGWRun{
		{ID: "still-waiting", Environment: emailgwrun.EnvironmentLab, Status: emailgwrun.StatusRunning, WindowEnd: &future, StartedAt: now},
		{ID: "overdue", Environment: emailgwrun.EnvironmentLab, Status: emailgwrun.StatusRunning, WindowEnd: &past, StartedAt: now},
		{ID: "no-window-yet", Environment: emailgwrun.EnvironmentLab, Status: emailgwrun.StatusPending, StartedAt: now},
	}
	got := ComputeEmailGWTimeBasedMetrics(runs, emailgwrun.EnvironmentLab, 1, now)
	if got.Detection.Outcomes.Pending != 2 {
		t.Errorf("pending = %d, want 2 (still-waiting + no-window-yet)", got.Detection.Outcomes.Pending)
	}
	if got.Detection.Outcomes.Timeout != 1 {
		t.Errorf("timeout = %d, want 1 (overdue)", got.Detection.Outcomes.Timeout)
	}
}

func TestComputeEmailGWTimeBasedMetrics_UndecodableResult_CountsAsMissingEvidence(t *testing.T) {
	now := time.Now().UTC()
	runs := []*emailgwrun.EmailGWRun{
		{ID: "no-result", Environment: emailgwrun.EnvironmentLab, Status: emailgwrun.StatusCompleted, Result: nil, StartedAt: now},
		{ID: "garbage-result", Environment: emailgwrun.EnvironmentLab, Status: emailgwrun.StatusCompleted, Result: json.RawMessage(`not json`), StartedAt: now},
	}
	got := ComputeEmailGWTimeBasedMetrics(runs, emailgwrun.EnvironmentLab, 1, now)
	if got.Detection.Outcomes.MissingEvidence != 2 {
		t.Fatalf("missingEvidence = %d, want 2", got.Detection.Outcomes.MissingEvidence)
	}
}

func TestComputeEmailGWTimeBasedMetrics_ConfirmedSuccessWithoutQualifyingEvidence_ExcludedFromLatencyButStillCounted(t *testing.T) {
	now := time.Now().UTC()
	// Verdict says confirmed-success but no AlertGenerated=true record
	// backs it -- an internal inconsistency this must never paper
	// over with a fabricated latency sample.
	inconsistent := emailgwefficacy.EfficacyResult{
		DetectionVerdict: emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictConfirmedSuccess},
	}
	runs := []*emailgwrun.EmailGWRun{
		{ID: "inconsistent", Environment: emailgwrun.EnvironmentLab, Status: emailgwrun.StatusCompleted, Result: marshalResult(t, inconsistent), StartedAt: now},
	}
	got := ComputeEmailGWTimeBasedMetrics(runs, emailgwrun.EnvironmentLab, 1, now)
	if got.Detection.Outcomes.ConfirmedSuccess != 1 {
		t.Errorf("confirmedSuccess = %d, want 1 (the verdict itself is still counted)", got.Detection.Outcomes.ConfirmedSuccess)
	}
	if !got.Detection.Latency.Unavailable || got.Detection.Latency.SampleCount != 0 {
		t.Errorf("latency = %+v, want unavailable with zero samples", got.Detection.Latency)
	}
}

func TestComputeEmailGWTimeBasedMetrics_NegativeDetectionDuration_Excluded(t *testing.T) {
	now := time.Now().UTC()
	observedAt := now
	// Alert timestamp before the observation -- clock skew or bad
	// data, either way never reported as a negative MTTD.
	backwards := emailgwefficacy.EfficacyResult{
		Observation:      emailgwefficacy.OriginDeliveryObservation{Timestamp: observedAt},
		DetectionVerdict: emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictConfirmedSuccess},
		Detection:        []emailgwefficacy.DetectionEvidence{{AlertGenerated: true, Timestamp: observedAt.Add(-time.Minute)}},
	}
	runs := []*emailgwrun.EmailGWRun{
		{ID: "backwards", Environment: emailgwrun.EnvironmentLab, Status: emailgwrun.StatusCompleted, Result: marshalResult(t, backwards), StartedAt: now},
	}
	got := ComputeEmailGWTimeBasedMetrics(runs, emailgwrun.EnvironmentLab, 1, now)
	if !got.Detection.Latency.Unavailable {
		t.Errorf("latency = %+v, want unavailable (negative duration must never be reported)", got.Detection.Latency)
	}
}

func TestComputeEmailGWTimeBasedMetrics_MTTR_ReusesResponseEvidenceDurationDirectly(t *testing.T) {
	now := time.Now().UTC()
	vendorComputedDuration := 7 * time.Minute
	result := emailgwefficacy.EfficacyResult{
		ResponseVerdict: emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictConfirmedSuccess},
		Response:        []emailgwefficacy.ResponseEvidence{{Completed: true, DurationToComplete: vendorComputedDuration, Timestamp: now}},
	}
	runs := []*emailgwrun.EmailGWRun{
		{ID: "responded", Environment: emailgwrun.EnvironmentLab, Status: emailgwrun.StatusCompleted, Result: marshalResult(t, result), StartedAt: now},
	}
	got := ComputeEmailGWTimeBasedMetrics(runs, emailgwrun.EnvironmentLab, 1, now)
	if got.Response.Latency.SampleCount != 1 || *got.Response.Latency.MeanSeconds != vendorComputedDuration.Seconds() {
		t.Fatalf("response latency = %+v, want 1 sample at %v", got.Response.Latency, vendorComputedDuration)
	}
}

func TestComputeEmailGWTimeBasedMetrics_EarliestDetectionWins_NotLatest(t *testing.T) {
	now := time.Now().UTC()
	observedAt := now.Add(-time.Hour)
	result := emailgwefficacy.EfficacyResult{
		Observation:      emailgwefficacy.OriginDeliveryObservation{Timestamp: observedAt},
		DetectionVerdict: emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictConfirmedSuccess},
		Detection: []emailgwefficacy.DetectionEvidence{
			{AlertGenerated: true, Timestamp: observedAt.Add(10 * time.Minute)},
			{AlertGenerated: true, Timestamp: observedAt.Add(3 * time.Minute)}, // earlier -- this one should win
			{AlertGenerated: false, Timestamp: observedAt.Add(1 * time.Minute)},
		},
	}
	runs := []*emailgwrun.EmailGWRun{
		{ID: "multi-alert", Environment: emailgwrun.EnvironmentLab, Status: emailgwrun.StatusCompleted, Result: marshalResult(t, result), StartedAt: now},
	}
	got := ComputeEmailGWTimeBasedMetrics(runs, emailgwrun.EnvironmentLab, 1, now)
	want := (3 * time.Minute).Seconds()
	if *got.Detection.Latency.MeanSeconds != want {
		t.Fatalf("MTTD = %v, want %v (earliest AlertGenerated=true record)", *got.Detection.Latency.MeanSeconds, want)
	}
}

func TestComputeEmailGWTimeBasedMetrics_BelowMinimumSampleSize_FlaggedInsufficientButNotHidden(t *testing.T) {
	now := time.Now().UTC()
	observedAt := now.Add(-time.Hour)
	result := emailgwefficacy.EfficacyResult{
		Observation:      emailgwefficacy.OriginDeliveryObservation{Timestamp: observedAt},
		DetectionVerdict: emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictConfirmedSuccess},
		Detection:        []emailgwefficacy.DetectionEvidence{{AlertGenerated: true, Timestamp: observedAt.Add(time.Minute)}},
	}
	runs := []*emailgwrun.EmailGWRun{
		{ID: "only-one", Environment: emailgwrun.EnvironmentLab, Status: emailgwrun.StatusCompleted, Result: marshalResult(t, result), StartedAt: now},
	}
	got := ComputeEmailGWTimeBasedMetrics(runs, emailgwrun.EnvironmentLab, 5, now)
	if got.Detection.Latency.Unavailable {
		t.Fatalf("latency = %+v, want Unavailable=false -- there IS a real sample", got.Detection.Latency)
	}
	if got.Detection.Latency.Sufficient {
		t.Errorf("sufficient = true, want false (1 sample < minimum 5)")
	}
	if got.Detection.Latency.SampleCount != 1 {
		t.Errorf("sampleCount = %d, want 1", got.Detection.Latency.SampleCount)
	}
	if got.Detection.Latency.MeanSeconds == nil {
		t.Errorf("meanSeconds = nil, want the real value visible alongside the insufficient flag")
	}
}

func TestComputeEmailGWTimeBasedMetrics_MultipleSamples_MeanMedianMinMax(t *testing.T) {
	now := time.Now().UTC()
	durations := []time.Duration{1 * time.Minute, 3 * time.Minute, 5 * time.Minute}
	var runs []*emailgwrun.EmailGWRun
	for i, d := range durations {
		observedAt := now.Add(-time.Hour)
		result := emailgwefficacy.EfficacyResult{
			Observation:      emailgwefficacy.OriginDeliveryObservation{Timestamp: observedAt},
			DetectionVerdict: emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictConfirmedSuccess},
			Detection:        []emailgwefficacy.DetectionEvidence{{AlertGenerated: true, Timestamp: observedAt.Add(d)}},
		}
		runs = append(runs, &emailgwrun.EmailGWRun{
			ID: "run" + string(rune('a'+i)), Environment: emailgwrun.EnvironmentLab,
			Status: emailgwrun.StatusCompleted, Result: marshalResult(t, result), StartedAt: now,
		})
	}
	got := ComputeEmailGWTimeBasedMetrics(runs, emailgwrun.EnvironmentLab, 1, now)
	l := got.Detection.Latency
	if l.SampleCount != 3 {
		t.Fatalf("sampleCount = %d, want 3", l.SampleCount)
	}
	if *l.MinSeconds != 60 || *l.MaxSeconds != 300 || *l.MedianSeconds != 180 || *l.MeanSeconds != 180 {
		t.Errorf("min/max/median/mean = %v/%v/%v/%v, want 60/300/180/180", *l.MinSeconds, *l.MaxSeconds, *l.MedianSeconds, *l.MeanSeconds)
	}
}

func TestComputeEmailGWTimeBasedMetrics_AllVerdictKindsCountedCorrectly(t *testing.T) {
	now := time.Now().UTC()
	verdicts := []emailgwefficacy.EmailGWVerdict{
		emailgwefficacy.VerdictConfirmedFailure,
		emailgwefficacy.VerdictInconclusive,
		emailgwefficacy.VerdictNotTested,
		emailgwefficacy.VerdictNotApplicable,
	}
	var runs []*emailgwrun.EmailGWRun
	for i, v := range verdicts {
		result := emailgwefficacy.EfficacyResult{DetectionVerdict: emailgwefficacy.VerdictDetail{Verdict: v}}
		runs = append(runs, &emailgwrun.EmailGWRun{
			ID: "v" + string(rune('a'+i)), Environment: emailgwrun.EnvironmentLab,
			Status: emailgwrun.StatusPartial, Result: marshalResult(t, result), StartedAt: now,
		})
	}
	got := ComputeEmailGWTimeBasedMetrics(runs, emailgwrun.EnvironmentLab, 1, now)
	o := got.Detection.Outcomes
	if o.ConfirmedFailure != 1 || o.Inconclusive != 1 || o.NotTested != 1 || o.NotApplicable != 1 {
		t.Errorf("outcomes = %+v, want exactly one of each non-success verdict", o)
	}
}
