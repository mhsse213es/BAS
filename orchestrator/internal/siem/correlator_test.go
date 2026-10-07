package siem

import (
	"context"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
)

func TestCorrelate_EmptyAgentIP_ReturnsError(t *testing.T) {
	_, err := Correlate(context.Background(), Config{}, "run-1", "agent-1", "", time.Now(), time.Now(), nil)
	if err == nil {
		t.Fatal("expected an error when agentIP is empty, got nil")
	}
}

func TestCorrelate_UnsupportedProvider_ReturnsWrappedQueryError(t *testing.T) {
	_, err := Correlate(context.Background(), Config{Provider: "splunk"}, "run-1", "agent-1", "10.0.0.5",
		time.Now(), time.Now(), nil)
	if err == nil {
		t.Fatal("expected an error for an unsupported provider")
	}
	if got := err.Error(); got == "" {
		t.Fatal("expected a non-empty error message")
	}
}

func TestTestConnectivity_UnsupportedProvider_ReturnsError(t *testing.T) {
	err := TestConnectivity(context.Background(), Config{Provider: "wazuh"})
	if err == nil {
		t.Fatal("expected an error for an unsupported provider")
	}
}

// qradarStub lets the test control exactly which alerts queryAlerts returns,
// without any real QRadar server. Correlate's own dispatch logic
// (queryAlerts -> newQRadarClient -> QueryAlerts) always exercises the real
// HTTP client, so these tests build the CorrelationReport directly from a
// fixed alert slice via the same windowing/classification code Correlate
// itself runs, by calling the package-private helper through a QRadar
// provider pointed at a local server. See correlator_http_test.go for the
// httptest-backed path; the tests below stay provider-agnostic by
// constructing results and asserting on the public classification contract.
func resultAt(techID, techName string, result models.CheckResult, executedAt time.Time, durationMs int64) models.SimulationResult {
	return models.SimulationResult{
		Technique:  models.AttackTechnique{ID: techID, Name: techName},
		Result:     result,
		ExecutedAt: executedAt,
		DurationMs: durationMs,
	}
}

func TestCorrelate_ClassifiesEachResultKind(t *testing.T) {
	// A fake QRadar server whose /ariel/searches flow returns one alert
	// timestamped to land inside T1059's window and nowhere near the
	// others, so the classification differences come only from
	// models.Result, not from alert timing.
	runStart := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	runEnd := runStart.Add(10 * time.Minute)
	t1059ExecutedAt := runStart.Add(2 * time.Minute)
	alertTime := t1059ExecutedAt.Add(10 * time.Second) // inside [-30s, +60s] of T1059

	srv := newFakeQRadarServer(t, []fakeQRadarEvent{
		{sourceIP: "10.0.0.5", startTimeMs: alertTime.UnixMilli(), ruleName: "Suspicious PowerShell"},
	})
	defer srv.Close()

	results := []models.SimulationResult{
		resultAt("T1059.001", "PowerShell", models.ResultFail, t1059ExecutedAt, 5000),       // detected
		resultAt("T1055", "Process Injection", models.ResultFail, runStart.Add(5*time.Minute), 5000), // undetected (alert out of window)
		resultAt("T1562", "Disable Defenses", models.ResultBlocked, runStart.Add(1*time.Minute), 1000),
		resultAt("T1105", "Ingress Tool Transfer", models.ResultPass, runStart.Add(3*time.Minute), 1000),
		resultAt("T1098", "Account Manipulation", models.ResultSkipped, time.Time{}, 0),
		resultAt("T1486", "Data Encrypted for Impact", models.ResultVetoed, time.Time{}, 0),
		resultAt("T1003", "Credential Dumping", models.ResultError, time.Time{}, 0),
	}

	report, err := Correlate(context.Background(), Config{Provider: ProviderQRadar, ConsoleURL: srv.URL},
		"run-1", "agent-1", "10.0.0.5", runStart, runEnd, results)
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}

	byTech := map[string]TechniqueCorrelation{}
	for _, tc := range report.Techniques {
		byTech[tc.TechniqueID] = tc
	}

	cases := []struct {
		techID      string
		wantVerdict string
	}{
		{"T1059.001", "detected"},
		{"T1055", "undetected"},
		{"T1562", "not_applicable"},
		{"T1105", "not_applicable"},
		{"T1098", "not_executed"},
		{"T1486", "not_executed"},
		{"T1003", "not_executed"},
	}
	for _, tc := range cases {
		got, ok := byTech[tc.techID]
		if !ok {
			t.Fatalf("no TechniqueCorrelation for %s", tc.techID)
		}
		if got.SIEMVerdict != tc.wantVerdict {
			t.Errorf("%s: SIEMVerdict = %q, want %q", tc.techID, got.SIEMVerdict, tc.wantVerdict)
		}
	}

	if report.Detected != 1 {
		t.Errorf("report.Detected = %d, want 1", report.Detected)
	}
	if report.Undetected != 1 {
		t.Errorf("report.Undetected = %d, want 1", report.Undetected)
	}
	if report.NotExecuted != 3 {
		t.Errorf("report.NotExecuted = %d, want 3", report.NotExecuted)
	}
	// DetectionRate/UndetectedRate are computed only over executed
	// (detected+undetected) techniques, not over not_applicable/not_executed.
	if report.DetectionRate != 50 {
		t.Errorf("report.DetectionRate = %d, want 50 (1 of 2 executed techniques detected)", report.DetectionRate)
	}
	if report.UndetectedRate != 50 {
		t.Errorf("report.UndetectedRate = %d, want 50", report.UndetectedRate)
	}

	detected := byTech["T1059.001"]
	if detected.AlertCount != 1 || len(detected.Alerts) != 1 {
		t.Fatalf("detected technique = %+v, want AlertCount=1 and one Alert attached", detected)
	}
	if detected.Alerts[0].RuleName != "Suspicious PowerShell" {
		t.Errorf("attached alert RuleName = %q, want %q", detected.Alerts[0].RuleName, "Suspicious PowerShell")
	}
}

func TestCorrelate_NoExecutedTechniques_RatesStayZero(t *testing.T) {
	srv := newFakeQRadarServer(t, nil)
	defer srv.Close()

	results := []models.SimulationResult{
		resultAt("T1098", "Account Manipulation", models.ResultSkipped, time.Time{}, 0),
	}
	report, err := Correlate(context.Background(), Config{Provider: ProviderQRadar, ConsoleURL: srv.URL},
		"run-1", "agent-1", "10.0.0.5", time.Now(), time.Now().Add(time.Minute), results)
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	if report.DetectionRate != 0 || report.UndetectedRate != 0 {
		t.Errorf("rates = %d/%d, want 0/0 when no technique executed (avoids a divide-by-zero)",
			report.DetectionRate, report.UndetectedRate)
	}
}

func TestCorrelate_CapsAttachedAlertsAtFive(t *testing.T) {
	runStart := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	executedAt := runStart.Add(time.Minute)

	var events []fakeQRadarEvent
	for i := 0; i < 8; i++ {
		events = append(events, fakeQRadarEvent{
			sourceIP:    "10.0.0.5",
			startTimeMs: executedAt.Add(10 * time.Second).UnixMilli(),
			ruleName:    "dup",
		})
	}
	srv := newFakeQRadarServer(t, events)
	defer srv.Close()

	results := []models.SimulationResult{
		resultAt("T1059.001", "PowerShell", models.ResultFail, executedAt, 1000),
	}
	report, err := Correlate(context.Background(), Config{Provider: ProviderQRadar, ConsoleURL: srv.URL},
		"run-1", "agent-1", "10.0.0.5", runStart, runStart.Add(10*time.Minute), results)
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	tc := report.Techniques[0]
	if tc.AlertCount != maxAlertsPerTech {
		t.Errorf("AlertCount = %d, want capped at maxAlertsPerTech=%d even though 8 alerts matched",
			tc.AlertCount, maxAlertsPerTech)
	}
	if len(tc.Alerts) != maxAlertsPerTech {
		t.Errorf("len(Alerts) = %d, want %d", len(tc.Alerts), maxAlertsPerTech)
	}
}
