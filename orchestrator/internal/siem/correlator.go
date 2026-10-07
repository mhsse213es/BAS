package siem

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/audspect/bas/internal/models"
)

// correlationWindow is how much time before and after the run we include in
// the SIEM query. Pre-window catches any alerts that fired before the first
// step; post-window catches slow SIEM ingestion pipelines.
const preWindow = 2 * time.Minute
const postWindow = 5 * time.Minute

// maxAlertsPerQuery caps SIEM result size so a noisy environment doesn't blow
// memory. If there are >500 alerts, counts are still accurate but only the
// first 500 raw records are returned.
const maxAlertsPerQuery = 500

// maxAlertsPerTech caps how many alert records we store per technique in the
// correlation report (keeps the JSON compact for the report renderer).
const maxAlertsPerTech = 5

// Correlate queries the configured SIEM for alerts fired from agentIP during
// the run's time window and maps them to the run's executed techniques.
//
// The correlation model:
//   - A technique is "detected" by the SIEM if ≥1 alert fired from the agent's
//     IP in the window [step.ExecutedAt − 30s, step.ExecutedAt + stepDuration + 60s].
//   - Only FAILED (allowed-through) techniques are candidates: a PASS/blocked
//     technique was stopped before producing alertable behaviour.
//   - Techniques that ERRORED or were SKIPPED are classified as "not_executed".
func Correlate(
	ctx context.Context,
	cfg Config,
	runID, agentID, agentIP string,
	runStart, runEnd time.Time,
	results []models.SimulationResult,
) (*CorrelationReport, error) {
	if agentIP == "" {
		return nil, fmt.Errorf("siem correlate: agent IP is empty — cannot query SIEM without a source IP")
	}
	// The IP is interpolated into the SIEM query, so it must be an address.
	if net.ParseIP(agentIP) == nil {
		return nil, fmt.Errorf("siem correlate: agent IP %q is not a valid IP address", agentIP)
	}

	qStart := runStart.Add(-preWindow)
	qEnd := runEnd.Add(postWindow)

	alerts, err := queryAlerts(ctx, cfg, agentIP, qStart, qEnd, maxAlertsPerQuery)
	if err != nil {
		return nil, fmt.Errorf("siem correlate query: %w", err)
	}

	report := &CorrelationReport{
		RunID:        runID,
		AgentID:      agentID,
		AgentIP:      agentIP,
		Provider:     cfg.Provider,
		ConfigID:     cfg.ID,
		WindowStart:  qStart,
		WindowEnd:    qEnd,
		TotalAlerts:  len(alerts),
		CorrelatedAt: time.Now().UTC(),
	}

	for _, res := range results {
		tc := TechniqueCorrelation{
			TechniqueID:   res.Technique.ID,
			TechniqueName: res.Technique.Name,
			BASVerdict:    string(res.Result),
		}

		switch res.Result {
		case models.ResultSkipped, models.ResultError, models.ResultVetoed:
			// ResultVetoed: Audspect's own agent refused to attempt this
			// step under B5's destructive-action policy -- it genuinely
			// never executed, so "not_executed" is the honest bucket here
			// (verified, B5 Task 9 audit), distinct from the "not_applicable"
			// case below (which DID execute and was stopped at the endpoint).
			tc.SIEMVerdict = "not_executed"
			report.NotExecuted++
		case models.ResultPass, models.ResultBlocked:
			// Technique was stopped at the endpoint before any alertable network
			// or process activity — SIEM detection is unlikely and not meaningful.
			tc.SIEMVerdict = "not_applicable"
		case models.ResultFail:
			// Technique ran to completion — check if SIEM saw it.
			stepStart := res.ExecutedAt.Add(-30 * time.Second)
			stepEnd := res.ExecutedAt.Add(time.Duration(res.DurationMs)*time.Millisecond + 60*time.Second)
			var matched []SIEMAlert
			for _, a := range alerts {
				if !a.Timestamp.Before(stepStart) && !a.Timestamp.After(stepEnd) {
					matched = append(matched, a)
					if len(matched) >= maxAlertsPerTech {
						break
					}
				}
			}
			tc.AlertCount = len(matched)
			if len(matched) > 0 {
				tc.SIEMVerdict = "detected"
				tc.Alerts = matched
				report.Detected++
			} else {
				tc.SIEMVerdict = "undetected"
				report.Undetected++
			}
		}

		report.Techniques = append(report.Techniques, tc)
	}

	executed := report.Detected + report.Undetected
	if executed > 0 {
		report.DetectionRate = report.Detected * 100 / executed
		report.UndetectedRate = report.Undetected * 100 / executed
	}

	return report, nil
}

// queryAlerts dispatches to the appropriate SIEM client based on the config provider.
func queryAlerts(ctx context.Context, cfg Config, agentIP string, start, end time.Time, max int) ([]SIEMAlert, error) {
	switch cfg.Provider {
	case ProviderQRadar:
		client := newQRadarClient(cfg)
		return client.QueryAlerts(ctx, agentIP, start, end, max)
	default:
		return nil, fmt.Errorf("siem: provider %q not yet supported — only qradar is available", cfg.Provider)
	}
}

// TestConnectivity verifies that the SIEM config can reach the console.
func TestConnectivity(ctx context.Context, cfg Config) error {
	switch cfg.Provider {
	case ProviderQRadar:
		return newQRadarClient(cfg).Ping(ctx)
	default:
		return fmt.Errorf("siem: provider %q not yet supported", cfg.Provider)
	}
}
