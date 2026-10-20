// Package pipelinecheck is the read-only posture stage for the detection pipeline.
//
// It answers one question: can Audspect reach and authenticate to the SIEM and ticketing
// connectors it is configured with? It does not prove that any event was ingested,
// normalised, correlated, alerted, cased or routed. A reachable connector produces
// INCONCLUSIVE, never a pass, and the result lists every pipeline stage left unverified.
package pipelinecheck

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/audspect/bas/internal/killchain"
	"github.com/audspect/bas/internal/siem"
)

// Kind names the connector family a target belongs to.
type Kind string

const (
	KindSIEM      Kind = "siem"
	KindTicketing Kind = "ticketing"
)

// Target is one configured connector to probe.
type Target struct {
	Kind     Kind
	ID       string
	Provider string
}

// Status is the outcome of a connectivity probe.
type Status string

const (
	// StatusConnected means the connector answered its own connectivity test.
	StatusConnected Status = "connected"
	// StatusFailed means the connector was configured but the test failed.
	StatusFailed Status = "failed"
	// StatusNotSupported means this build has no connectivity test for the provider.
	// The check cannot run, so it is reported as untested, not as a pass.
	StatusNotSupported Status = "not_supported"
)

// ErrNotSupported is returned by a Prober when no connectivity test exists.
var ErrNotSupported = errors.New("connectivity test not available for this provider")

// Result is one probe outcome with the time it was taken.
type Result struct {
	Target    Target
	Status    Status
	Detail    string
	CheckedAt time.Time
}

// Prober runs a connectivity test for one target. Return nil when the connector answers,
// an error wrapping ErrNotSupported when no test exists, and any other error when the
// test fails.
type Prober interface {
	Probe(ctx context.Context, t Target) error
}

// Run probes every target. It never stops early, so every failure is reported.
func Run(ctx context.Context, p Prober, targets []Target, now func() time.Time) []Result {
	out := make([]Result, 0, len(targets))
	for _, t := range targets {
		err := p.Probe(ctx, t)
		r := Result{Target: t, CheckedAt: now()}
		switch {
		case err == nil:
			r.Status = StatusConnected
			r.Detail = "connectivity test passed"
		case errors.Is(err, ErrNotSupported):
			r.Status = StatusNotSupported
			r.Detail = err.Error()
		default:
			r.Status = StatusFailed
			r.Detail = err.Error()
		}
		out = append(out, r)
	}
	return out
}

// notVerified lists what a connectivity test cannot show. It is returned with every
// connected outcome so the report never reads as end-to-end validation.
var notVerified = []string{
	"event ingestion",
	"normalization",
	"correlation",
	"alert creation",
	"case creation",
	"routing",
	"analyst acknowledgement (human-dependent; NOT_TESTED until verified or recorded)",
	"escalation (human-dependent; NOT_TESTED until verified or recorded)",
	"permissions (the connector interface exposes no permission check)",
}

// Outcome turns probe results into the stage verdict and its reasons.
//
//   - No targets: ERROR. Nothing was tested, so nothing may pass.
//   - Any target failed or not supported: ERROR, with each one named.
//   - All targets connected: INCONCLUSIVE. Connectivity was shown, and the reasons say
//     which pipeline stages remain unverified.
func Outcome(results []Result) (killchain.Verdict, []string) {
	if len(results) == 0 {
		return killchain.VerdictError, []string{"no SIEM or ticketing connectors configured; pipeline not tested"}
	}
	var problems []string
	for _, r := range results {
		switch r.Status {
		case StatusFailed:
			problems = append(problems, fmt.Sprintf("%s %s (%s): connectivity failed: %s", r.Target.Kind, r.Target.ID, r.Target.Provider, r.Detail))
		case StatusNotSupported:
			problems = append(problems, fmt.Sprintf("%s %s (%s): no connectivity test in this build, so not tested", r.Target.Kind, r.Target.ID, r.Target.Provider))
		}
	}
	if len(problems) > 0 {
		return killchain.VerdictError, problems
	}
	reasons := []string{"connectivity and configuration reachable; this is not proof of event ingestion"}
	for _, v := range notVerified {
		reasons = append(reasons, "not verified: "+v)
	}
	return killchain.VerdictInconclusive, reasons
}

// SIEMLoader loads a stored SIEM configuration by ID.
type SIEMLoader func(ctx context.Context, id string) (siem.Config, error)

// TicketingTester runs the ticketing connector's own connectivity test.
type TicketingTester interface {
	TestConnector(ctx context.Context, id string) error
}

// ConnectorProber probes SIEM and ticketing targets through the existing connectivity
// functions, so no second client is written.
type ConnectorProber struct {
	LoadSIEM  SIEMLoader
	Ticketing TicketingTester
}

// Probe runs the connectivity test for one target.
func (c ConnectorProber) Probe(ctx context.Context, t Target) error {
	switch t.Kind {
	case KindSIEM:
		if c.LoadSIEM == nil {
			return errors.New("SIEM configuration loader not wired")
		}
		cfg, err := c.LoadSIEM(ctx, t.ID)
		if err != nil {
			return fmt.Errorf("load configuration: %w", err)
		}
		err = siem.TestConnectivity(ctx, cfg)
		if errors.Is(err, siem.ErrProviderNotSupported) {
			return fmt.Errorf("%w: %v", ErrNotSupported, err)
		}
		return err
	case KindTicketing:
		if c.Ticketing == nil {
			return errors.New("ticketing connector not wired")
		}
		return c.Ticketing.TestConnector(ctx, t.ID)
	default:
		return fmt.Errorf("unknown connector kind %q", t.Kind)
	}
}
