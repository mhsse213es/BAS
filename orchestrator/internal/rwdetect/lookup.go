package rwdetect

import (
	"context"
	"fmt"
	"time"

	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/rwevidence"
)

// AttemptContext is the per-attempt identity and timing a detection query
// needs. HostName/HostIP come from the agent's registration record (a stable
// host reference). ExecutedAt is the step's actual execution timestamp and is
// the ONLY source of event time: the agent's registration time is never used
// as an event time. A zero ExecutedAt means the timestamp is unknown.
type AttemptContext struct {
	HostName   string
	HostIP     string
	ExecutedAt time.Time
}

// ContextSource resolves an attempt's host and execution timing. Production
// implementations are not part of this package; callers supply one.
type ContextSource interface {
	AttemptContextFor(ctx context.Context, key rwevidence.AttemptKey) (AttemptContext, error)
}

// WindowPolicy is the fixed query interval around an execution timestamp.
// Before covers clock skew between the agent and the telemetry source; After
// covers delayed telemetry ingestion. The policy in effect is recorded in each
// result's reason so runs stay comparable.
type WindowPolicy struct {
	Before time.Duration
	After  time.Duration
}

// DefaultWindowPolicy: 5 minutes before the execution timestamp (skew) and 30
// minutes after it (delayed ingestion).
var DefaultWindowPolicy = WindowPolicy{Before: 5 * time.Minute, After: 30 * time.Minute}

// maxFutureSkew is how far an execution timestamp may lead the orchestrator's
// clock before it is treated as unreliable rather than as a real event time.
const maxFutureSkew = 5 * time.Minute

// ConnectorLookup implements rwevidence.DetectionLookup over a
// detectverify.Connector. Every path that cannot establish a trustworthy host
// and event time returns tested=false (inconclusive) without querying the
// connector. Only a real connector error is returned as err.
type ConnectorLookup struct {
	Connector detectverify.Connector
	Context   ContextSource
	Window    WindowPolicy
	Now       func() time.Time
}

// NewConnectorLookup uses DefaultWindowPolicy and the system clock.
func NewConnectorLookup(conn detectverify.Connector, src ContextSource) *ConnectorLookup {
	return &ConnectorLookup{Connector: conn, Context: src, Window: DefaultWindowPolicy, Now: time.Now}
}

// LookupDetection implements rwevidence.DetectionLookup.
func (l *ConnectorLookup) LookupDetection(ctx context.Context, key rwevidence.AttemptKey) (tested bool, verified bool, reason string, err error) {
	ac, err := l.Context.AttemptContextFor(ctx, key)
	if err != nil {
		return false, false, "", err
	}
	if ac.HostName == "" && ac.HostIP == "" {
		return false, false, "host identity missing from the agent registration record; evidence inconclusive", nil
	}
	if ac.ExecutedAt.IsZero() {
		return false, false, "step execution timestamp missing; evidence inconclusive, no window inferred", nil
	}
	exec := ac.ExecutedAt.UTC()
	if exec.After(l.Now().UTC().Add(maxFutureSkew)) {
		return false, false, fmt.Sprintf("step execution timestamp %s is ahead of the orchestrator clock beyond tolerance; evidence inconclusive", exec.Format(time.RFC3339)), nil
	}

	expectationID := key.RunID + "/" + key.Action
	windowStart := exec.Add(-l.Window.Before)
	windowEnd := exec.Add(l.Window.After)
	req, ok := VerifyRequestFor(rwevidence.Technique{MitreID: key.TechniqueID}, key.RunID, expectationID, ac.HostName, ac.HostIP, exec, windowStart, windowEnd)
	if !ok {
		return false, false, "technique has no MITRE mapping; evidence inconclusive", nil
	}

	result, err := l.Connector.Verify(ctx, req)
	if err != nil {
		return false, false, "", err
	}
	tested, verified, base := DetectionLookupResultFor(result)
	reason = fmt.Sprintf("%s [host=%s ip=%s event_time=%s window=%s..%s UTC, policy=-%s/+%s, time source=step execution timestamp]",
		base, ac.HostName, ac.HostIP, exec.Format(time.RFC3339),
		windowStart.Format(time.RFC3339), windowEnd.Format(time.RFC3339),
		l.Window.Before, l.Window.After)
	return tested, verified, reason, nil
}
