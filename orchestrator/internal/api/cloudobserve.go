package api

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/observability"
)

// cloudTracer names the spans for cloud work. With no tracer provider installed,
// as in the current server configuration, these spans are no-ops.
var cloudTracer = otel.Tracer("bas/cloud")

// metricsOrNil returns the settings' metrics, or nil when settings are absent.
func (s *CloudSettings) metricsOrNil() *observability.CloudMetrics {
	if s == nil {
		return nil
	}
	return s.metrics
}

// observedDiscoverer wraps a discoverer with telemetry. It records the pass
// duration, the objects found by kind, the failure category and preflight failures
// as metrics. It also writes a span and a structured log line. Metrics carry only
// bounded labels. The account ID is kept to the span and the log, where identifiers
// belong, and never reaches a metric label.
type observedDiscoverer struct {
	inner    cloudgraph.Discoverer
	provider string
	account  string
	metrics  *observability.CloudMetrics
}

func observeDiscoverer(inner cloudgraph.Discoverer, account cloudgraph.AccountScope, metrics *observability.CloudMetrics) cloudgraph.Discoverer {
	return observedDiscoverer{inner: inner, provider: account.Provider, account: account.AccountID, metrics: metrics}
}

func (d observedDiscoverer) Discover(ctx context.Context) (*cloudgraph.DiscoveredGraph, cloudgraph.DiscoveryReport, error) {
	ctx, span := cloudTracer.Start(ctx, "cloud.discovery.pass", oteltrace.WithAttributes(
		attribute.String("cloud.provider", d.provider),
		attribute.String("cloud.account_id", d.account),
	))
	defer span.End()

	start := time.Now()
	graph, report, err := d.inner.Discover(ctx)
	elapsed := time.Since(start)

	outcome := "ok"
	category := ""
	if err != nil {
		outcome = "failed"
		category = cloudFailureCategory(err)
		span.RecordError(err)
		span.SetAttributes(attribute.String("cloud.failure_category", category))
		if d.metrics != nil {
			d.metrics.DiscoveryFailures.WithLabelValues(d.provider, category).Inc()
		}
	} else if graph != nil && d.metrics != nil {
		d.metrics.DiscoveryObjects.WithLabelValues(d.provider, "identity").Add(float64(len(graph.Identities)))
		d.metrics.DiscoveryObjects.WithLabelValues(d.provider, "permission").Add(float64(len(graph.Permissions)))
		for _, r := range graph.Resources {
			d.metrics.DiscoveryObjects.WithLabelValues(d.provider, r.Kind).Inc()
		}
	}
	if d.metrics != nil {
		d.metrics.DiscoveryPassDuration.WithLabelValues(d.provider, outcome).Observe(elapsed.Seconds())
	}

	attrs := []any{
		"event", "cloud.discovery.pass",
		"provider", d.provider,
		"account_id", d.account,
		"outcome", outcome,
		"duration_ms", elapsed.Milliseconds(),
	}
	if err != nil {
		// The error has already been scrubbed of secrets by accountChecked.
		slog.Warn("cloud discovery pass failed", append(attrs, "category", category, "error", err.Error())...)
	} else {
		slog.Info("cloud discovery pass completed", attrs...)
	}
	return graph, report, err
}

// Preflight runs the wrapped source's checks and counts each failed check. Check
// names are reduced to the part before any ":", so a per-ancestor name does not
// add a new label value for each ancestor.
func (d observedDiscoverer) Preflight(ctx context.Context) []cloudgraph.PreflightCheck {
	ctx, span := cloudTracer.Start(ctx, "cloud.preflight", oteltrace.WithAttributes(
		attribute.String("cloud.provider", d.provider),
		attribute.String("cloud.account_id", d.account),
	))
	defer span.End()

	p, ok := d.inner.(cloudgraph.Preflighter)
	if !ok {
		return []cloudgraph.PreflightCheck{{Name: "discovery-source", Status: "FAIL", Detail: "this discovery source cannot be preflighted"}}
	}
	checks := p.Preflight(ctx)
	var failed []string
	for _, c := range checks {
		if c.Status != "FAIL" {
			continue
		}
		name, _, _ := strings.Cut(c.Name, ":")
		failed = append(failed, name)
		if d.metrics != nil {
			d.metrics.PreflightFailures.WithLabelValues(d.provider, name).Inc()
		}
	}
	span.SetAttributes(attribute.Int("cloud.preflight_failed", len(failed)))
	slog.Info("cloud preflight completed",
		"event", "cloud.preflight",
		"provider", d.provider,
		"account_id", d.account,
		"failed_checks", strings.Join(failed, ","),
	)
	return checks
}

// cloudFailureCategory reduces an error to one of a fixed set of categories, so the
// failure metric has bounded labels. The named permission stays in the log.
func cloudFailureCategory(err error) string {
	msg := err.Error()
	lower := strings.ToLower(msg)
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, errCloudDiscoveryNotConfigured):
		return "not-configured"
	case strings.Contains(msg, "resolve to account"):
		return "account-mismatch"
	case strings.Contains(msg, "(needs ") || strings.Contains(msg, "needs ") || strings.Contains(msg, "HTTP 403") || strings.Contains(lower, "access denied") || strings.Contains(lower, "accessdenied") || strings.Contains(lower, "unauthorized") || strings.Contains(lower, "forbidden"):
		return "permission"
	case strings.Contains(msg, "429") || strings.Contains(lower, "throttl") || strings.Contains(lower, "rate limit"):
		return "throttled"
	default:
		return "other"
	}
}
