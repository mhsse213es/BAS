package cloudgraph

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

// RetryPolicy governs how a cloud API call retries transient failures:
// HTTP 429 (throttled) and 5xx responses, and transport errors that are not
// caused by context cancellation. Zero value means one attempt, no retry.
type RetryPolicy struct {
	MaxAttempts int           // total attempts including the first
	BaseDelay   time.Duration // first backoff; doubles on each retry
	MaxDelay    time.Duration // cap on any single wait, including Retry-After
}

// DefaultRetryPolicy is used by the real discovery clients. Four attempts
// with a 500ms base keeps a throttled tenant from failing a run on the first
// 429, while bounding the worst case to roughly half a minute per call.
var DefaultRetryPolicy = RetryPolicy{
	MaxAttempts: 4,
	BaseDelay:   500 * time.Millisecond,
	MaxDelay:    20 * time.Second,
}

// DefaultRateLimiter returns the per-client request limiter the real clients
// install: 5 requests/second sustained, bursts of 10. Cloud control planes
// throttle per principal, so one discovery run must not flood them.
func DefaultRateLimiter() *rate.Limiter {
	return rate.NewLimiter(rate.Limit(5), 10)
}

// retryableStatus reports whether an HTTP status is worth retrying. 4xx
// other than 429 are caller errors (bad token, forbidden, bad request) and
// retrying them only delays the failure, so they are never retried.
func retryableStatus(code int) bool {
	return code == http.StatusTooManyRequests ||
		code == http.StatusInternalServerError ||
		code == http.StatusBadGateway ||
		code == http.StatusServiceUnavailable ||
		code == http.StatusGatewayTimeout
}

// backoff returns the wait before retry number n (1-based). Exponential from
// BaseDelay, capped at MaxDelay, with half-to-full jitter so concurrent runs
// against one tenant do not retry in lockstep. A server-supplied Retry-After
// raises the wait but is still bounded by MaxDelay.
func (p RetryPolicy) backoff(n int, retryAfter time.Duration) time.Duration {
	d := p.BaseDelay
	for i := 1; i < n && d < p.MaxDelay; i++ {
		d *= 2
	}
	if d > p.MaxDelay {
		d = p.MaxDelay
	}
	if retryAfter > d {
		d = retryAfter
	}
	if d > p.MaxDelay && p.MaxDelay > 0 {
		d = p.MaxDelay
	}
	if d <= 0 {
		return 0
	}
	half := d / 2
	return half + time.Duration(rand.Int64N(int64(half)+1))
}

// parseRetryAfter reads a Retry-After header in its delta-seconds form.
// HTTP-date form is not used by the Microsoft or Google control planes, so an
// unparseable value yields zero and the exponential backoff applies instead.
func parseRetryAfter(v string) time.Duration {
	secs, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || secs < 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
}

// sleepCtx waits for d or until ctx is done, whichever comes first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// doWithRetry sends a request built fresh by build on every attempt (a
// request body or bearer token may need re-creating), waiting on limiter
// before each attempt when one is set. It returns the last response when a
// retryable status is still present after the final attempt, so callers keep
// their existing status-code handling. Transport errors on the final attempt
// are returned wrapped; context cancellation is never retried.
func doWithRetry(ctx context.Context, client *http.Client, limiter *rate.Limiter, policy RetryPolicy, build func(context.Context) (*http.Request, error)) (*http.Response, error) {
	attempts := max(policy.MaxAttempts, 1)
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if limiter != nil {
			if err := limiter.Wait(ctx); err != nil {
				return nil, err
			}
		}
		req, err := build(ctx)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err == nil && !retryableStatus(resp.StatusCode) {
			return resp, nil
		}
		if err == nil && attempt == attempts {
			return resp, nil
		}

		var retryAfter time.Duration
		if err != nil {
			if ctx.Err() != nil {
				return nil, err
			}
			lastErr = err
		} else {
			retryAfter = parseRetryAfter(resp.Header.Get("Retry-After"))
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
			resp.Body.Close()
		}
		if attempt == attempts {
			return nil, fmt.Errorf("gave up after %d attempts: %w", attempts, lastErr)
		}
		if err := sleepCtx(ctx, policy.backoff(attempt, retryAfter)); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("gave up after %d attempts: %w", attempts, lastErr)
}

// Redact removes every non-empty secret from msg before it is logged, stored
// in cloud_runs.error, or returned to an API caller. Discovery errors carry
// URLs and upstream bodies that may echo credentials back; this is the single
// place that scrubs them.
func Redact(msg string, secrets ...string) string {
	for _, s := range secrets {
		if s != "" {
			msg = strings.ReplaceAll(msg, s, "[REDACTED]")
		}
	}
	return msg
}
