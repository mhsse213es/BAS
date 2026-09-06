package sched

import "time"

// RetryPolicy bounds how many times a job's attempt cycle repeats and how
// long to wait between attempts. sched has no notion of why a policy is
// generous or conservative -- that judgment belongs to the caller (package
// main, which does know about risk classification), exactly like
// ConcurrencyLimiter's SetLimit takes a plain int with the Level -> int
// mapping living entirely outside sched.
type RetryPolicy struct {
	// MaxAttempts is the total number of attempts, including the first --
	// MaxAttempts <= 1 means no retry (the default zero value, so a Job built
	// without setting Retry behaves exactly as before this phase).
	MaxAttempts int
	// Backoff returns the delay before the next attempt, given the 1-indexed
	// number of the attempt that just failed (Backoff(1) is the delay after
	// the first attempt fails, before the second attempt starts). Nil is
	// treated as zero delay.
	Backoff func(attempt int) time.Duration
}

func (p RetryPolicy) maxAttempts() int {
	if p.MaxAttempts < 1 {
		return 1
	}
	return p.MaxAttempts
}

func (p RetryPolicy) backoff(attempt int) time.Duration {
	if p.Backoff == nil {
		return 0
	}
	return p.Backoff(attempt)
}
