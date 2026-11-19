package main

import (
	"context"
	"log"
	"time"
)

// certRenewalCheckInterval is how often a running agent re-checks its certificate. Renewal starts
// at 75% of the lifetime, so a six-hour check leaves ample time to retry before expiry.
const certRenewalCheckInterval = 6 * time.Hour

// runPeriodic calls fn immediately, then every `every`, until ctx is cancelled.
func runPeriodic(ctx context.Context, every time.Duration, fn func(context.Context)) {
	fn(ctx)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fn(ctx)
		}
	}
}

// runCertRenewal keeps an enrolled agent's certificate fresh without a restart (audit F-06). The
// live connection picks the new certificate up on its next handshake. Never-enrolled agents are
// left to the bootstrap retry loop.
func (a *Agent) runCertRenewal(ctx context.Context) {
	runPeriodic(ctx, certRenewalCheckInterval, func(ctx context.Context) {
		if !isEnrolled() {
			return
		}
		if _, err := ensureCertificate(ctx, a.cfg(), a.id.AgentID); err != nil {
			log.Printf("[!] certificate check: %v", err)
		}
	})
}
