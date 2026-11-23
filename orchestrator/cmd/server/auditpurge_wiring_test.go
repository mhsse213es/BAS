package main

import (
	"context"
	"testing"

	"github.com/audspect/bas/config"
)

// With purging off, startAuditPurge returns before any pool is used.
func TestStartAuditPurge_DisabledByDefault(t *testing.T) {
	startAuditPurge(context.Background(), &config.Config{}, nil, nil)
}

// Enabled but not configured: it refuses to start and never reaches a pool, so nil pools are safe here.
func TestStartAuditPurge_RefusesWhenNotConfigured(t *testing.T) {
	startAuditPurge(context.Background(), &config.Config{AuditPurgeEnabled: true}, nil, nil)
}
