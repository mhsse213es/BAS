//go:build !windows

package main

import (
	"context"

	"audspect/agent/protocol"
)

// HostPool is a no-op on non-Windows platforms: there is no PowerShell host to
// pool, so every step runs through the standard per-process executor.
type HostPool struct{}

// NewHostPool returns nil on non-Windows platforms. A nil pool makes execStep
// skip the pooled path entirely.
func NewHostPool(int) *HostPool { return nil }

// pooledCandidate is always false off Windows — there is no host pool.
func pooledCandidate(ScenarioStep) bool { return false }

// Run never runs anything off Windows; ok=false tells execStep to use the
// per-process path.
func (p *HostPool) Run(context.Context, ScenarioStep) (protocol.ExecResult, bool) {
	return protocol.ExecResult{}, false
}

// Close is a no-op.
func (p *HostPool) Close() {}
