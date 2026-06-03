//go:build linux || darwin

package main

// newStepJob, terminateStepJob, closeStepJob are no-ops on Linux/macOS.
// Process-group kill via exec.CommandContext context cancellation is sufficient
// on POSIX — the signal propagates to the entire process group automatically.

func newStepJob(_ int) (uintptr, error) { return 0, nil }
func terminateStepJob(_ uintptr)        {}
func closeStepJob(_ uintptr)            {}
