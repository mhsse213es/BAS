//go:build linux || darwin

package main

import "context"

// trackExecPID, untrackExecPID and startDismisser are no-ops on Linux/macOS.
// POSIX processes don't show interactive GUI dialogs — signals propagate
// through the process group and the Job Object equivalent (process groups)
// already handles tree-kill via exec.CommandContext.

func trackExecPID(_ uint32)           {}
func untrackExecPID(_ uint32)         {}
func startDismisser(_ context.Context) {}
