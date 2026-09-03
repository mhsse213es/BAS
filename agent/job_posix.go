//go:build linux || darwin

package main

import (
	"log"
	"syscall"
)

// Process-tree termination on POSIX.
//
// This file previously claimed that "process-group kill via
// exec.CommandContext context cancellation is sufficient on POSIX -- the
// signal propagates to the entire process group automatically" and left every
// function empty. Both halves of that claim were wrong: CommandContext's
// default cancellation is cmd.Process.Kill(), which SIGKILLs a single PID and
// never touches a process group, and nothing put the child in a group of its
// own to begin with. Layer 3 (the tree kill Windows gets from Job Objects) was
// therefore a no-op on Linux/macOS, so any step whose shell forked left
// descendants alive holding the step's stdout/stderr pipe -- wedging cmd.Wait
// indefinitely and hanging the whole run, immune to timeout and to operator
// cancel alike.
//
// buildCmd now sets SysProcAttr.Setpgid, so the shell leads its own process
// group whose PGID equals its PID, and terminateStepJob can signal all of it.

// newStepJob is a no-op on POSIX: the process group is established at spawn
// time by buildCmd's Setpgid, not afterwards. The returned handle is unused.
func newStepJob(_ int) (uintptr, error) { return 0, nil }

// terminateStepJob SIGKILLs the step's entire process group. Called only after
// the execute-timeout or a scenario cancel has already fired and the grace
// window has elapsed, so anything still alive here is refusing to wind down.
func terminateStepJob(_ uintptr, pid int) {
	if pid <= 0 {
		return
	}
	// Negative PID targets the process group. buildCmd's Setpgid makes the
	// child a group leader, so its PGID is its PID.
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil {
		// ESRCH simply means the tree already exited -- the common, healthy
		// case once the direct-child kill was enough. Anything else is worth
		// seeing, since it means descendants may still be holding the step's
		// pipes open.
		if err != syscall.ESRCH {
			log.Printf("[exec] process-group kill for pid %d: %v", pid, err)
		}
	}
}

// closeStepJob is a no-op on POSIX -- there is no job handle to release.
func closeStepJob(_ uintptr) {}
