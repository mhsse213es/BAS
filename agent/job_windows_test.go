//go:build windows

package main

import (
	"bufio"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// processAlive reports whether pid identifies a currently-running process.
func processAlive(pid uint32) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	const stillActive = 259
	return code == stillActive
}

// spawnDetachedTree starts a PowerShell process that itself launches a
// long-running detached child (ping -t) via Start-Process, prints the
// child's PID on its first stdout line, then sleeps -- simulating a step
// whose direct child has already spawned a grandchild by the time the
// step's timeout fires. ping.exe's recorded ParentProcessID is the
// PowerShell process regardless of Job Object membership, since
// Start-Process still goes through CreateProcess from inside PowerShell --
// exactly the kernel-level fact killProcessTree's BFS walk relies on.
// Returns the PowerShell parent's PID and the detached ping child's PID.
func spawnDetachedTree(t *testing.T) (parentPID, childPID uint32) {
	t.Helper()
	script := `$p = Start-Process ping -ArgumentList '-t','127.0.0.1' -WindowStyle Hidden -PassThru; Write-Output $p.Id; Start-Sleep -Seconds 30`
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start parent: %v", err)
	}
	t.Cleanup(func() { cmd.Process.Kill() })
	parentPID = uint32(cmd.Process.Pid)

	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		t.Fatalf("parent never printed child PID: %v", scanner.Err())
	}
	line := strings.TrimSpace(scanner.Text())
	n, err := strconv.Atoi(line)
	if err != nil {
		t.Fatalf("parse child PID from %q: %v", line, err)
	}
	childPID = uint32(n)

	if !processAlive(childPID) {
		t.Fatalf("detached child pid=%d not alive right after spawn -- flaky setup, not a mechanism failure", childPID)
	}
	return parentPID, childPID
}

// TestKillProcessTree_NaiveSinglePIDKill_LeavesDescendantAlive proves the
// failure mode killProcessTree exists to prevent: terminating only the
// direct child leaves a detached grandchild running. This is the "before"
// half of the same revert-and-rerun proof used for the POSIX fix (see
// project memory project_agent_execution_hang.md) -- without demonstrating
// the naive approach actually fails, the next test only shows "the code
// passes", never "the code matters".
func TestKillProcessTree_NaiveSinglePIDKill_LeavesDescendantAlive(t *testing.T) {
	parentPID, childPID := spawnDetachedTree(t)
	defer killProcessTree(parentPID) // clean up the detached ping regardless of outcome

	ph, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, parentPID)
	if err != nil {
		t.Fatalf("OpenProcess(parent): %v", err)
	}
	windows.TerminateProcess(ph, 1)
	windows.CloseHandle(ph)

	time.Sleep(300 * time.Millisecond)
	if !processAlive(childPID) {
		t.Fatal("detached child died along with a naive single-PID kill -- test no longer demonstrates the real failure mode, redesign it")
	}
}

// TestKillProcessTree_KillsDescendants is the "after" half: the production
// kill path terminateStepJob always runs regardless of Job Object outcome
// (see terminateStepJob's doc comment) is exercised here directly via
// killProcessTree, and must kill the whole tree -- including the detached
// grandchild the naive kill above proves survives on its own.
func TestKillProcessTree_KillsDescendants(t *testing.T) {
	parentPID, childPID := spawnDetachedTree(t)

	killProcessTree(parentPID)
	time.Sleep(300 * time.Millisecond)

	if processAlive(parentPID) {
		t.Errorf("parent pid=%d survived killProcessTree", parentPID)
	}
	if processAlive(childPID) {
		t.Errorf("detached child pid=%d survived killProcessTree -- descendant escaped the tree kill", childPID)
	}
}

// TestNewStepJob_TerminateKillsJobMember proves the primary path (Job
// Object assignment + TerminateJobObject) also works end to end: a process
// assigned to the job via newStepJob is dead after terminateStepJob, even
// before killProcessTree's PID sweep would have caught it on its own.
func TestNewStepJob_TerminateKillsJobMember(t *testing.T) {
	cmd := exec.Command("ping", "-t", "127.0.0.1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	pid := cmd.Process.Pid
	t.Cleanup(func() { cmd.Process.Kill() })

	job, err := newStepJob(pid)
	if err != nil {
		t.Fatalf("newStepJob: %v", err)
	}
	defer closeStepJob(job)

	if job == 0 {
		t.Fatal("newStepJob returned success but job handle is 0")
	}

	terminateStepJob(job, pid)
	time.Sleep(300 * time.Millisecond)

	if processAlive(uint32(pid)) {
		t.Errorf("pid=%d, job-assigned, survived terminateStepJob", pid)
	}
}
