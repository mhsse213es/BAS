//go:build windows

package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// After a run, a process the run started and left behind is stopped. A process counts as the run's only if it is
// new since the run began AND either descends from the agent or is an orphan of a well-known demo program (its parent
// has gone, so nothing the user did started it). The user's own programs have a live parent (Explorer) and are never
// touched, and the shell and system processes are never touched whatever their parentage.

type fakeProc = procInfo

func withFakeProcs(t *testing.T, agent uint32, procs []fakeProc) *[]uint32 {
	t.Helper()
	var killed []uint32
	oldList, oldKill, oldAgent := listProcessesFn, terminateFn, agentPIDFn
	listProcessesFn = func() []procInfo { return procs }
	terminateFn = func(pid uint32) error { killed = append(killed, pid); return nil }
	agentPIDFn = func() uint32 { return agent }
	t.Cleanup(func() { listProcessesFn, terminateFn, agentPIDFn = oldList, oldKill, oldAgent })
	return &killed
}

func TestSweep_StopsADescendantOfTheAgentThatIsNewSinceTheRunBegan(t *testing.T) {
	base := procBaseline{}
	killed := withFakeProcs(t, 100, []fakeProc{
		{PID: 100, PPID: 4, Created: 10, Exe: "agent.exe"},
		{PID: 200, PPID: 100, Created: 50, Exe: "powershell.exe"},
		{PID: 201, PPID: 200, Created: 60, Exe: "vendortool.exe"}, // grandchild, not a demo program: still ours by ancestry
	})
	lines := sweepStrayProcesses(base)
	if len(*killed) != 2 || len(lines) != 2 {
		t.Fatalf("want both descendants stopped, killed=%v lines=%v", *killed, lines)
	}
	if !strings.Contains(lines[0], "powershell.exe") && !strings.Contains(lines[1], "powershell.exe") {
		t.Errorf("each stop is reported with the program name: %v", lines)
	}
}

func TestSweep_LeavesAProcessThatWasAlreadyRunning(t *testing.T) {
	base := procBaseline{200: 50}
	killed := withFakeProcs(t, 100, []fakeProc{
		{PID: 100, PPID: 4, Created: 10, Exe: "agent.exe"},
		{PID: 200, PPID: 100, Created: 50, Exe: "powershell.exe"}, // same pid and creation time as at the start
	})
	if lines := sweepStrayProcesses(base); len(*killed) != 0 || len(lines) != 0 {
		t.Fatalf("a pre-existing process must not be touched: %v %v", *killed, lines)
	}
}

func TestSweep_AReusedPidIsANewProcess(t *testing.T) {
	base := procBaseline{200: 50}
	killed := withFakeProcs(t, 100, []fakeProc{
		{PID: 100, PPID: 4, Created: 10, Exe: "agent.exe"},
		{PID: 200, PPID: 100, Created: 900, Exe: "cmd.exe"}, // pid 200 again, but created later
	})
	sweepStrayProcesses(base)
	if len(*killed) != 1 {
		t.Fatalf("a process that reuses a pid is new, killed=%v", *killed)
	}
}

func TestSweep_NeverTouchesTheShellOrSystemProcessesOrTheAgentItself(t *testing.T) {
	procs := []fakeProc{{PID: 100, PPID: 4, Created: 10, Exe: "agent.exe"}}
	for i, name := range []string{"explorer.exe", "dwm.exe", "winlogon.exe", "csrss.exe", "lsass.exe", "services.exe",
		"svchost.exe", "sihost.exe", "ctfmon.exe", "agent.exe", "RuntimeBroker.exe"} {
		procs = append(procs, fakeProc{PID: uint32(300 + i), PPID: 100, Created: 70, Exe: name})
	}
	killed := withFakeProcs(t, 100, procs)
	exeName := "agent.exe"
	oldSelf := selfExeName
	selfExeName = func() string { return exeName }
	defer func() { selfExeName = oldSelf }()
	sweepStrayProcesses(procBaseline{})
	if len(*killed) != 0 {
		t.Fatalf("protected processes were stopped: %v", *killed)
	}
}

func TestSweep_AnOrphanOfADemoProgramIsStoppedButAUsersOwnProgramIsNot(t *testing.T) {
	killed := withFakeProcs(t, 100, []fakeProc{
		{PID: 100, PPID: 4, Created: 10, Exe: "agent.exe"},
		{PID: 500, PPID: 40, Created: 5, Exe: "explorer.exe"},
		{PID: 600, PPID: 999, Created: 80, Exe: "notepad.exe"}, // parent 999 is gone: launched by something that has exited
		{PID: 601, PPID: 500, Created: 85, Exe: "notepad.exe"}, // parent is Explorer: the user opened it
		{PID: 602, PPID: 999, Created: 90, Exe: "vendor.exe"},  // orphan, but not a demo program
	})
	sweepStrayProcesses(procBaseline{500: 5, 100: 10})
	if len(*killed) != 1 || (*killed)[0] != 600 {
		t.Fatalf("only the orphaned notepad should be stopped, killed=%v", *killed)
	}
}

func TestSweep_StopsARealDetachedChildAndSparesOneThatPredatedTheRun(t *testing.T) {
	oldAgent := agentPIDFn
	agentPIDFn = func() uint32 { return uint32(os.Getpid()) }
	defer func() { agentPIDFn = oldAgent }()

	older := exec.Command("ping", "-n", "120", "127.0.0.1")
	if err := older.Start(); err != nil {
		t.Fatal(err)
	}
	defer older.Process.Kill()
	time.Sleep(300 * time.Millisecond)

	base := captureProcs()

	during := exec.Command("ping", "-n", "120", "127.0.0.1")
	if err := during.Start(); err != nil {
		t.Fatal(err)
	}
	defer during.Process.Kill()
	time.Sleep(300 * time.Millisecond)

	lines := sweepStrayProcesses(base)
	found := false
	for _, l := range lines {
		if strings.Contains(strings.ToLower(l), "ping.exe") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the child started during the run must be stopped and reported, got %v", lines)
	}
	done := make(chan error, 1)
	go func() { done <- during.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the stray child is still running")
	}
	alive := false
	for _, p := range realListProcesses() {
		if int(p.PID) == older.Process.Pid {
			alive = true
		}
	}
	if !alive {
		t.Fatal("the process that predated the run must still be running")
	}
}

func TestSweep_RunsThroughSnapshotAndRevert(t *testing.T) {
	snap := captureSnapshot("sweep-test")
	if snap.Procs == nil {
		t.Fatal("captureSnapshot did not record the running processes")
	}
	stray := exec.Command("ping", "-n", "120", "127.0.0.1") // a child of this process, started during the "run"
	if err := stray.Start(); err != nil {
		t.Fatal(err)
	}
	defer stray.Process.Kill()
	time.Sleep(300 * time.Millisecond)

	reverted := revertFromSnapshot(snap)
	found := false
	for _, r := range reverted {
		if strings.HasPrefix(r, "stray process stopped:") && strings.Contains(strings.ToLower(r), "ping.exe") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the stray process must be stopped and reported by the revert, got %v", reverted)
	}
}
