//go:build windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
)

type fakeServiceController struct {
	controlCalls []svc.Cmd
	queryResults []svc.Status
	queryErr     error
	queryIdx     int
}

func (f *fakeServiceController) Control(c svc.Cmd) (svc.Status, error) {
	f.controlCalls = append(f.controlCalls, c)
	return svc.Status{}, nil
}

func (f *fakeServiceController) Query() (svc.Status, error) {
	if f.queryErr != nil {
		return svc.Status{}, f.queryErr
	}
	if len(f.queryResults) == 0 {
		return svc.Status{}, nil
	}
	idx := f.queryIdx
	if idx >= len(f.queryResults) {
		idx = len(f.queryResults) - 1
	} else {
		f.queryIdx++
	}
	return f.queryResults[idx], nil
}

func TestStopServiceAndWait_StopsCleanlyWithinPoll(t *testing.T) {
	s := &fakeServiceController{
		queryResults: []svc.Status{
			{State: svc.StopPending},
			{State: svc.Stopped},
		},
	}
	terminateCalled := false
	terminate := func(pid uint32) error { terminateCalled = true; return nil }

	err := stopServiceAndWait(s, 2*time.Second, 5*time.Millisecond, terminate)
	if err != nil {
		t.Fatalf("stopServiceAndWait returned error: %v", err)
	}
	if terminateCalled {
		t.Fatal("terminate should not be called when the service stops within the poll window")
	}
	if len(s.controlCalls) != 1 || s.controlCalls[0] != svc.Stop {
		t.Fatalf("expected exactly one svc.Stop control call, got %v", s.controlCalls)
	}
}

func TestStopServiceAndWait_TerminatesAfterTimeout(t *testing.T) {
	s := &fakeServiceController{
		queryResults: []svc.Status{
			{State: svc.Running, ProcessId: 4242},
		},
	}
	var terminatedPID uint32
	terminate := func(pid uint32) error { terminatedPID = pid; return nil }

	err := stopServiceAndWait(s, 30*time.Millisecond, 5*time.Millisecond, terminate)
	if err != nil {
		t.Fatalf("stopServiceAndWait returned error: %v", err)
	}
	if terminatedPID != 4242 {
		t.Fatalf("expected terminate to be called with PID 4242, got %d", terminatedPID)
	}
}

func TestStopServiceAndWait_TerminateFailurePropagates(t *testing.T) {
	s := &fakeServiceController{
		queryResults: []svc.Status{
			{State: svc.Running, ProcessId: 99},
		},
	}
	wantErr := errors.New("terminate boom")
	terminate := func(pid uint32) error { return wantErr }

	err := stopServiceAndWait(s, 20*time.Millisecond, 5*time.Millisecond, terminate)
	if err == nil {
		t.Fatal("expected an error when terminate fails, got nil")
	}
}

func TestStopServiceAndWait_QueryErrorTreatedAsStopped(t *testing.T) {
	s := &fakeServiceController{queryErr: errors.New("service handle gone")}
	terminateCalled := false
	terminate := func(pid uint32) error { terminateCalled = true; return nil }

	err := stopServiceAndWait(s, 2*time.Second, 5*time.Millisecond, terminate)
	if err != nil {
		t.Fatalf("stopServiceAndWait returned error: %v", err)
	}
	if terminateCalled {
		t.Fatal("terminate should not be called when Query errors (service already gone)")
	}
}

func TestStopServiceAndWait_ZeroPIDSkipsTerminate(t *testing.T) {
	s := &fakeServiceController{
		queryResults: []svc.Status{
			{State: svc.Running, ProcessId: 0},
		},
	}
	terminateCalled := false
	terminate := func(pid uint32) error { terminateCalled = true; return nil }

	err := stopServiceAndWait(s, 20*time.Millisecond, 5*time.Millisecond, terminate)
	if err != nil {
		t.Fatalf("stopServiceAndWait returned error: %v", err)
	}
	if terminateCalled {
		t.Fatal("terminate should not be called when the last known status has no PID")
	}
}

func TestTerminateProcessByPID_KillsRunningProcess(t *testing.T) {
	cmd := exec.Command("cmd", "/c", "ping -n 30 127.0.0.1 >nul")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start test process: %v", err)
	}
	pid := uint32(cmd.Process.Pid)

	if err := terminateProcessByPID(pid); err != nil {
		t.Fatalf("terminateProcessByPID: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
		// process exited -- Wait() returning an error here is expected since it was killed
	case <-time.After(5 * time.Second):
		t.Fatal("process did not exit after terminateProcessByPID")
	}
}

func TestScheduleBinaryDeleteOnReboot_ExistingFileSucceeds(t *testing.T) {
	f, err := os.CreateTemp("", "bas-uninstall-test-*.tmp")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	path := f.Name()
	f.Close()
	defer os.Remove(path)

	if err := scheduleBinaryDeleteOnReboot(path); err != nil {
		t.Fatalf("scheduleBinaryDeleteOnReboot: %v", err)
	}
}

func TestScheduleBinaryDeleteOnReboot_MissingFileIsNotAnError(t *testing.T) {
	// MOVEFILE_DELAY_UNTIL_REBOOT only queues the pending-rename registration;
	// Windows does not verify the source exists until the actual reboot-time
	// delete attempt, so a missing path here is not itself an error.
	path := filepath.Join(os.TempDir(), "bas-does-not-exist-12345.exe")
	if err := scheduleBinaryDeleteOnReboot(path); err != nil {
		t.Fatalf("scheduleBinaryDeleteOnReboot on a missing path should not error, got: %v", err)
	}
}

func TestScheduleBinaryDeleteOnReboot_EmptyPathErrors(t *testing.T) {
	if err := scheduleBinaryDeleteOnReboot(""); err == nil {
		t.Fatal("expected an error scheduling delete for an empty path")
	}
}

const testRunKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`

func TestRemoveRegistryRunValue_RemovesExistingValue(t *testing.T) {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, testRunKeyPath, registry.SET_VALUE)
	if err != nil {
		t.Fatalf("create test Run key: %v", err)
	}
	const name = "BASUninstallTestValue"
	if err := k.SetStringValue(name, `"C:\nowhere.exe" --tray`); err != nil {
		k.Close()
		t.Fatalf("seed test Run value: %v", err)
	}
	k.Close()

	if err := removeRegistryRunValue(registry.CURRENT_USER, name); err != nil {
		t.Fatalf("removeRegistryRunValue: %v", err)
	}

	rk, err := registry.OpenKey(registry.CURRENT_USER, testRunKeyPath, registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("reopen test Run key: %v", err)
	}
	defer rk.Close()
	if _, _, err := rk.GetStringValue(name); err == nil {
		t.Fatal("expected the Run value to be gone after removeRegistryRunValue")
	}
}

func TestRemoveRegistryRunValue_MissingValueIsSuccess(t *testing.T) {
	if err := removeRegistryRunValue(registry.CURRENT_USER, "BASUninstallTestValueThatNeverExisted"); err != nil {
		t.Fatalf("removing an absent Run value should be a no-op success, got: %v", err)
	}
}

func TestCloseTrayWindow_NoWindowIsNoop(t *testing.T) {
	// No tray window registered in this test process -- must not panic or block.
	closeTrayWindow()
}

func TestCloseTrayWindow_ClosesRunningTrayWindow(t *testing.T) {
	// Probe for an existing tray instance WITHOUT calling trayAlreadyRunning()
	// -- that function also creates the singleton mutex as a side effect of
	// checking, which would make runTray()'s own internal trayAlreadyRunning()
	// call (same process, same mutex) see it as already held and return
	// immediately without ever creating a window.
	mutexName, _ := windows.UTF16PtrFromString("BASAgentTray_singleton")
	if h, err := windows.OpenMutex(0x00100000 /*SYNCHRONIZE*/, false, mutexName); err == nil && h != 0 {
		windows.CloseHandle(h)
		t.Skip("another tray instance already holds the singleton mutex in this session")
	}

	done := make(chan struct{})
	go func() {
		runTray()
		close(done)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for trayWnd == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if trayWnd == 0 {
		t.Fatal("tray window did not appear within timeout")
	}

	closeTrayWindow()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runTray did not exit after closeTrayWindow posted the Exit command")
	}
}

// TestHelperProcessSleep is not a real test -- it's spawned as a subprocess
// by TestTerminateOtherAgentProcesses_KillsMatchingProcessButNotSelf to
// stand in for a tray/status-window process sharing the same exe (matching
// terminateOtherAgentProcesses' basename-based lookup requires an actual
// second process running this same test binary, not a mock). Guarded by an
// env var so `go test` running it directly, as part of the normal suite, is
// an instant no-op rather than an actual multi-second sleep.
func TestHelperProcessSleep(t *testing.T) {
	if os.Getenv("BAS_TEST_HELPER_SLEEP") != "1" {
		return
	}
	time.Sleep(30 * time.Second)
}

func TestTerminateOtherAgentProcesses_KillsMatchingProcessButNotSelf(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	cmd := exec.Command(exe, "-test.run", "^TestHelperProcessSleep$")
	cmd.Env = append(os.Environ(), "BAS_TEST_HELPER_SLEEP=1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start decoy process: %v", err)
	}
	decoyPID := uint32(cmd.Process.Pid)
	defer cmd.Process.Kill() // safety net if the test fails before termination

	// Give the decoy a moment to actually be running before terminating --
	// terminateOtherAgentProcesses only sees processes present in the
	// snapshot at the moment it's called.
	time.Sleep(200 * time.Millisecond)

	terminateOtherAgentProcesses()

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
		// decoy exited -- expected
	case <-time.After(5 * time.Second):
		t.Fatal("decoy process did not exit after terminateOtherAgentProcesses")
	}

	if uint32(os.Getpid()) == decoyPID {
		t.Fatal("test process PID unexpectedly matches decoy PID -- test setup is broken")
	}
}

func TestRemoveShortcutAt_RemovesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Audspect Agent - Show Tray Icon.lnk")
	if err := os.WriteFile(path, []byte("not a real shortcut, just test bytes"), 0644); err != nil {
		t.Fatalf("seed test shortcut file: %v", err)
	}

	if err := removeShortcutAt(path); err != nil {
		t.Fatalf("removeShortcutAt: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected shortcut file to be gone, stat err = %v", err)
	}
}

func TestRemoveShortcutAt_MissingFileIsSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.lnk")
	if err := removeShortcutAt(path); err != nil {
		t.Fatalf("removing an absent shortcut should be a no-op success, got: %v", err)
	}
}
