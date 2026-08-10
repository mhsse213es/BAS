//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
)

const runKeyPath = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

// trayRunValueName matches the value name registerTrayStartup (installer/main.go)
// writes at install time under HKLM\...\Run.
const trayRunValueName = "BASAgentTray"

// serviceController is the subset of *mgr.Service that stopServiceAndWait
// needs, so the poll/terminate loop can be tested against a fake instead of
// a real SCM handle.
type serviceController interface {
	Control(c svc.Cmd) (svc.Status, error)
	Query() (svc.Status, error)
}

// stopServiceAndWait requests a stop and polls Query() until the service
// reports Stopped (mirrors svcUpdate's poll loop), up to timeout. If the
// service is still not stopped when the deadline passes, it terminates the
// service process directly by PID via terminate — a last resort so a
// wedged service never blocks uninstall indefinitely. A Query error is
// treated as "service already gone" (nothing left to terminate).
func stopServiceAndWait(s serviceController, timeout, pollInterval time.Duration, terminate func(pid uint32) error) error {
	_, _ = s.Control(svc.Stop)

	deadline := time.Now().Add(timeout)
	var last svc.Status
	for {
		st, err := s.Query()
		if err != nil {
			return nil
		}
		last = st
		if st.State == svc.Stopped {
			return nil
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(pollInterval)
	}

	if last.ProcessId == 0 {
		return nil
	}
	if err := terminate(last.ProcessId); err != nil {
		return fmt.Errorf("service did not stop within %s and terminate failed: %w", timeout, err)
	}
	return nil
}

// terminateProcessByPID force-kills a process by PID. Used as the last-resort
// fallback when a service does not respond to Control(svc.Stop) in time.
func terminateProcessByPID(pid uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(h)
	if err := windows.TerminateProcess(h, 1); err != nil {
		return fmt.Errorf("TerminateProcess(%d): %w", pid, err)
	}
	return nil
}

// scheduleBinaryDeleteOnReboot registers path for deletion the next time
// Windows restarts. A running process cannot delete its own executing .exe
// (nor can the service's stopped-but-recently-exited process be assumed
// fully unmapped), so uninstall cannot remove the binary in-place — this is
// the standard OS-level deferred-delete mechanism instead of a custom
// helper process.
func scheduleBinaryDeleteOnReboot(path string) error {
	src, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(src, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT); err != nil {
		return fmt.Errorf("MoveFileEx(%s, delay-until-reboot): %w", path, err)
	}
	return nil
}

// removeRegistryRunValue deletes a value from root's
// SOFTWARE\Microsoft\Windows\CurrentVersion\Run key. A missing key or a
// missing value are both treated as success — uninstall cleanup is
// idempotent, so "already gone" is the desired end state, not an error.
func removeRegistryRunValue(root registry.Key, name string) error {
	k, err := registry.OpenKey(root, runKeyPath, registry.SET_VALUE)
	if err != nil {
		if err == registry.ErrNotExist {
			return nil
		}
		return fmt.Errorf("open Run key: %w", err)
	}
	defer k.Close()

	if err := k.DeleteValue(name); err != nil && err != registry.ErrNotExist {
		return fmt.Errorf("delete Run value %q: %w", name, err)
	}
	return nil
}

// removeTrayRunKey removes the BASAgentTray autostart entry that
// registerTrayStartup (installer/main.go) writes under HKLM at install time.
func removeTrayRunKey() error {
	return removeRegistryRunValue(registry.LOCAL_MACHINE, trayRunValueName)
}

// closeTrayWindow best-effort closes any running tray process by finding its
// window (class "BASAgentTrayWnd", title "BAS Agent" — see tray_windows.go)
// and posting WM_COMMAND/tIDM_EXIT, which trayWndProc handles by removing
// the icon and calling PostQuitMessage so the process actually ends. This is
// the only way the tray exits now — its right-click menu has no user-facing
// "Exit" entry by design (the client must not be able to quit it), so
// tIDM_EXIT is reachable only programmatically, from here. Plain WM_CLOSE was
// considered and rejected: trayWndProc has no WM_DESTROY handler, so
// DefWindowProc's default WM_CLOSE handling (DestroyWindow) would tear down
// the window but leave GetMessage blocking forever — the icon might vanish
// but the process would never exit, which is the opposite of what uninstall
// needs. A missing window means no tray is running, which is already the
// desired end state, so there is nothing to report as a failure.
//
// FindWindowW only sees windows on the caller's own window station, so this
// is a no-op whenever the caller and the tray are in different Windows
// sessions -- exactly the normal case for both svcUninstall (may run
// elevated in a different session than the logged-in user) and
// platformSelfUninstall (runs as SYSTEM in the service's non-interactive
// Session 0, while the tray runs in the interactive user's session -- see
// launchTrayForActiveSession in usertoken_windows.go). Both callers pair
// this with terminateOtherAgentProcesses below, which works regardless of
// session.
func closeTrayWindow() {
	hwnd, _, _ := trayFindWindow.Call(
		uintptr(unsafe.Pointer(trayClsName)),
		uintptr(unsafe.Pointer(trayWndTitle)),
	)
	if hwnd == 0 {
		return
	}
	trayPostMessage.Call(hwnd, tWM_COMMAND, uintptr(tIDM_EXIT), 0)
}

// terminateOtherAgentProcesses hard-kills every other running process that
// shares this executable's name (the tray, an open status console, or any
// stray copy), skipping the caller's own PID. This is the actual backstop
// that makes uninstall reliably end the tray/status-window "task" even
// when closeTrayWindow's cross-session FindWindowW lookup can't see it (the
// normal case -- see closeTrayWindow's doc comment). Process enumeration
// via Toolhelp32Snapshot and TerminateProcess both work across sessions,
// unlike window-handle-based APIs. Best-effort: a process that's already
// gone, or one this caller lacks rights to open, is silently skipped --
// uninstall must never fail over tray cleanup.
func terminateOtherAgentProcesses() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	selfName := filepath.Base(exe)
	selfPID := uint32(os.Getpid())

	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snap, &entry); err != nil {
		return
	}
	for {
		name := windows.UTF16ToString(entry.ExeFile[:])
		if strings.EqualFold(name, selfName) && entry.ProcessID != selfPID {
			if h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, entry.ProcessID); err == nil {
				windows.TerminateProcess(h, 1)
				windows.CloseHandle(h)
			}
		}
		if err := windows.Process32Next(snap, &entry); err != nil {
			break
		}
	}
}

// removeShortcutAt deletes the file at path. A missing file is treated as
// success — uninstall cleanup is idempotent, so "already gone" is the
// desired end state, not an error.
func removeShortcutAt(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove shortcut %s: %w", path, err)
	}
	return nil
}

// removeTrayShortcut removes the all-users Start Menu shortcut that
// createTrayShortcut (installer/main.go) creates at install time, using the
// identical path construction so uninstall targets the same file.
func removeTrayShortcut() error {
	startMenu := filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs`)
	shortcutPath := filepath.Join(startMenu, "Audspect Agent - Show Tray Icon.lnk")
	return removeShortcutAt(shortcutPath)
}
