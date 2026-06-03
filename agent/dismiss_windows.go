//go:build windows

package main

import (
	"context"
	"log"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ── Win32 constants ───────────────────────────────────────────────────────────

const (
	wmCommand          = uintptr(0x0111) // WM_COMMAND
	wmClose            = uintptr(0x0010) // WM_CLOSE
	idCancel           = uintptr(2)      // IDCANCEL — "No / Cancel" button
	th32csSnapProcess  = uint32(0x00000002)
)

// dialogClasses is the set of window class names that indicate an interactive
// blocking dialog. We dismiss any visible window in this set that is owned by
// an active scenario step process.
var dialogClasses = map[string]bool{
	"#32770":           true, // Standard Win32 dialog — MessageBox, common dialogs
	"TaskDialogWindow": true, // Vista+ TaskDialog (UAC-style rich dialogs)
	"MsgBoxDlg":        true, // Some application-defined dialog class
	"#32769":           true, // Desktop — sometimes wraps a stuck dialog
}

// ── Lazy user32 procs (unique prefix to avoid name conflicts) ─────────────────

var (
	dlgUser32 = windows.NewLazySystemDLL("user32.dll")

	procDlgEnumWindows     = dlgUser32.NewProc("EnumWindows")
	procDlgGetWinPID       = dlgUser32.NewProc("GetWindowThreadProcessId")
	procDlgIsVisible       = dlgUser32.NewProc("IsWindowVisible")
	procDlgPostMsg         = dlgUser32.NewProc("PostMessageW")
	procDlgGetClassName    = dlgUser32.NewProc("GetClassNameW")
	procDlgGetWindowText   = dlgUser32.NewProc("GetWindowTextW")
)

// ── Active scenario PID tracking ─────────────────────────────────────────────
//
// execStep calls trackExecPID after cmd.Start() and untrackExecPID in a defer.
// The dismisser checks every discovered dialog window's PID (and its ancestors)
// against this set to decide whether it belongs to a running scenario step.

var (
	scenPIDsMu sync.RWMutex
	scenPIDs   = make(map[uint32]bool)
)

// trackExecPID registers a process ID as belonging to an active scenario step.
func trackExecPID(pid uint32) {
	scenPIDsMu.Lock()
	scenPIDs[pid] = true
	scenPIDsMu.Unlock()
}

// untrackExecPID removes a process ID from the active-scenario set.
func untrackExecPID(pid uint32) {
	scenPIDsMu.Lock()
	delete(scenPIDs, pid)
	scenPIDsMu.Unlock()
}

// ── Dialog auto-dismisser ─────────────────────────────────────────────────────

// startDismisser launches a background goroutine that scans for dialog boxes
// owned by active scenario processes every 500 ms and auto-dismisses them.
// The goroutine stops when ctx is cancelled (i.e. when the scenario ends).
//
// Call it once at the start of every runScenario invocation:
//
//	dismissCtx, dismissCancel := context.WithCancel(ctx)
//	defer dismissCancel()
//	startDismisser(dismissCtx)
func startDismisser(ctx context.Context) {
	go func() {
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				dismissScenarioDialogs()
			}
		}
	}()
}

// enumDlgCB is allocated once. It collects visible dialog-class window handles
// into the []uintptr slice whose address is passed as lParam.
// EnumWindows is synchronous so the slice lives on the caller's stack frame
// for the entire duration of the callback — safe to pass as unsafe.Pointer.
var enumDlgCB = syscall.NewCallback(func(hwnd, lParam uintptr) uintptr {
	// Skip invisible windows.
	vis, _, _ := procDlgIsVisible.Call(hwnd)
	if vis == 0 {
		return 1 // continue enumeration
	}

	// Check window class.
	var buf [256]uint16
	procDlgGetClassName.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if !dialogClasses[windows.UTF16ToString(buf[:])] {
		return 1
	}

	results := (*[]uintptr)(unsafe.Pointer(lParam))
	*results = append(*results, hwnd)
	return 1
})

func dismissScenarioDialogs() {
	// Collect all visible dialog windows on the desktop.
	// KeepAlive pins the slice header so the GC doesn't move it while the
	// synchronous EnumWindows callback is writing into it via unsafe.Pointer.
	var dialogs []uintptr
	procDlgEnumWindows.Call(enumDlgCB, uintptr(unsafe.Pointer(&dialogs)))
	runtime.KeepAlive(&dialogs)

	for _, hwnd := range dialogs {
		// Resolve the owning process ID.
		var pid uint32
		procDlgGetWinPID.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
		if pid == 0 {
			continue
		}

		// Check whether this PID (or an ancestor) belongs to a scenario step.
		if !isScenarioPID(pid) {
			continue
		}

		// Read the title for the audit log.
		var title [256]uint16
		procDlgGetWindowText.Call(hwnd, uintptr(unsafe.Pointer(&title[0])), uintptr(len(title)))
		titleStr := windows.UTF16ToString(title[:])

		log.Printf("[BAS-DISMISS] dialog auto-dismissed: pid=%d title=%q", pid, titleStr)

		// PostMessage is non-blocking — we don't wait for the dialog to close.
		// IDCANCEL first: handles dialogs with a Cancel / No button.
		procDlgPostMsg.Call(hwnd, wmCommand, idCancel, 0)
		// WM_CLOSE immediately after: closes dialogs that have no Cancel button
		// or that don't respond to WM_COMMAND (e.g. some custom dialogs).
		procDlgPostMsg.Call(hwnd, wmClose, 0, 0)
	}
}

// isScenarioPID returns true if pid is an active scenario step PID or if any
// of its process ancestors (up to 8 levels) is an active scenario step PID.
// This catches grandchild processes spawned by the direct step child.
func isScenarioPID(pid uint32) bool {
	scenPIDsMu.RLock()
	defer scenPIDsMu.RUnlock()

	if scenPIDs[pid] {
		return true
	}

	// Take a snapshot of the process table and walk ancestors.
	snap, err := windows.CreateToolhelp32Snapshot(th32csSnapProcess, 0)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(snap)

	parentOf := make(map[uint32]uint32, 128)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	for err = windows.Process32First(snap, &entry); err == nil; err = windows.Process32Next(snap, &entry) {
		parentOf[entry.ProcessID] = entry.ParentProcessID
	}

	current := pid
	for i := 0; i < 8; i++ {
		parent, ok := parentOf[current]
		if !ok || parent == 0 || parent == current {
			break
		}
		if scenPIDs[parent] {
			return true
		}
		current = parent
	}
	return false
}
