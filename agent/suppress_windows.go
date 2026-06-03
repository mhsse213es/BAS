//go:build windows

package main

import (
	"log"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// ── Win32 error-mode suppression ─────────────────────────────────────────────

var (
	modKernel32      = windows.NewLazySystemDLL("kernel32.dll")
	procSetErrorMode = modKernel32.NewProc("SetErrorMode")
)

const (
	// SetErrorMode flags — combined, these suppress all system-generated error dialogs
	// for the agent process AND every child process it spawns (flags are inherited).
	semFailCriticalErrors = 0x0001 // no "drive not ready / insert disk" dialogs
	semNoGPFaultErrorBox  = 0x0002 // no General Protection Fault / crash dialogs
	semNoOpenFileErrorBox = 0x8000 // no "file not found" open-file dialogs
	semNoAlignFaultBox    = 0x0004 // no alignment-fault dialogs on some architectures
)

func setErrorMode(flags uint32) uint32 {
	old, _, _ := procSetErrorMode.Call(uintptr(flags))
	return uint32(old)
}

// ── suppressSystemDialogs ─────────────────────────────────────────────────────
// Called once during agent startup (platformPreStart).  Sets process-level and
// machine-level controls so that every scenario step executes in a dialog-free
// environment even if the step triggers a crash, missing file, or GPF.
//
// Controls applied:
//  1. SetErrorMode  — kernel-level: inherits to all child processes
//  2. WER DontShowUI — no "App has stopped working" popup on any crash
//  3. WER Auto      — silent JIT debugger (no "Debug / Close" choice dialog)
//  4. HungAppTimeout / AutoEndTasks — Windows auto-kills hung windows in 1 s
//  5. DisablePCA    — Program Compatibility Assistant won't intercept crashes
func suppressSystemDialogs() {
	suppressedFlags := uint32(semFailCriticalErrors | semNoGPFaultErrorBox |
		semNoOpenFileErrorBox | semNoAlignFaultBox)

	old := setErrorMode(suppressedFlags)
	log.Printf("[suppress] SetErrorMode: 0x%04X → 0x%04X — crash/GPF/file dialogs suppressed for all child processes",
		old, suppressedFlags)

	applyWERSuppression()
	applyHungAppDismissal()
	applyPCASuppression()
}

// applyWERSuppression disables Windows Error Reporting interactive dialogs.
// Without this, any crash inside a scenario step shows an "App has stopped
// working" modal that blocks the step until a human clicks Close.
func applyWERSuppression() {
	const werKey = `Software\Microsoft\Windows\Windows Error Reporting`

	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, werKey, registry.SET_VALUE)
	if err != nil {
		log.Printf("[suppress] WER key open failed: %v — crash dialogs may still appear", err)
		return
	}
	defer k.Close()

	// DontShowUI=1 → WER collects data silently, never shows a dialog.
	if err := k.SetDWordValue("DontShowUI", 1); err != nil {
		log.Printf("[suppress] WER DontShowUI: %v", err)
	}
	// Keep logging enabled — SOC analysts still get crash reports in Event Log.
	_ = k.SetDWordValue("LoggingDisabled", 0)

	log.Printf("[suppress] WER DontShowUI=1 applied — crash dialogs suppressed")

	// AeDebug Auto=1: if a crash reaches the JIT debugger hook, Windows invokes
	// the debugger automatically without asking.  Auto=0 (Windows default) shows a
	// "Debug / Close" dialog that hangs the step forever.
	const aeKey = `Software\Microsoft\Windows NT\CurrentVersion\AeDebug`
	ak, _, err := registry.CreateKey(registry.LOCAL_MACHINE, aeKey, registry.SET_VALUE)
	if err == nil {
		defer ak.Close()
		_ = ak.SetStringValue("Auto", "1")
		log.Printf("[suppress] AeDebug Auto=1 applied — JIT debug dialogs suppressed")
	}
}

// applyHungAppDismissal sets desktop timeouts so Windows auto-terminates hung
// application windows (including dialog boxes stuck waiting for input) after
// 1 second instead of showing "Not Responding" indefinitely.
func applyHungAppDismissal() {
	k, _, err := registry.CreateKey(registry.CURRENT_USER,
		`Control Panel\Desktop`, registry.SET_VALUE)
	if err != nil {
		log.Printf("[suppress] Desktop key: %v", err)
		return
	}
	defer k.Close()

	// AutoEndTasks=1: auto-end apps that don't respond to WM_ENDSESSION.
	_ = k.SetStringValue("AutoEndTasks", "1")
	// HungAppTimeout: ms before "Not Responding" label appears (1 s).
	_ = k.SetStringValue("HungAppTimeout", "1000")
	// WaitToKillAppTimeout: ms before Windows force-kills a hung app (1 s).
	_ = k.SetStringValue("WaitToKillAppTimeout", "1000")

	log.Printf("[suppress] HungAppTimeout=1000ms, AutoEndTasks=1 applied — hung dialogs auto-dismissed after 1 s")
}

// applyPCASuppression disables the Program Compatibility Assistant.
// PCA intercepts executables that crash or exit with certain codes and pops up
// "This program might not have installed correctly" — exactly what ART tests
// trigger regularly (they are designed to simulate attacker behaviour that
// Windows flags as suspicious).
func applyPCASuppression() {
	const pcaKey = `Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags`

	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, pcaKey, registry.SET_VALUE)
	if err != nil {
		log.Printf("[suppress] PCA key: %v", err)
		return
	}
	defer k.Close()

	_ = k.SetDWordValue("DisablePCA", 1)
	log.Printf("[suppress] DisablePCA=1 applied — Program Compatibility Assistant suppressed")
}

// RestoreSystemDialogs undoes the registry changes applied by suppressSystemDialogs.
// Called on clean agent shutdown so the machine reverts to standard Windows
// behaviour when BAS is not running.
func RestoreSystemDialogs() {
	// Restore WER interactive mode
	const werKey = `Software\Microsoft\Windows\Windows Error Reporting`
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, werKey, registry.SET_VALUE); err == nil {
		_ = k.SetDWordValue("DontShowUI", 0)
		k.Close()
	}

	// Restore PCA
	const pcaKey = `Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags`
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, pcaKey, registry.SET_VALUE); err == nil {
		_ = k.DeleteValue("DisablePCA")
		k.Close()
	}

	// Restore hung-app timeouts to Windows defaults (5000 ms)
	if k, err := registry.OpenKey(registry.CURRENT_USER, `Control Panel\Desktop`, registry.SET_VALUE); err == nil {
		_ = k.SetStringValue("AutoEndTasks", "0")
		_ = k.SetStringValue("HungAppTimeout", "5000")
		_ = k.SetStringValue("WaitToKillAppTimeout", "5000")
		k.Close()
	}

	// Restore AeDebug Auto to default (0 = ask before attaching debugger)
	const aeKey = `Software\Microsoft\Windows NT\CurrentVersion\AeDebug`
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, aeKey, registry.SET_VALUE); err == nil {
		_ = k.SetStringValue("Auto", "0")
		k.Close()
	}

	// SetErrorMode back to 0 (Windows default — show all dialogs)
	setErrorMode(0)
	log.Printf("[suppress] system dialog suppression reverted — machine restored to normal Windows behaviour")
}

