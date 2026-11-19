//go:build windows

package main

import (
	"log"

	"golang.org/x/sys/windows"
)

// trayKillFunc terminates the process with the given PID. A package-level
// var, injectable in tests, mirroring trayProcessAlive's pattern.
var trayKillFunc = func(pid int32) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.TerminateProcess(h, 0)
}

// stopTrayForActiveSession terminates the currently tracked tray process, if
// one is still running, and clears trayPID.
//
// The service stopping (via the SCM, including MSI's ServiceControl Stop
// during an upgrade/reinstall) never used to touch the tray: it is a
// separate process ("<exe> --tray", the SAME binary as the service),
// spawned into the logged-in user's session via CreateProcessAsUser, and
// the SCM has no idea it exists. An upgrade's file-replacement step would
// then find that tray process still holding the exe open, and Windows
// Installer's Restart Manager would refuse to proceed automatically
// ("unable to automatically close all requested applications"), forcing a
// manual stop before every reinstall over an already-installed agent.
func stopTrayForActiveSession() {
	pid := trayPID.Load()
	if !trayProcessAlive(pid) {
		return
	}
	if err := trayKillFunc(pid); err != nil {
		log.Printf("[svc] stop tray: terminate pid %d: %v", pid, err)
		return
	}
	trayPID.Store(0)
}
