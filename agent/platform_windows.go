//go:build windows

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"
)

var (
	flagUpdate       *bool
	flagConsole      *bool
	flagTray         *bool
	flagStatusWindow *bool

	// Console allocation procs — used when the agent is launched without an
	// attached console (e.g. via ShellExecuteW during self-elevation from Explorer).
	procGetConsoleWindow = modKernel32.NewProc("GetConsoleWindow")
	procAllocConsole     = modKernel32.NewProc("AllocConsole")
)

// ensureConsole allocates a visible console window when the process was spawned
// without one (happens when ShellExecuteW elevates from Explorer or a GUI app).
// It is a no-op when already running inside CMD or PowerShell.
func ensureConsole() {
	hw, _, _ := procGetConsoleWindow.Call()
	if hw != 0 {
		return // already have a console
	}
	procAllocConsole.Call()
	// Reattach Go's standard streams to the new console so log/fmt output is visible.
	if f, err := os.OpenFile("CONOUT$", os.O_RDWR, 0); err == nil {
		os.Stdout = f
		os.Stderr = f
		log.SetOutput(f) // redirect default logger to new console
	}
	if f, err := os.OpenFile("CONIN$", os.O_RDONLY, 0); err == nil {
		os.Stdin = f
	}
}

func registerPlatformFlags() {
	flagUpdate = flag.Bool("update", false, "In-place binary update without reinstall")
	flagConsole = flag.Bool("console", false, "Force interactive console mode")
	flagTray = flag.Bool("tray", false, "Run the system-tray status monitor (user session)")
	flagStatusWindow = flag.Bool("status-window", false, "Open the WebView2 status console (user session)")
}

func platformHandleFlags() bool {
	// UI modes run unprivileged in the user session and must be handled before
	// any elevation logic in platformPreStart.
	if *flagStatusWindow {
		runStatusWindow()
		return true
	}
	if *flagTray {
		runTray()
		return true
	}
	if *flagUpdate {
		if err := svcUpdate(); err != nil {
			fmt.Fprintf(os.Stderr, "update failed: %v\n", err)
			os.Exit(1)
		}
		return true
	}
	if !*flagConsole && isWindowsService() {
		if err := svcRun(); err != nil {
			log.Fatalf("[!] service run: %v", err)
		}
		return true
	}
	return false
}

func platformPreStart() {
	// Ensure a visible console exists before any output.
	// When the agent is spawned via ShellExecuteW (self-elevation from Explorer),
	// Windows may not attach a console automatically — AllocConsole() creates one.
	ensureConsole()

	if !isElevated() {
		log.Println("[!] Not running as Administrator — requesting UAC elevation...")
		if err := selfElevate(); err != nil {
			log.Printf("[!] UAC elevation failed: %v", err)
			log.Println("[!] Continuing without admin rights — some security checks may be limited.")
		} else {
			fmt.Println()
			fmt.Println("  BAS Agent — elevated instance is starting.")
			fmt.Println("  A new console window will appear momentarily.")
			fmt.Println("  (This window will close in 3 seconds.)")
			fmt.Println()
			time.Sleep(3 * time.Second)
			os.Exit(0)
		}
	}
	enablePrivileges()

	// Suppress system-generated interactive dialogs (WER, PCA, hung-app, GPF)
	// so that scenario steps never block waiting for human input.
	// All settings are reverted on clean shutdown via RestoreSystemDialogs().
	suppressSystemDialogs()

	// Startup integrity check — compare running binary against hash stored at install.
	if err := VerifyOwnIntegrity(); err != nil {
		log.Printf("[!] INTEGRITY: %v — server will be notified via heartbeat", err)
		// Do not abort: let the agent connect so the server can quarantine it.
		// Aborting silently is worse — it hides the compromise from the SOC.
	}
}

func platformPrintBannerExtras(_ Identity) {
	fmt.Printf("  Elevated  : %v\n", isElevated())
}

// platformRestoreOnShutdown reverts dialog suppression before the agent exits
// so the machine returns to normal Windows behaviour when BAS is not running.
func platformRestoreOnShutdown() {
	RestoreSystemDialogs()
}

// readEncryptedSecretPlatform returns the DPAPI-decrypted agent secret from registry.
func readEncryptedSecretPlatform() string {
	return ReadEncryptedSecret()
}
