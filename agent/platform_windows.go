//go:build windows

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

var (
	flagUpdate  *bool
	flagConsole *bool
)

func registerPlatformFlags() {
	flagUpdate = flag.Bool("update", false, "In-place binary update without reinstall")
	flagConsole = flag.Bool("console", false, "Force interactive console mode")
}

func platformHandleFlags() bool {
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
	if !isElevated() {
		log.Println("[!] Not running as Administrator — attempting UAC elevation...")
		if err := selfElevate(); err != nil {
			log.Printf("[!] UAC elevation failed: %v", err)
			log.Println("[!] Some checks will be skipped without admin rights.")
		} else {
			os.Exit(0)
		}
	}
	enablePrivileges()

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

// readEncryptedSecretPlatform returns the DPAPI-decrypted agent secret from registry.
func readEncryptedSecretPlatform() string {
	return ReadEncryptedSecret()
}
