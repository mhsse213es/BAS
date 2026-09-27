//go:build windows

package main

import (
	"os/exec"
)

// certDirPlatform is where the agent's CA root, own certificate, and
// private key are stored on Windows — separate from the DPAPI-encrypted
// registry storage used for the bootstrap AgentSecret (agent/config.go),
// since these are files a real TLS stack needs to read directly, not a
// single decrypted string.
func certDirPlatform() string {
	return `C:\ProgramData\Audspect\certs`
}

// hardenCertDirPlatform restricts the cert directory to SYSTEM and
// Administrators via icacls, matching how the rest of this codebase already
// shells out to Windows-native tools for privileged operations (see
// elevate.go, suppress_windows.go) rather than reimplementing Windows ACL
// APIs directly. Best-effort: a failure here is reported to the caller but
// does not prevent the key from being usable.
func hardenCertDirPlatform(dir string) error {
	cmd := exec.Command("icacls", dir,
		"/inheritance:r",
		"/grant:r", `SYSTEM:(OI)(CI)F`,
		"/grant:r", `*S-1-5-32-544:(OI)(CI)F`, // well-known SID for Administrators
	)
	return cmd.Run()
}
