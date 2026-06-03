//go:build windows

package main

import "os"

// logDir returns the platform log directory.
// Uses C:\ProgramData\BASAgent\logs — writable by SYSTEM, visible to Administrators.
func logDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return base + `\BASAgent\logs`
}
