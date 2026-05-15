//go:build windows

package main

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// getWindowsVersion returns the real Windows build version using
// RtlGetVersion, which bypasses the compatibility shim that makes
// older apps see Windows 8 on Windows 10/11.
func getWindowsVersion() string {
	v := windows.RtlGetVersion()
	return fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
}
