//go:build windows

package main

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/windows"
)

// getWindowsVersion mirrors agent/sysinfo_windows.go's getWindowsVersion
// exactly -- RtlGetVersion bypasses the compatibility shim that makes older
// apps see a wrong version on newer Windows; here it correctly reports the
// real legacy build number (e.g. 6.1.7601 for Windows 7 SP1).
func getWindowsVersion() string {
	v := windows.RtlGetVersion()
	return fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
}

func getOSVersion() string {
	return fmt.Sprintf("Windows/%s (%s)", runtime.GOARCH, getWindowsVersion())
}
