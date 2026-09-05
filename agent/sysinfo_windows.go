//go:build windows

package main

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func getOSVersion() string {
	return fmt.Sprintf("Windows/%s (%s)", runtime.GOARCH, getWindowsVersion())
}

// getWindowsVersion returns the real Windows build version using
// RtlGetVersion, which bypasses the compatibility shim that makes
// older apps see Windows 8 on Windows 10/11.
func getWindowsVersion() string {
	v := windows.RtlGetVersion()
	return fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
}

// Separate lazy-DLL var name to avoid conflict with jobKernel32 in job_windows.go.
var (
	netapi32                  = windows.NewLazySystemDLL("netapi32.dll")
	procNetGetJoinInformation = netapi32.NewProc("NetGetJoinInformation")
	procNetApiBufferFree      = netapi32.NewProc("NetApiBufferFree")
)

// NetSetupDomainName is the BufferType value NetGetJoinInformation reports
// when the machine is joined to an Active Directory domain (as opposed to
// NetSetupUnjoined=1 or NetSetupWorkgroupName=2 for a workgroup machine).
const netSetupDomainName = 3

// getDomainJoined reports whether this Windows machine is domain-joined, via
// the standard NetGetJoinInformation Win32 API -- not wrapped by
// golang.org/x/sys/windows, so bound directly here, same pattern as
// SetInformationJobObject in job_windows.go. Returns nil only if the API call
// itself fails (rare — access-denied under unusual security policy, or a
// non-standard Windows edition); a genuine "not joined" answer is a real,
// non-nil false, not nil.
func getDomainJoined() *bool {
	var nameBuffer *uint16
	var bufferType uint32
	ret, _, _ := procNetGetJoinInformation.Call(
		0, // lpServer: nil = local computer
		uintptr(unsafe.Pointer(&nameBuffer)),
		uintptr(unsafe.Pointer(&bufferType)),
	)
	if nameBuffer != nil {
		defer procNetApiBufferFree.Call(uintptr(unsafe.Pointer(nameBuffer)))
	}
	if ret != 0 { // non-zero = NET_API_STATUS error code, not NERR_Success
		return nil
	}
	joined := bufferType == netSetupDomainName
	return &joined
}
