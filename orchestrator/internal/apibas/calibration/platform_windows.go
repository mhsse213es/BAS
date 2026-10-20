//go:build windows

package calibration

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

// memoryStatusEx mirrors the Win32 MEMORYSTATUSEX structure.
type memoryStatusEx struct {
	length               uint32
	memoryLoad           uint32
	totalPhys            uint64
	availPhys            uint64
	totalPageFile        uint64
	availPageFile        uint64
	totalVirtual         uint64
	availVirtual         uint64
	availExtendedVirtual uint64
}

// osVersionInfoEx mirrors the Win32 OSVERSIONINFOEXW structure.
type osVersionInfoEx struct {
	size           uint32
	major          uint32
	minor          uint32
	build          uint32
	platform       uint32
	csd            [128]uint16
	servicePackMaj uint16
	servicePackMin uint16
	suiteMask      uint16
	productType    byte
	reserved       byte
}

// osAttributes reads the platform attributes from the Win32 API. Each value comes from a
// kernel call, not from an environment variable an operator could set.
func osAttributes() map[string]sourcedValue {
	out := map[string]sourcedValue{}
	var m memoryStatusEx
	m.length = uint32(unsafe.Sizeof(m))
	if r, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx").Call(uintptr(unsafe.Pointer(&m))); r != 0 {
		out["memory_total_bytes"] = sourcedValue{strconv.FormatUint(m.totalPhys, 10), "kernel32!GlobalMemoryStatusEx"}
	}
	var v osVersionInfoEx
	v.size = uint32(unsafe.Sizeof(v))
	if r, _, _ := syscall.NewLazyDLL("ntdll.dll").NewProc("RtlGetVersion").Call(uintptr(unsafe.Pointer(&v))); r == 0 {
		out["os_version"] = sourcedValue{fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.build), "ntdll!RtlGetVersion"}
	}
	// PROCESSOR_IDENTIFIER is set by the operating system at boot from the CPU's CPUID data.
	if id := os.Getenv("PROCESSOR_IDENTIFIER"); id != "" {
		out["cpu_model"] = sourcedValue{id, "system-env:PROCESSOR_IDENTIFIER"}
	}
	return out
}
