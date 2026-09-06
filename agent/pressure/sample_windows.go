//go:build windows

package pressure

import (
	"fmt"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Separate lazy-DLL vars from agent/sysinfo_windows.go's netapi32 ones (that
// file is package main; this is a different package, so there's no actual
// naming collision, but kernel32/psapi are named distinctly here for clarity
// about which API each Proc belongs to.
var (
	pressureKernel32         = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalMemoryStatusEx = pressureKernel32.NewProc("GlobalMemoryStatusEx")
	procGetSystemTimes       = pressureKernel32.NewProc("GetSystemTimes")
	pressurePsapi            = windows.NewLazySystemDLL("psapi.dll")
	procGetProcessMemoryInfo = pressurePsapi.NewProc("GetProcessMemoryInfo")
)

// memoryStatusEx mirrors the Win32 MEMORYSTATUSEX struct (fields in its
// documented order and width). dwLength must be set to sizeof(this struct)
// before the call -- GlobalMemoryStatusEx validates it and fails otherwise.
type memoryStatusEx struct {
	dwLength                uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

// processMemoryCounters mirrors the Win32 PROCESS_MEMORY_COUNTERS struct.
// SIZE_T fields are pointer-width (8 bytes on the amd64 builds this agent
// ships); cb must be set to sizeof(this struct) before the call.
type processMemoryCounters struct {
	cb                         uint32
	_                          uint32 // padding to align the following uintptr fields on amd64
	PageFaultCount             uint32
	_                          uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

var (
	hostCPUMu                       sync.Mutex
	hostCPUPrevIdle, hostCPUPrevTot uint64
	hostCPUHasPrev                  bool
)

// SampleHost returns host-wide CPU and memory utilization as 0-100
// percentages. See package pressure's sample_<os>.go doc convention for the
// error contract (genuine failure or ErrNoBaseline on the first call).
func SampleHost() (cpuPercent, memPercent float64, err error) {
	var mem memoryStatusEx
	mem.dwLength = uint32(unsafe.Sizeof(mem))
	ret, _, callErr := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&mem)))
	if ret == 0 {
		return 0, 0, fmt.Errorf("GlobalMemoryStatusEx: %w", callErr)
	}
	// dwMemoryLoad is already "the approximate percentage of physical memory
	// in use", 0-100 -- Windows computes this for us, no division needed.
	memPercent = float64(mem.dwMemoryLoad)

	var idle, kernelT, userT windows.Filetime
	ret, _, callErr = procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&idle)),
		uintptr(unsafe.Pointer(&kernelT)),
		uintptr(unsafe.Pointer(&userT)),
	)
	if ret == 0 {
		return 0, 0, fmt.Errorf("GetSystemTimes: %w", callErr)
	}

	idleTicks := uint64(idle.Nanoseconds())
	// Windows' kernel time accounting INCLUDES idle time, so total busy+idle
	// time is kernel+user, not kernel+user+idle.
	totalTicks := uint64(kernelT.Nanoseconds()) + uint64(userT.Nanoseconds())

	hostCPUMu.Lock()
	defer hostCPUMu.Unlock()
	if !hostCPUHasPrev {
		hostCPUPrevIdle, hostCPUPrevTot = idleTicks, totalTicks
		hostCPUHasPrev = true
		return 0, 0, ErrNoBaseline
	}
	idleDelta := idleTicks - hostCPUPrevIdle
	totalDelta := totalTicks - hostCPUPrevTot
	hostCPUPrevIdle, hostCPUPrevTot = idleTicks, totalTicks

	if totalDelta == 0 {
		cpuPercent = 0
	} else {
		cpuPercent = 100 * (1 - float64(idleDelta)/float64(totalDelta))
	}
	return cpuPercent, memPercent, nil
}

var (
	selfCPUMu        sync.Mutex
	selfCPUPrevTicks uint64
	selfCPUPrevWall  time.Time
	selfCPUHasPrev   bool
)

// SampleSelf returns this agent process's own CPU and memory utilization.
// Attribution-only -- see the design spec's "Host vs. agent readings"; never
// fed into Controller.Observe.
func SampleSelf() (cpuPercent, memPercent float64, err error) {
	// Memory: GetProcessMemoryInfo gives our own working-set size; divide by
	// total physical memory (fetched fresh, independent of SampleHost's own
	// call -- these two functions must not share hidden state) for a percent.
	var mem memoryStatusEx
	mem.dwLength = uint32(unsafe.Sizeof(mem))
	ret, _, callErr := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&mem)))
	if ret == 0 {
		return 0, 0, fmt.Errorf("GlobalMemoryStatusEx: %w", callErr)
	}

	var counters processMemoryCounters
	counters.cb = uint32(unsafe.Sizeof(counters))
	ret, _, callErr = procGetProcessMemoryInfo.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&counters)),
		uintptr(counters.cb),
	)
	if ret == 0 {
		return 0, 0, fmt.Errorf("GetProcessMemoryInfo: %w", callErr)
	}
	if mem.ullTotalPhys > 0 {
		memPercent = 100 * float64(counters.WorkingSetSize) / float64(mem.ullTotalPhys)
	}

	// CPU: GetProcessTimes IS wrapped by x/sys/windows -- use it directly,
	// no raw syscall needed here.
	var creation, exit, kernelT, userT windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &creation, &exit, &kernelT, &userT); err != nil {
		return 0, 0, fmt.Errorf("GetProcessTimes: %w", err)
	}
	ticks := uint64(kernelT.Nanoseconds()) + uint64(userT.Nanoseconds())
	now := time.Now()

	// Wall-clock-normalized: process CPU-time consumed since the last sample,
	// divided by real elapsed wall-clock time (NOT an assumed fixed interval
	// -- this function has no idea how often its caller ticks), converts to a
	// percentage of one core.
	selfCPUMu.Lock()
	defer selfCPUMu.Unlock()
	if !selfCPUHasPrev {
		selfCPUPrevTicks = ticks
		selfCPUPrevWall = now
		selfCPUHasPrev = true
		return 0, 0, ErrNoBaseline
	}
	tickDelta := ticks - selfCPUPrevTicks
	wallDelta := now.Sub(selfCPUPrevWall)
	selfCPUPrevTicks = ticks
	selfCPUPrevWall = now

	if wallDelta <= 0 {
		cpuPercent = 0
	} else {
		cpuPercent = 100 * float64(tickDelta) / float64(wallDelta.Nanoseconds())
	}
	return cpuPercent, memPercent, nil
}
