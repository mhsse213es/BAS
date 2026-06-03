//go:build windows

package main

import (
	"fmt"
	"log"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Separate lazy-DLL var name to avoid conflict with modKernel32 in suppress_windows.go.
var (
	jobKernel32                = windows.NewLazySystemDLL("kernel32.dll")
	procSetInformationJobObject = jobKernel32.NewProc("SetInformationJobObject")
)

// ── Job Object structures ──────────────────────────────────────────────────────
//
// These mirror the Windows SDK JOBOBJECT_EXTENDED_LIMIT_INFORMATION layout for
// 64-bit processes (amd64 only — the only platform we target for Windows).
// Field offsets verified against the SDK; total size = 144 bytes.

type jobBasicLimitInfo struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	_                       [4]byte // alignment pad before uintptr fields
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	_                       [4]byte // alignment pad before Affinity (uintptr)
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type jobIOCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type jobExtendedLimitInfo struct {
	BasicLimitInformation jobBasicLimitInfo
	IoInfo                jobIOCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

const (
	// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: when all handles to the Job are closed,
	// every process still in the job is terminated by the kernel automatically.
	// This is the safety-net that fires if the agent crashes before it can call
	// TerminateJobObject explicitly.
	jobLimitKillOnClose = uint32(0x00002000)

	// JobObjectExtendedLimitInformation class ID for SetInformationJobObject.
	jobExtLimitClass = uint32(9)
)

// newStepJob creates an anonymous Job Object, sets JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
// and assigns the process identified by pid into it.
//
// Returns the Job handle (non-zero on success) or (0, error) if anything fails.
// The caller is responsible for calling closeStepJob when the step finishes.
func newStepJob(pid int) (uintptr, error) {
	// Create an anonymous Job Object (no name → not inheritable from outside).
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("CreateJobObject: %w", err)
	}

	// Set KILL_ON_JOB_CLOSE so processes are cleaned up even if we crash.
	info := jobExtendedLimitInfo{}
	info.BasicLimitInformation.LimitFlags = jobLimitKillOnClose
	ret, _, apiErr := procSetInformationJobObject.Call(
		uintptr(job),
		uintptr(jobExtLimitClass),
		uintptr(unsafe.Pointer(&info)),
		uintptr(unsafe.Sizeof(info)),
	)
	if ret == 0 {
		windows.CloseHandle(job)
		return 0, fmt.Errorf("SetInformationJobObject: %w", apiErr)
	}

	// Open a handle to the target process.
	ph, err := windows.OpenProcess(
		windows.PROCESS_TERMINATE|windows.PROCESS_SET_QUOTA,
		false,
		uint32(pid),
	)
	if err != nil {
		windows.CloseHandle(job)
		return 0, fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(ph)

	// Assign the process to the job.
	// This fails if the process is already in a different job (Windows < 8).
	// Windows 8+ supports nested jobs; if this still fails, log and continue.
	if err := windows.AssignProcessToJobObject(job, ph); err != nil {
		windows.CloseHandle(job)
		return 0, fmt.Errorf("AssignProcessToJobObject: %w", err)
	}

	return uintptr(job), nil
}

// terminateStepJob immediately terminates every process in the job.
// Called from the context-watcher goroutine when a step times out or is cancelled.
// After this call, cmd.Wait() returns quickly because the main process is dead.
func terminateStepJob(job uintptr) {
	if job == 0 {
		return
	}
	if err := windows.TerminateJobObject(windows.Handle(job), 1); err != nil {
		log.Printf("[job] TerminateJobObject: %v", err)
	}
}

// closeStepJob closes the Job Object handle.
// Because of KILL_ON_JOB_CLOSE, this terminates any processes that are still
// alive in the job at the moment the last handle is closed.
func closeStepJob(job uintptr) {
	if job == 0 {
		return
	}
	windows.CloseHandle(windows.Handle(job))
}
