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
	jobKernel32                 = windows.NewLazySystemDLL("kernel32.dll")
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

// terminateStepJob immediately terminates every process in the job, then
// always also sweeps by PID via killProcessTree. The PID sweep is not
// redundant: TerminateJobObject only reaches processes actually inside the
// job, and a process can end up outside it two ways -- the job assignment
// itself failed (newStepJob logs "timeout will only kill direct child" and
// returns job=0, e.g. because the target was already in a different job,
// which real-world apps like Chrome commonly are for their own sandboxing),
// or a child process used CREATE_BREAKAWAY_FROM_JOB to opt out after a
// successful assignment. Either way, pid is the one thing we always have --
// walking the live process tree from it catches what the job could not.
// Called from the context-watcher goroutine when a step times out or is
// cancelled. After this call, cmd.Wait() returns quickly because the main
// process is dead.
func terminateStepJob(job uintptr, pid int) {
	if job != 0 {
		if err := windows.TerminateJobObject(windows.Handle(job), 1); err != nil {
			log.Printf("[job] TerminateJobObject: %v", err)
		}
	}
	killProcessTree(uint32(pid))
}

// killProcessTree force-terminates pid and every one of its descendant
// processes (any depth), walking the live process table directly -- entirely
// independent of Job Objects, so it still works when a process could not be
// (or no longer is) job-assigned. Safe to call on PIDs that have already
// exited: OpenProcess simply fails for them and they're skipped.
func killProcessTree(pid uint32) {
	snap, err := windows.CreateToolhelp32Snapshot(th32csSnapProcess, 0)
	if err != nil {
		log.Printf("[job] killProcessTree: snapshot: %v", err)
		return
	}
	defer windows.CloseHandle(snap)

	parentOf := make(map[uint32]uint32, 128)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	for err = windows.Process32First(snap, &entry); err == nil; err = windows.Process32Next(snap, &entry) {
		parentOf[entry.ProcessID] = entry.ParentProcessID
	}

	// BFS out from pid to every descendant, any depth.
	toKill := map[uint32]bool{pid: true}
	for changed := true; changed; {
		changed = false
		for candidate, parent := range parentOf {
			if toKill[parent] && !toKill[candidate] {
				toKill[candidate] = true
				changed = true
			}
		}
	}

	killed := 0
	for target := range toKill {
		ph, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, target)
		if err != nil {
			continue // already exited, or access denied — nothing more we can do
		}
		windows.TerminateProcess(ph, 1)
		windows.CloseHandle(ph)
		killed++
	}
	if killed > 0 {
		log.Printf("[job] killProcessTree: terminated %d process(es) rooted at pid=%d", killed, pid)
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
