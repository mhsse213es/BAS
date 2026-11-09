//go:build windows

package main

// Stray-process sweep: the end of a run stops what the run started and left running.
//
// Each step already runs inside a Job Object that is killed with the step. What escapes is anything started outside it
// (through WMI, a scheduled task, COM or a hijacked launcher). Such a process still shows on the screen: a calculator, a
// shell window, Explorer opening on something. So the start of a run records which processes exist, and the end stops
// those that are new AND demonstrably the run's:
//
//   - descended from the agent (every parent link is a live process created before its child); or
//   - an orphan of a well-known demo program (calc, notepad, a shell, a script host): its parent has exited, so nothing
//     the user did can have started it, since a user's programs are started by Explorer, which is alive.
//
// The shell, system processes and the agent's own programs are never stopped, whatever their parentage.

import (
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// procInfo is one running process.
type procInfo struct {
	PID, PPID uint32
	Created   uint64 // FILETIME; with the PID it identifies a process (PIDs are reused)
	Exe       string // base name
}

// procBaseline is the set of processes that existed when the run began: PID to creation time.
type procBaseline map[uint32]uint64

// Variables so tests can supply a process list and see what would be stopped.
var (
	listProcessesFn = realListProcesses
	terminateFn     = realTerminate
	agentPIDFn      = func() uint32 { return uint32(os.Getpid()) }
	selfExeName     = func() string {
		p, err := os.Executable()
		if err != nil {
			return ""
		}
		return filepath.Base(p)
	}
)

func realListProcesses() []procInfo {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	var out []procInfo
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		p := procInfo{PID: e.ProcessID, PPID: e.ParentProcessID, Exe: windows.UTF16ToString(e.ExeFile[:])}
		if h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, e.ProcessID); err == nil {
			var c, x, k, u windows.Filetime
			if windows.GetProcessTimes(h, &c, &x, &k, &u) == nil {
				p.Created = uint64(c.HighDateTime)<<32 | uint64(c.LowDateTime)
			}
			windows.CloseHandle(h)
		}
		out = append(out, p)
	}
	return out
}

func realTerminate(pid uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.TerminateProcess(h, 1)
}

func captureProcs() procBaseline {
	b := procBaseline{}
	for _, p := range listProcessesFn() {
		b[p.PID] = p.Created
	}
	return b
}

// neverStop are processes the sweep leaves alone whatever started them.
var neverStop = map[string]bool{
	"explorer.exe": true, "dwm.exe": true, "winlogon.exe": true, "csrss.exe": true, "wininit.exe": true,
	"lsass.exe": true, "services.exe": true, "smss.exe": true, "svchost.exe": true, "system": true, "registry": true,
	"sihost.exe": true, "ctfmon.exe": true, "fontdrvhost.exe": true, "runtimebroker.exe": true, "taskhostw.exe": true,
	"searchhost.exe": true, "startmenuexperiencehost.exe": true, "shellexperiencehost.exe": true,
	"textinputhost.exe": true, "applicationframehost.exe": true, "securityhealthsystray.exe": true,
	"audiodg.exe": true, "wmiprvse.exe": true, "spoolsv.exe": true, "conhost.exe": true, "msmpeng.exe": true,
	"nissrv.exe": true, "dllhost.exe": true, "taskmgr.exe": true,
}

// demoPrograms are what a test launches to show it ran. Only when orphaned are they stopped without ancestry.
var demoPrograms = map[string]bool{
	"calc.exe": true, "calculatorapp.exe": true, "win32calc.exe": true, "notepad.exe": true, "mspaint.exe": true,
	"wordpad.exe": true, "write.exe": true, "cmd.exe": true, "powershell.exe": true, "pwsh.exe": true,
	"powershell_ise.exe": true, "wscript.exe": true, "cscript.exe": true, "mshta.exe": true,
}

func isNew(base procBaseline, p procInfo) bool {
	c, had := base[p.PID]
	return !had || c != p.Created
}

// descendsFromAgent follows the parent links: each parent must be alive and older than its child, so a recycled PID
// cannot make an unrelated process look like the agent's.
func descendsFromAgent(byPID map[uint32]procInfo, p procInfo, agent uint32) bool {
	cur := p
	for depth := 0; depth < 32; depth++ {
		par, ok := byPID[cur.PPID]
		if !ok || par.Created > cur.Created {
			return false
		}
		if par.PID == agent {
			return true
		}
		cur = par
	}
	return false
}

func orphaned(byPID map[uint32]procInfo, p procInfo) bool {
	par, ok := byPID[p.PPID]
	return !ok || par.Created > p.Created
}

// sweepStrayProcesses stops what the run started and left behind, and returns one line per process stopped (or that
// could not be stopped, prefixed "restore incomplete:").
func sweepStrayProcesses(base procBaseline) []string {
	procs := listProcessesFn()
	byPID := make(map[uint32]procInfo, len(procs))
	for _, p := range procs {
		byPID[p.PID] = p
	}
	agent, self := agentPIDFn(), strings.ToLower(selfExeName())
	var out []string
	for _, p := range procs {
		name := strings.ToLower(p.Exe)
		if p.PID == agent || p.PID == 0 || neverStop[name] || (self != "" && name == self) || !isNew(base, p) {
			continue
		}
		if !descendsFromAgent(byPID, p, agent) && !(demoPrograms[name] && orphaned(byPID, p)) {
			continue
		}
		if err := terminateFn(p.PID); err != nil {
			out = append(out, "restore incomplete: could not stop "+p.Exe+" (pid "+itoa(p.PID)+") left by the run: "+err.Error())
			continue
		}
		out = append(out, "stray process stopped: "+p.Exe+" (pid "+itoa(p.PID)+")")
	}
	return out
}

func itoa(n uint32) string {
	if n == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
