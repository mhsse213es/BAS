//go:build darwin

package pressure

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// sysctlUint64 shells out to `sysctl -n <name>` and parses the result as a
// uint64. Matches sysinfo_darwin.go's existing exec.Command("sw_vers", ...)
// shell-out precedent -- macOS has no cleaner dependency-free path.
func sysctlUint64(name string) (uint64, error) {
	out, err := exec.Command("sysctl", "-n", name).Output()
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
}

// vmStatPageSizeAndFree runs `vm_stat` and returns (pageSizeBytes, freePages).
// vm_stat's first line is "Mach Virtual Memory Statistics: (page size of
// 4096 bytes)"; subsequent lines are "Pages free:    12345." (note the
// trailing period, which must be stripped before parsing).
func vmStatPageSizeAndFree() (pageSize uint64, freePages uint64, err error) {
	out, err := exec.Command("vm_stat").Output()
	if err != nil {
		return 0, 0, err
	}
	lines := strings.Split(string(out), "\n")
	if len(lines) == 0 {
		return 0, 0, errShortVMStat
	}
	// First line: "Mach Virtual Memory Statistics: (page size of 4096 bytes)"
	first := lines[0]
	const marker = "page size of "
	idx := strings.Index(first, marker)
	if idx == -1 {
		return 0, 0, errShortVMStat
	}
	rest := first[idx+len(marker):]
	end := strings.Index(rest, " ")
	if end == -1 {
		return 0, 0, errShortVMStat
	}
	pageSize, err = strconv.ParseUint(rest[:end], 10, 64)
	if err != nil {
		return 0, 0, errShortVMStat
	}

	for _, line := range lines[1:] {
		if strings.HasPrefix(line, "Pages free:") {
			val := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "Pages free:"), "."))
			freePages, err = strconv.ParseUint(val, 10, 64)
			if err != nil {
				return 0, 0, errShortVMStat
			}
			return pageSize, freePages, nil
		}
	}
	return 0, 0, errShortVMStat
}

func hostMemPercent() (float64, error) {
	total, err := sysctlUint64("hw.memsize")
	if err != nil || total == 0 {
		return 0, errShortVMStat
	}
	pageSize, freePages, err := vmStatPageSizeAndFree()
	if err != nil {
		return 0, err
	}
	freeBytes := pageSize * freePages
	return 100 * (1 - float64(freeBytes)/float64(total)), nil
}

// hostCPUPercentFromTop shells out to `top -l 1 -n 0`, which prints one
// sample and no process rows (-n 0), and parses its "CPU usage: 12.34% user,
// 5.67% sys, 81.99% idle" summary line -- this is a single instantaneous
// OS-computed reading (top does its own internal delta), so unlike the
// Windows/Linux host CPU functions, this does NOT need this package's own
// two-call delta/ErrNoBaseline handling for the HOST cpu number specifically.
func hostCPUPercentFromTop() (float64, error) {
	out, err := exec.Command("top", "-l", "1", "-n", "0").Output()
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(line, "CPU usage:") {
			continue
		}
		// "CPU usage: 12.34% user, 5.67% sys, 81.99% idle"
		fields := strings.Split(line, ",")
		for _, f := range fields {
			f = strings.TrimSpace(f)
			if strings.HasSuffix(f, "idle") {
				pctStr := strings.TrimSuffix(strings.Fields(f)[0], "%")
				idle, err := strconv.ParseFloat(pctStr, 64)
				if err != nil {
					return 0, errShortTop
				}
				return 100 - idle, nil
			}
		}
	}
	return 0, errShortTop
}

// SampleHost returns host-wide CPU and memory utilization as 0-100
// percentages. Unlike Windows/Linux, `top`'s single-shot summary is already
// delta-computed by the OS, so this never returns ErrNoBaseline for CPU --
// only a genuine command-execution or parse failure produces a non-nil error.
func SampleHost() (cpuPercent, memPercent float64, err error) {
	memPercent, err = hostMemPercent()
	if err != nil {
		return 0, 0, err
	}
	cpuPercent, err = hostCPUPercentFromTop()
	if err != nil {
		return 0, 0, err
	}
	return cpuPercent, memPercent, nil
}

// SampleSelf shells out to `ps -o rss=,%cpu= -p <pid>` for this process,
// which gives both this process's RSS (KB) and an OS-computed %CPU (already
// normalized as "percent of one core" by ps) in a single call -- no manual
// delta or ErrNoBaseline handling needed here either, matching the host
// function's rationale above.
func SampleSelf() (cpuPercent, memPercent float64, err error) {
	pid := os.Getpid()
	out, err := exec.Command("ps", "-o", "rss=,%cpu=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return 0, 0, err
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) != 2 {
		return 0, 0, errShortPS
	}
	rssKB, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, 0, errShortPS
	}
	cpuPercent, err = strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return 0, 0, errShortPS
	}

	total, err := sysctlUint64("hw.memsize")
	if err != nil || total == 0 {
		return 0, 0, errShortVMStat
	}
	memPercent = 100 * (rssKB * 1024) / float64(total)
	return cpuPercent, memPercent, nil
}
