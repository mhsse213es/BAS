//go:build linux

package pressure

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// readProcStatCPU reads the first "cpu " line of /proc/stat and returns
// (idleTicks, totalTicks) in kernel jiffies. Format: "cpu  user nice system
// idle iowait irq softirq steal guest guest_nice" (all fields after "cpu" are
// space-separated integers; iowait counts as idle for our purposes, matching
// the standard convention used by tools like `top`).
func readProcStatCPU() (idle, total uint64, err error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return 0, 0, sc.Err()
	}
	fields := strings.Fields(sc.Text()) // ["cpu", "user", "nice", "system", "idle", "iowait", ...]
	var vals []uint64
	for _, f := range fields[1:] {
		v, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			break // stop at the first non-numeric field; we only need the first 5
		}
		vals = append(vals, v)
	}
	if len(vals) < 4 {
		return 0, 0, errShortProcStat
	}
	user, nice, system, idleField := vals[0], vals[1], vals[2], vals[3]
	iowait := uint64(0)
	if len(vals) > 4 {
		iowait = vals[4]
	}
	idle = idleField + iowait
	total = user + nice + system + idle
	if len(vals) > 5 {
		for _, v := range vals[5:] {
			total += v
		}
	}
	return idle, total, nil
}

// readProcMeminfoPercent reads /proc/meminfo and returns used-memory percent
// as 100*(1 - MemAvailable/MemTotal). MemAvailable (not MemFree) is the
// kernel's own "how much could actually be given to a new process without
// swapping" estimate -- using MemFree alone would overcount page-cache memory
// as "used" when it is in fact readily reclaimable.
func readProcMeminfoPercent() (float64, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	var total, available uint64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			total = parseMeminfoKB(line)
		case strings.HasPrefix(line, "MemAvailable:"):
			available = parseMeminfoKB(line)
		}
	}
	if total == 0 {
		return 0, errShortProcMeminfo
	}
	return 100 * (1 - float64(available)/float64(total)), nil
}

// parseMeminfoKB extracts the numeric kB value from a "Key:   12345 kB" line.
func parseMeminfoKB(line string) uint64 {
	fields := strings.Fields(line) // ["MemTotal:", "12345", "kB"]
	if len(fields) < 2 {
		return 0
	}
	v, _ := strconv.ParseUint(fields[1], 10, 64)
	return v
}

var (
	hostCPUMu                       sync.Mutex
	hostCPUPrevIdle, hostCPUPrevTot uint64
	hostCPUHasPrev                  bool
)

func SampleHost() (cpuPercent, memPercent float64, err error) {
	memPercent, err = readProcMeminfoPercent()
	if err != nil {
		return 0, 0, err
	}

	idle, total, err := readProcStatCPU()
	if err != nil {
		return 0, 0, err
	}

	hostCPUMu.Lock()
	defer hostCPUMu.Unlock()
	if !hostCPUHasPrev {
		hostCPUPrevIdle, hostCPUPrevTot = idle, total
		hostCPUHasPrev = true
		return 0, 0, ErrNoBaseline
	}
	idleDelta := idle - hostCPUPrevIdle
	totalDelta := total - hostCPUPrevTot
	hostCPUPrevIdle, hostCPUPrevTot = idle, total

	if totalDelta == 0 {
		cpuPercent = 0
	} else {
		cpuPercent = 100 * (1 - float64(idleDelta)/float64(totalDelta))
	}
	return cpuPercent, memPercent, nil
}

// readProcSelfStatCPU reads utime+stime (fields 14 and 15, 1-indexed) from
// /proc/self/stat, in clock ticks. The process comm field (field 2) is
// parenthesized and may itself contain spaces or parens, so this splits on
// the LAST ')' rather than naively using strings.Fields on the whole line.
func readProcSelfStatCPU() (ticks uint64, err error) {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, err
	}
	line := string(data)
	closeParen := strings.LastIndexByte(line, ')')
	if closeParen == -1 || closeParen+2 >= len(line) {
		return 0, errShortProcSelfStat
	}
	rest := strings.Fields(line[closeParen+2:]) // fields from index 3 (state) onward
	// rest[0] = state (field 3), so utime is rest[10] (field 14), stime is rest[11] (field 15).
	if len(rest) < 12 {
		return 0, errShortProcSelfStat
	}
	utime, err1 := strconv.ParseUint(rest[10], 10, 64)
	stime, err2 := strconv.ParseUint(rest[11], 10, 64)
	if err1 != nil || err2 != nil {
		return 0, errShortProcSelfStat
	}
	return utime + stime, nil
}

// readProcSelfVmRSSKB reads VmRSS from /proc/self/status, in KB.
func readProcSelfVmRSSKB() (uint64, error) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "VmRSS:") {
			return parseMeminfoKB(line), nil
		}
	}
	return 0, errShortProcSelfStatus
}

const clockTicksPerSec = 100 // USER_HZ -- standard on every mainstream Linux distro this agent targets

var (
	selfCPUMu        sync.Mutex
	selfCPUPrevTicks uint64
	selfCPUPrevWall  time.Time
	selfCPUHasPrev   bool
)

func SampleSelf() (cpuPercent, memPercent float64, err error) {
	rssKB, err := readProcSelfVmRSSKB()
	if err != nil {
		return 0, 0, err
	}
	totalKB, err := readProcMeminfoTotalKB()
	if err != nil {
		return 0, 0, err
	}
	if totalKB > 0 {
		memPercent = 100 * float64(rssKB) / float64(totalKB)
	}

	ticks, err := readProcSelfStatCPU()
	if err != nil {
		return 0, 0, err
	}
	now := time.Now()

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
		secondsOfCPU := float64(tickDelta) / float64(clockTicksPerSec)
		cpuPercent = 100 * secondsOfCPU / wallDelta.Seconds()
	}
	return cpuPercent, memPercent, nil
}

// readProcMeminfoTotalKB reads just MemTotal from /proc/meminfo, for
// converting SampleSelf's absolute RSS reading into a percentage.
func readProcMeminfoTotalKB() (uint64, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			return parseMeminfoKB(line), nil
		}
	}
	return 0, errShortProcMeminfo
}
