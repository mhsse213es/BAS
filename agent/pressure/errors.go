package pressure

import "errors"

// ErrNoBaseline is returned by a sample_<os>.go sampling function on its very
// first call in this process: CPU utilization needs a delta between two
// syscalls (or two /proc reads, or two shell-outs), and the first call has
// nothing to diff against yet. This is an error, never a real-looking
// (0, 0, nil), specifically so callers' ordinary skip-this-tick-on-error
// handling takes care of it automatically -- see agent/pressure_loop.go.
var ErrNoBaseline = errors.New("pressure: no baseline sample yet")

var (
	errShortProcStat       = errors.New("pressure: /proc/stat: unexpected format")
	errShortProcMeminfo    = errors.New("pressure: /proc/meminfo: MemTotal not found")
	errShortProcSelfStat   = errors.New("pressure: /proc/self/stat: unexpected format")
	errShortProcSelfStatus = errors.New("pressure: /proc/self/status: VmRSS not found")
)

var (
	errShortVMStat = errors.New("pressure: vm_stat/sysctl: unexpected output")
	errShortTop    = errors.New("pressure: top: unexpected output")
	errShortPS     = errors.New("pressure: ps: unexpected output")
)
