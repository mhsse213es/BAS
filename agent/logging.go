package main

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
)

// The agent previously logged only to its console window (lost on reboot) and to
// the server (lost while disconnected). This file adds a persistent local log so
// the agent leaves a diagnosable trail across reboots and outages.

const (
	logFileName = "agent.log"
	maxLogBytes = 8 << 20 // rotate to agent.log.1 once the file exceeds 8 MiB
	// logKeepRotated is how many rotated logs (agent.log.1 ... agent.log.N) are kept; older ones are deleted.
	logKeepRotated = 5
)

// initFileLogging tees the standard logger to a persistent file (in addition to
// stdout) at the first writable location. Returns the log path, or "" if none was
// writable (in which case logging stays console-only).
func initFileLogging() string {
	for _, dir := range logDirCandidates() {
		if f, err := openLogFileIn(dir); err == nil {
			log.SetOutput(teeWriter(os.Stdout, f))
			return filepath.Join(dir, logFileName)
		}
	}
	return ""
}

// bestEffortWriter wraps a writer so its own write failures can never
// suppress writes to whatever else shares an io.MultiWriter with it --
// io.MultiWriter.Write aborts the entire chain the instant any one writer
// returns an error, without attempting the writers after it. See
// teeWriter's doc comment for why that matters here.
type bestEffortWriter struct{ w io.Writer }

func (b bestEffortWriter) Write(p []byte) (int, error) {
	b.w.Write(p) //nolint:errcheck // intentionally ignored -- see type doc comment
	return len(p), nil
}

// teeWriter builds the writer initFileLogging installs as the log package's
// output. console must never be able to suppress writes to file -- file is
// the durable record operators and support actually rely on, while console
// is best-effort and unreliable in some run modes.
//
// A Windows service normally runs in Session 0 with no console attached, so
// os.Stdout can be an invalid handle whose Write always errors. Before this
// fix, console was passed to io.MultiWriter unwrapped and listed first: the
// very first log.Printf after initFileLogging's own line (which happens to
// run before that failure mode was ever exercised) would hit the broken
// stdout, MultiWriter would abort the chain right there, and the file write
// behind it in the chain never ran -- for the rest of that process's life.
// This is exactly what made a real agent's persistent log file capture only
// ever one line, across months of restarts, while the identical binary run
// interactively (a real console attached) logged everything correctly: the
// only difference between those two runs was whether stdout worked.
func teeWriter(console, file io.Writer) io.Writer {
	return io.MultiWriter(bestEffortWriter{console}, file)
}

// logDirCandidates lists log directories in preference order: the platform's fixed agent log folder
// (agentLogDir, the same on every install so operators know where to look), then a "logs" folder next to
// the executable, then a per-user config dir (an unprivileged tray or status process cannot write the first
// two), then the OS temp dir as a last resort.
func logDirCandidates() []string {
	dirs := []string{agentLogDir()}
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Join(filepath.Dir(exe), "logs"))
	}
	if cfg, err := os.UserConfigDir(); err == nil {
		dirs = append(dirs, filepath.Join(cfg, "BASAgent", "logs"))
	}
	dirs = append(dirs, filepath.Join(os.TempDir(), "BASAgent"))
	return dirs
}

// openLogFileIn creates dir if needed and opens dir/agent.log for appending. If
// the existing file already exceeds maxLogBytes it is rotated to agent.log.1
// first so the active log stays bounded.
func openLogFileIn(dir string) (*os.File, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, logFileName)
	if fi, err := os.Stat(path); err == nil && fi.Size() > maxLogBytes {
		rotateLog(path, logKeepRotated)
	}
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
}

// rotateLog shifts path.1 ... path.(keep-1) up by one, drops the oldest, and moves path to path.1.
func rotateLog(path string, keep int) {
	_ = os.Remove(path + "." + strconv.Itoa(keep))
	for n := keep - 1; n >= 1; n-- {
		_ = os.Rename(path+"."+strconv.Itoa(n), path+"."+strconv.Itoa(n+1))
	}
	_ = os.Rename(path, path+".1")
}
