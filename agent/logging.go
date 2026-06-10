package main

import (
	"io"
	"log"
	"os"
	"path/filepath"
)

// The agent previously logged only to its console window (lost on reboot) and to
// the server (lost while disconnected). This file adds a persistent local log so
// the agent leaves a diagnosable trail across reboots and outages.

const (
	logFileName = "agent.log"
	maxLogBytes = 8 << 20 // rotate to agent.log.1 once the file exceeds 8 MiB
)

// initFileLogging tees the standard logger to a persistent file (in addition to
// stdout) at the first writable location. Returns the log path, or "" if none was
// writable (in which case logging stays console-only).
func initFileLogging() string {
	for _, dir := range logDirCandidates() {
		if f, err := openLogFileIn(dir); err == nil {
			log.SetOutput(io.MultiWriter(os.Stdout, f))
			return filepath.Join(dir, logFileName)
		}
	}
	return ""
}

// logDirCandidates lists log directories in preference order: a "logs" folder
// next to the executable (most discoverable — where operators look), then a
// per-user config dir, then the OS temp dir as a last resort.
func logDirCandidates() []string {
	var dirs []string
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
		_ = os.Rename(path, path+".1")
	}
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
}
