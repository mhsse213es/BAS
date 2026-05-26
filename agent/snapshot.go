package main

import (
	"context"
	"os/exec"
	"time"
)

// SystemSnapshot holds a point-in-time capture of OS state that techniques
// commonly modify: temp files, scheduled tasks/cron, services, persistence
// registry keys, firewall rules, and sensitive config files.
type SystemSnapshot struct {
	RunID   string
	TakenAt time.Time
	Lists   map[string][]string // category → items present at snapshot time
	Files   map[string][]byte   // path (or logical key) → content at snapshot time
}

func newSnapshot(runID string) *SystemSnapshot {
	return &SystemSnapshot{
		RunID:   runID,
		TakenAt: time.Now(),
		Lists:   make(map[string][]string),
		Files:   make(map[string][]byte),
	}
}

// toSet converts a slice to a membership map for O(1) lookup.
func toSet(items []string) map[string]bool {
	s := make(map[string]bool, len(items))
	for _, v := range items {
		s[v] = true
	}
	return s
}

// snapCmd runs a command with a 10-second timeout and returns combined output.
func snapCmd(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}
