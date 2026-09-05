package main

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
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

// cmdTimeout bounds every external command snapshot/revert code runs. A var,
// not a const, so tests can shrink it to prove the timeout mechanism
// actually fires without waiting the real 10s.
var cmdTimeout = 10 * time.Second

// snapCmd runs a command with a bounded timeout and returns combined output.
func snapCmd(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}

// snapCmdRun runs a mutating command with the same bounded timeout as
// snapCmd, discarding output -- for revert operations where only
// success/failure matters. Every mutation in revertFromSnapshot must go
// through this, never raw exec.Command: revertFromSnapshot runs after every
// step has already reported completion but before submitResults (see
// runScenario in agent.go), so a hung command here strands the whole run at
// status 'running' forever even though every technique already finished.
func snapCmdRun(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Run()
}

// snapCmdRunStdin is snapCmdRun's counterpart for a command that reads its
// input from stdin (crontab -, iptables-restore) instead of args.
func snapCmdRunStdin(name string, stdin []byte, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	return cmd.Run()
}

// listCategoryPrefixes maps each SystemSnapshot.Lists category key to the
// normalized key prefix diffSnapshots emits. A given platform's snapshot only
// ever populates the categories its own captureSnapshot captures — entries
// for the other platform's categories are harmless no-ops here.
var listCategoryPrefixes = map[string]string{
	"tmp_files": "tmp:",
	"services":  "service:",
	"schtasks":  "schtask:",
	"startup":   "startup:",
	"cron_dirs": "cron:",

	// POSIX persistence surfaces. launch_items is the macOS analogue of
	// startup, systemd_units covers unit files on disk rather than only the
	// units currently loaded, and autostart is the Linux analogue of the
	// Windows Startup folder.
	"launch_items":  "launch:",
	"systemd_units": "unit:",
	"autostart":     "autostart:",
	"at_jobs":       "atjob:",
}

// diffSnapshots returns normalized keys for every item present in after but
// absent (or changed) from before, across every category both snapshots
// share: "tmp:<path>", "service:<name>", "schtask:<name>", "startup:<path>",
// "cron:<path>" (list categories, via listCategoryPrefixes), plus
// "registry:<key>\<value>" (Windows Run/RunOnce values, via diffRegistry) and
// whole-file keys unchanged from SystemSnapshot.Files (e.g. "crontab:user",
// "iptables", "/etc/hosts") whenever their content differs. Order is not
// significant to callers.
func diffSnapshots(before, after *SystemSnapshot) []string {
	var diff []string

	for category, items := range after.Lists {
		prefix, ok := listCategoryPrefixes[category]
		if !ok {
			continue
		}
		beforeSet := toSet(before.Lists[category])
		for _, item := range items {
			if !beforeSet[item] {
				diff = append(diff, prefix+item)
			}
		}
	}

	diff = append(diff, diffRegistry(before, after)...)

	for key, afterBlob := range after.Files {
		if strings.HasPrefix(key, "reg:") {
			continue // handled by diffRegistry above
		}
		// A key absent from before and present after is a CREATED artifact --
		// a dropped /etc/ld.so.preload, a planted authorized_keys, a new
		// LaunchAgent plist. Skipping those (the previous behaviour) meant a
		// run that leaked one still produced a clean cleanup verdict, because
		// the most dangerous case looked identical to no change at all.
		//
		// Removal is not the mirror of this: after.Files is what is iterated,
		// so a file that existed before and is gone now simply does not appear,
		// which is correct -- deleting a file is not leaving an artifact behind.
		if beforeBlob, ok := before.Files[key]; ok && bytes.Equal(beforeBlob, afterBlob) {
			continue
		}
		diff = append(diff, key)
	}

	return diff
}
