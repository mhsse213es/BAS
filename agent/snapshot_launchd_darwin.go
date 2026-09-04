//go:build darwin

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// macOS-specific snapshot coverage.
//
// This closes the largest hole in cleanup verification anywhere in the agent.
// The shared POSIX snapshot is Linux-shaped -- it drives systemctl, iptables
// and /etc/rc.local, none of which exist here -- so on a Mac it captured the
// user crontab, /tmp, /etc/hosts and a few shell rc files, and nothing else.
// launchd, which is how essentially all macOS persistence is established, was
// not looked at. A run that dropped a LaunchAgent plist and left it behind
// produced a clean cleanup verdict.

// posixHomeContainer and posixExtraHomes tell the shared capture where user
// home directories live on this platform.
const posixHomeContainer = "/Users"

var posixExtraHomes = []string{"/var/root"}

// systemLaunchDirs run as root at boot (LaunchDaemons) or for every user at
// login (LaunchAgents).
var systemLaunchDirs = []string{
	"/Library/LaunchDaemons",
	"/Library/LaunchAgents",
	"/System/Library/LaunchAgents",
	"/System/Library/LaunchDaemons",
}

// capturePlatformExtras records every launch item on the host.
func capturePlatformExtras(s *SystemSnapshot) {
	for _, dir := range systemLaunchDirs {
		collectLaunchItems(s, dir)
	}
	// Per-user agents need no privilege to install and run at that user's login.
	for _, home := range homeDirsUnder(posixHomeContainer, posixExtraHomes...) {
		collectLaunchItems(s, filepath.Join(home, "Library", "LaunchAgents"))
	}
}

// collectLaunchItems appends one directory's plists to the snapshot. A missing
// directory is not an error; several of these are absent on any given Mac.
func collectLaunchItems(s *SystemSnapshot, dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".plist") {
			continue
		}
		s.Lists["launch_items"] = append(s.Lists["launch_items"], filepath.Join(dir, e.Name()))
	}
}

// revertPlatformExtras removes launch items the run created.
//
// Only plists absent from the snapshot are touched, so nothing that was already
// on the Mac is removed. Each is unloaded before deletion: a job started from
// the dropped plist keeps running otherwise, and deleting the file alone would
// leave the process behind while making it harder to find.
//
// Apple's own directories under /System are captured so that a plist appearing
// there is visible in the diff, but they are SIP-protected -- the removal will
// simply fail, which is the correct outcome rather than something to work
// around.
func revertPlatformExtras(s *SystemSnapshot) []string {
	var reverted []string

	original := toSet(s.Lists["launch_items"])
	after := newSnapshot(s.RunID)
	capturePlatformExtras(after)

	for _, path := range after.Lists["launch_items"] {
		if original[path] {
			continue
		}
		// bootout is the modern unload; the older form is tried as a fallback
		// so this works across the releases the agent ships to.
		exec.Command("launchctl", "bootout", "system", path).Run() //nolint:errcheck
		exec.Command("launchctl", "unload", "-w", path).Run()      //nolint:errcheck
		if os.Remove(path) == nil {
			reverted = append(reverted, "launch item removed: "+path)
		}
	}

	return reverted
}
