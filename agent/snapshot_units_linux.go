//go:build linux

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Linux-specific snapshot coverage.
//
// The shared POSIX snapshot lists systemd units that are LOADED. That misses
// the case that matters most for cleanup verification: a unit file dropped on
// disk and not yet started is invisible to `systemctl list-units`, so a run
// that leaves one behind produced a clean verdict. The same is true of a timer
// file, an XDG autostart entry, and /etc/ld.so.preload -- none of which the
// snapshot looked at before.

// posixHomeContainer and posixExtraHomes tell the shared capture where user
// home directories live on this platform.
const posixHomeContainer = "/home"

var posixExtraHomes = []string{"/root"}

// systemdUnitFileDirs are searched for unit FILES rather than loaded units.
// The user directory is included because a unit there needs no privilege to
// install and still runs at every login.
var systemdUnitFileDirs = []string{
	"/etc/systemd/system",
	"/run/systemd/system",
	"/usr/local/lib/systemd/system",
}

// autostartDirs are the Linux analogue of the Windows Startup folder, which
// the Windows snapshot has always captured and this one did not.
var autostartDirs = []string{"/etc/xdg/autostart"}

// unitFileSuffixes are the unit types worth tracking as persistence.
var unitFileSuffixes = []string{".service", ".timer", ".socket", ".path"}

func isUnitFile(name string) bool {
	for _, s := range unitFileSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// capturePlatformExtras adds the Linux persistence surfaces to a snapshot.
func capturePlatformExtras(s *SystemSnapshot) {
	for _, dir := range systemdUnitFileDirs {
		collectInto(s, "systemd_units", dir, isUnitFile)
	}
	// Per-user units install without privilege and run at login.
	for _, home := range homeDirsUnder(posixHomeContainer, posixExtraHomes...) {
		collectInto(s, "systemd_units", filepath.Join(home, ".config", "systemd", "user"), isUnitFile)
	}

	for _, dir := range autostartDirs {
		collectInto(s, "autostart", dir, nil)
	}
	for _, home := range homeDirsUnder(posixHomeContainer, posixExtraHomes...) {
		collectInto(s, "autostart", filepath.Join(home, ".config", "autostart"), nil)
	}

	// ld.so.preload injects a library into every dynamically linked process on
	// the host. It usually does not exist, which is exactly why its creation
	// has to be detectable -- see the created-file handling in diffSnapshots.
	if content, err := os.ReadFile("/etc/ld.so.preload"); err == nil {
		s.Files["/etc/ld.so.preload"] = content
	}
}

// collectInto appends the entries of one directory to a snapshot list. keep
// filters by filename; nil keeps everything. A missing directory is not an
// error -- most of these are absent on any given host.
func collectInto(s *SystemSnapshot, category, dir string, keep func(string) bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if keep != nil && !keep(e.Name()) {
			continue
		}
		s.Lists[category] = append(s.Lists[category], filepath.Join(dir, e.Name()))
	}
}

// revertPlatformExtras removes Linux persistence artifacts the run created.
//
// Only entries absent from the snapshot are touched, so a unit or autostart
// file that was already on the host is never removed. /etc/ld.so.preload is
// handled by the shared file restore when it existed at capture; when it did
// not, it is removed outright, because a preload file the run created is an
// artifact and leaving it would keep injecting into every process on the host.
func revertPlatformExtras(s *SystemSnapshot) []string {
	var reverted []string

	origUnits := toSet(s.Lists["systemd_units"])
	after := newSnapshot(s.RunID)
	capturePlatformExtras(after)

	for _, path := range after.Lists["systemd_units"] {
		if origUnits[path] {
			continue
		}
		// Stop and disable before removing, so a unit that was started from the
		// dropped file does not keep running with its file gone.
		unit := filepath.Base(path)
		exec.Command("systemctl", "stop", unit).Run()    //nolint:errcheck
		exec.Command("systemctl", "disable", unit).Run() //nolint:errcheck
		if os.Remove(path) == nil {
			reverted = append(reverted, "systemd unit removed: "+path)
		}
	}
	if len(reverted) > 0 {
		exec.Command("systemctl", "daemon-reload").Run() //nolint:errcheck
	}

	origAutostart := toSet(s.Lists["autostart"])
	for _, path := range after.Lists["autostart"] {
		if origAutostart[path] {
			continue
		}
		if os.Remove(path) == nil {
			reverted = append(reverted, "autostart entry removed: "+path)
		}
	}

	if _, existedBefore := s.Files["/etc/ld.so.preload"]; !existedBefore {
		if _, err := os.Stat("/etc/ld.so.preload"); err == nil {
			if os.Remove("/etc/ld.so.preload") == nil {
				reverted = append(reverted, "ld.so.preload removed (created during run)")
			}
		}
	} else if original, ok := s.Files["/etc/ld.so.preload"]; ok {
		if current, err := os.ReadFile("/etc/ld.so.preload"); err == nil && !bytes.Equal(current, original) {
			if os.WriteFile("/etc/ld.so.preload", original, 0644) == nil {
				reverted = append(reverted, "ld.so.preload restored")
			}
		}
	}

	return reverted
}
