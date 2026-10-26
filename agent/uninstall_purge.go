package main

import (
	"os"
	"path/filepath"
	"sort"
)

// Removing the data an agent leaves on a machine once its service is gone: the client key and certificate, the
// enrolled CA, the local API token, logs and the event spool. Only locations the agent itself creates are listed,
// by name; a folder somebody else put beside them is never touched, only reported.

// purgeReport says what an uninstall removed and what it could not.
type purgeReport struct {
	Removed  []string // gone
	Deferred []string // in use now; scheduled for deletion at the next boot
	Failed   []string // neither removed nor schedulable: the operator must remove these
	Kept     []string // folders left in place because they hold files the agent did not create
}

// Clean reports whether nothing of the agent is left: no failures, nothing waiting for a reboot, nothing kept.
func (r purgeReport) Clean() bool {
	return len(r.Deferred) == 0 && len(r.Failed) == 0 && len(r.Kept) == 0
}

// purgeOps is the filesystem as the purge sees it, so tests (and the in-use fallback) can stand in for it.
type purgeOps struct {
	removeAll func(path string) error
	remove    func(path string) error // removes an empty folder
	schedule  func(path string) error // deletes at the next boot; may be nil where the OS has no such thing
}

// osPurgeOps is the real filesystem. schedule is the platform's delete-at-boot call (nil when there is none).
func osPurgeOps(schedule func(path string) error) purgeOps {
	return purgeOps{removeAll: os.RemoveAll, remove: os.Remove, schedule: schedule}
}

// agentDataTargets lists, for a machine, the folders the agent creates (trees, removed whole) and the shared
// parents that are removed only if they end up empty. Paths are passed in so the list can be tested.
func agentDataTargets(programData string, installDirs []string, userConfigDir, tempDir string, glob func(pattern string) []string) (trees, parents []string) {
	// A missing base path must not become a relative target: it would be resolved against whatever folder the
	// uninstall runs from.
	if programData != "" {
		audspect := filepath.Join(programData, "Audspect")
		trees = append(trees,
			filepath.Join(programData, "BASAgent"), // local API token, logs, event spool, settings record
			filepath.Join(audspect, "certs"),       // client key + certificate, deployment CA, command-signing key, enrolment state
		)
		if glob != nil {
			trees = append(trees, glob(filepath.Join(audspect, "certs.replaced-*"))...) // certificate sets kept by CA rotation
		}
		parents = []string{audspect}
	}
	for _, d := range installDirs {
		if d != "" {
			trees = append(trees, filepath.Join(d, "logs")) // agent log beside the executable
		}
	}
	if userConfigDir != "" {
		trees = append(trees, filepath.Join(userConfigDir, "BASAgent")) // per-profile agent log
	}
	if tempDir != "" {
		trees = append(trees, filepath.Join(tempDir, "BASAgent")) // last-resort agent log
	}
	return trees, parents
}

// purgeAgentFiles removes the trees, then each parent if it is empty. A tree that cannot be removed now (a file in
// use) is scheduled for deletion at the next boot, files before folders and the deepest first so each folder is
// empty when its turn comes. Nothing is reported as removed that is not gone.
func purgeAgentFiles(trees, parents []string, ops purgeOps) purgeReport {
	var rep purgeReport
	for _, t := range trees {
		if _, err := os.Stat(t); err != nil {
			continue // nothing there
		}
		if err := ops.removeAll(t); err == nil {
			rep.Removed = append(rep.Removed, t)
			continue
		}
		if ops.schedule == nil {
			rep.Failed = append(rep.Failed, t)
			continue
		}
		if scheduleTree(t, ops.schedule) {
			rep.Deferred = append(rep.Deferred, t)
		} else {
			rep.Failed = append(rep.Failed, t)
		}
	}
	for _, p := range parents {
		entries, err := os.ReadDir(p)
		if err != nil {
			continue
		}
		if len(entries) == 0 {
			if err := ops.remove(p); err == nil {
				continue
			}
		}
		rep.Kept = append(rep.Kept, p)
	}
	return rep
}

// scheduleTree schedules every file, then every folder (deepest first), then the root, for deletion at boot.
func scheduleTree(root string, schedule func(string) error) bool {
	var files, dirs []string
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || p == root {
			return nil
		}
		if info.IsDir() {
			dirs = append(dirs, p)
		} else {
			files = append(files, p)
		}
		return nil
	})
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	ok := true
	for _, group := range [][]string{files, dirs, {root}} {
		for _, p := range group {
			if err := schedule(p); err != nil {
				ok = false
			}
		}
	}
	return ok
}

// print writes the outcome in words an administrator can act on.
func (r purgeReport) print(w func(format string, a ...any)) {
	for _, p := range r.Removed {
		w("[+] Removed %s\n", p)
	}
	for _, p := range r.Deferred {
		w("[~] %s is in use; it will be deleted at the next restart\n", p)
	}
	for _, p := range r.Failed {
		w("[!] Could not remove %s: delete it by hand\n", p)
	}
	for _, p := range r.Kept {
		w("[~] Left %s in place: it holds files the agent did not create\n", p)
	}
	if r.Clean() {
		w("[+] No agent data remains on this computer\n")
	}
}
