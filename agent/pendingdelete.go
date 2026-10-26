package main

import (
	"os"
	"path/filepath"
	"strings"
)

// Windows keeps "delete this file at the next restart" orders in the registry (PendingFileRenameOperations, a list
// of source/destination pairs; an empty destination means delete). An order for the agent's own executable that
// outlives the uninstall that created it would delete the NEXT installation at the next restart, so the agent
// cancels any such order for its own path when it installs.

// pendingEntryPath strips the flag ("*1") and native ("\??\") prefixes the list uses, leaving a plain path.
func pendingEntryPath(entry string) string {
	e := entry
	if strings.HasPrefix(e, "*") && len(e) > 1 {
		e = e[2:] // "*1", "*2": flag character after the asterisk
	}
	e = strings.TrimPrefix(e, "!")
	e = strings.TrimPrefix(e, `\??\`)
	return e
}

// dropPendingDeletes removes the delete orders (empty destination) for path and for anything inside it, comparing
// case-insensitively; a sibling whose name merely starts the same is not matched. A list
// that is not made of pairs is returned unchanged rather than guessed at. It returns the list to keep and how many
// orders were dropped.
func dropPendingDeletes(values []string, path string) (kept []string, dropped int) {
	if len(values)%2 != 0 {
		return values, 0
	}
	want := strings.ToLower(filepath.Clean(path))
	kept = make([]string, 0, len(values))
	for i := 0; i < len(values); i += 2 {
		src, dst := values[i], values[i+1]
		got := strings.ToLower(filepath.Clean(pendingEntryPath(src)))
		if dst == "" && (got == want || strings.HasPrefix(got, want+`\`)) {
			dropped++
			continue
		}
		kept = append(kept, src, dst)
	}
	return kept, dropped
}

// scheduleExeDelete schedules the executable's removal at the next restart, unless Windows Installer owns the file:
// an MSI uninstall removes it itself once the agent's uninstall has finished, and a leftover order would later
// delete a reinstalled agent.
func scheduleExeDelete(path string, msiManaged bool, schedule func(string) error) (scheduled bool, err error) {
	if msiManaged {
		return false, nil
	}
	if err := schedule(path); err != nil {
		return false, err
	}
	return true, nil
}

// msiRemovingEnv is set by the MSI's uninstall action on the agent it runs, so the agent knows Windows Installer is
// removing the executable and must not also schedule that for the next restart.
const msiRemovingEnv = "BAS_REMOVED_BY_MSI"

func removedByMSI() bool { return os.Getenv(msiRemovingEnv) == "1" }
