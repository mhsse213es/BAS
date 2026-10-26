//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

const sessionManagerKey = `SYSTEM\CurrentControlSet\Control\Session Manager`

// cancelPendingDeletes removes, from Windows' list of delete-at-restart orders, the orders for each root and for
// anything inside it. It returns how many were removed. A missing list is not an error.
func cancelPendingDeletes(roots ...string) (int, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, sessionManagerKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return 0, err
	}
	defer k.Close()
	values, _, err := k.GetStringsValue("PendingFileRenameOperations")
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	total := 0
	for _, r := range roots {
		if r == "" {
			continue
		}
		var n int
		values, n = dropPendingDeletes(values, r)
		total += n
	}
	if total == 0 {
		return 0, nil
	}
	if len(values) == 0 {
		if err := k.DeleteValue("PendingFileRenameOperations"); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return 0, err
		}
		return total, nil
	}
	return total, k.SetStringsValue("PendingFileRenameOperations", values)
}

// agentPendingDeleteRoots are the paths whose delete-at-restart orders must not outlive an uninstall: the
// executable and the folders the agent keeps its data in.
func agentPendingDeleteRoots(exePath string) []string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return []string{
		exePath,
		filepath.Join(pd, "BASAgent"),
		filepath.Join(pd, "Audspect", "certs"),
		filepath.Join(filepath.Dir(exePath), "logs"),
	}
}
