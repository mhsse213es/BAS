package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// installSelfBinary copies the currently running executable to destPath,
// resolving symlinks first so a symlinked invocation (e.g. a PATH shim)
// installs the real binary, not the symlink. Used by the POSIX service
// installers (service_linux.go, service_darwin.go) to place a durable copy
// at the fixed path their systemd unit / launchd plist references, since
// the file the operator downloaded and ran --install from is not
// guaranteed to still exist afterward.
func installSelfBinary(destPath string) error {
	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}
	selfPath, err = filepath.EvalSymlinks(selfPath)
	if err != nil {
		return fmt.Errorf("resolve symlink: %w", err)
	}
	data, err := os.ReadFile(selfPath)
	if err != nil {
		return fmt.Errorf("read binary: %w", err)
	}
	if err := os.WriteFile(destPath, data, 0755); err != nil {
		return fmt.Errorf("write binary to %s: %w", destPath, err)
	}
	return nil
}
