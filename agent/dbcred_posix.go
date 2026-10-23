//go:build linux || darwin

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// dbcredStoreDir is the root-only credential directory next to the service
// config (/etc/bas-agent/config on both Linux, configFile in service_linux.go,
// and macOS, darwinConfigFile in service_darwin.go). A var so tests can point
// it at a temp dir.
var dbcredStoreDir = "/etc/bas-agent/dbcred"

const maxDBCredFileBytes = 16 << 10

// readStoredDBCredentialPlatform reads <dbcredStoreDir>/<name>.json. It refuses
// (returns an error, never a default) when the directory is group/world
// writable, when the entry is not a regular file, when its mode is wider than
// 0600, or when it is owned by someone other than root or the agent's own uid.
func readStoredDBCredentialPlatform(name string) ([]byte, bool, error) {
	di, err := os.Stat(dbcredStoreDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("credential directory: %w", err)
	}
	if !di.IsDir() || di.Mode().Perm()&0o022 != 0 {
		return nil, false, fmt.Errorf("credential directory is not a directory or is writable by group/others (mode %04o)", di.Mode().Perm())
	}
	p := filepath.Join(dbcredStoreDir, name+".json")
	fi, err := os.Lstat(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("credential file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, false, fmt.Errorf("credential file is not a regular file")
	}
	if fi.Mode().Perm()&0o177 != 0 {
		return nil, false, fmt.Errorf("credential file mode %04o is wider than 0600", fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if st.Uid != 0 && int(st.Uid) != os.Geteuid() {
			return nil, false, fmt.Errorf("credential file is owned by uid %d, not root or the agent", st.Uid)
		}
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, false, fmt.Errorf("credential file: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxDBCredFileBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("credential file: %w", err)
	}
	if len(b) > maxDBCredFileBytes {
		return nil, false, fmt.Errorf("credential file too large")
	}
	return b, true, nil
}
