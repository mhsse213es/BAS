//go:build linux || darwin

package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// dbcredStoreDir is the root-only credential directory next to the service
// config (/etc/bas-agent/config on both Linux, configFile in service_linux.go,
// and macOS, darwinConfigFile in service_darwin.go). A var so tests can point
// it at a temp dir.
var dbcredStoreDir = "/etc/bas-agent/dbcred"

const maxDBCredFileBytes = 16 << 10

// ownerOK reports whether uid may own the credential directory or file: root,
// or (for an agent deliberately run as a non-root service account) the agent's
// own effective uid. When the agent runs as root (euid 0) only root qualifies,
// which is the spec's "root-only" rule.
func ownerOK(uid uint32) bool { return uid == 0 || int(uid) == os.Geteuid() }

// readStoredDBCredentialPlatform reads <dbcredStoreDir>/<name>.json with no
// stat-then-open window: the directory and the file are opened with O_NOFOLLOW
// (a symlink is refused), and every check is made with Fstat on the opened
// descriptor, which is also the descriptor the content is read from.
// It refuses (an error, never a default) when the directory is not a directory,
// is group/world writable, or has an owner other than root/the agent euid; or
// when the entry is not a regular file, has a mode wider than 0600, has an
// owner other than root/the agent euid, or exceeds 16 KiB.
// Not executed on the Windows build host: compile-checked for linux and darwin.
func readStoredDBCredentialPlatform(name string) ([]byte, bool, error) {
	dfd, err := unix.Open(dbcredStoreDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("credential directory: %w", err)
	}
	defer unix.Close(dfd)
	var dst unix.Stat_t
	if err := unix.Fstat(dfd, &dst); err != nil {
		return nil, false, fmt.Errorf("credential directory: %w", err)
	}
	if uint32(dst.Mode)&unix.S_IFMT != unix.S_IFDIR {
		return nil, false, fmt.Errorf("credential directory is not a directory")
	}
	if uint32(dst.Mode)&0o022 != 0 {
		return nil, false, fmt.Errorf("credential directory is writable by group/others (mode %04o)", uint32(dst.Mode)&0o7777)
	}
	if !ownerOK(dst.Uid) {
		return nil, false, fmt.Errorf("credential directory is owned by uid %d, not root or the agent", dst.Uid)
	}

	ffd, err := unix.Openat(dfd, name+".json", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("credential file: %w", err)
	}
	f := os.NewFile(uintptr(ffd), name+".json") // owns ffd from here
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(ffd, &st); err != nil {
		return nil, false, fmt.Errorf("credential file: %w", err)
	}
	if uint32(st.Mode)&unix.S_IFMT != unix.S_IFREG {
		return nil, false, fmt.Errorf("credential file is not a regular file")
	}
	if uint32(st.Mode)&0o177 != 0 {
		return nil, false, fmt.Errorf("credential file mode %04o is wider than 0600", uint32(st.Mode)&0o7777)
	}
	if !ownerOK(st.Uid) {
		return nil, false, fmt.Errorf("credential file is owned by uid %d, not root or the agent", st.Uid)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxDBCredFileBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("credential file: %w", err)
	}
	if len(b) > maxDBCredFileBytes {
		return nil, false, fmt.Errorf("credential file too large")
	}
	return b, true, nil
}
