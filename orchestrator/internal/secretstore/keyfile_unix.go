//go:build linux || darwin

package secretstore

import (
	"errors"
	"io/fs"
	"syscall"
)

// platformKeyFileCheck requires mode 0600 or stricter and root ownership.
func platformKeyFileCheck(fi fs.FileInfo) error {
	if err := checkKeyPerms(fi); err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("secretstore: cannot read key file owner")
	}
	if st.Uid != 0 {
		return errors.New("secretstore: encryption key file must be owned by root")
	}
	return nil
}
