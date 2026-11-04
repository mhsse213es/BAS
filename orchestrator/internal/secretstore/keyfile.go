package secretstore

import (
	"encoding/base64"
	"errors"
	"io/fs"
	"os"
	"strings"
)

// DefaultKeyPath is where the installer places the interim encryption key on a Linux host. It is root-owned, mode 0600, and
// outside the database directory, so ordinary database dumps and the upgrade backup (which copies the data directory) do not
// capture it.
const DefaultKeyPath = "/etc/audspect/secrets/db-encryption.key"

// keyFileCheck decides whether a key file's metadata is acceptable. The platform check is in keyfile_unix.go or
// keyfile_other.go.
type keyFileCheck func(fi fs.FileInfo) error

// LoadKeyFile reads the interim encryption key. The file must hold the base64 text of 32 random bytes on one line. On Unix it
// must be owned by root and carry no group or other permission bits. The key text is returned, and no error names it.
func LoadKeyFile(path string) (string, error) {
	return loadKeyFile(path, platformKeyFileCheck)
}

func loadKeyFile(path string, check keyFileCheck) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", errors.New("secretstore: encryption key file is not readable")
	}
	if !fi.Mode().IsRegular() {
		return "", errors.New("secretstore: encryption key path is not a regular file")
	}
	if err := check(fi); err != nil {
		return "", err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", errors.New("secretstore: encryption key file is not readable")
	}
	key := strings.TrimSpace(string(b))
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(raw) != minKeyBytes {
		return "", errors.New("secretstore: encryption key must be base64 of exactly 32 random bytes")
	}
	return key, nil
}

// checkKeyPerms is the mode check every platform applies where mode bits are meaningful.
func checkKeyPerms(fi fs.FileInfo) error {
	if fi.Mode().Perm()&0o077 != 0 {
		return errors.New("secretstore: encryption key file must not be readable by group or others")
	}
	return nil
}
