package secretstore

import (
	"encoding/base64"
	"errors"
	"io/fs"
	"os"
	"strings"
)

// DefaultKeyPath is where the installer places the interim encryption key on a Linux host. It is root-owned, group-readable by the service group (0640), and
// outside the database directory, so ordinary database dumps and the upgrade backup (which copies the data directory) do not
// capture it.
const DefaultKeyPath = "/etc/audspect/secrets/db-encryption.key"

// keyFileCheck decides whether a key file's metadata is acceptable. The platform check is in keyfile_unix.go or
// keyfile_other.go.
type keyFileCheck func(fi fs.FileInfo) error

// LoadKeyFile reads the interim encryption key. The file must hold the base64 text of 32 random bytes on one line. On Unix it
// must be owned by root, readable at most by the service group, and not accessible to others. The key text is returned, and no error names it.
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

// checkKeyPerms is the mode check every platform applies where mode bits are meaningful. The owner (root) may read and
// write. The group may read, because the orchestrator's service account is the group, and it cannot write or execute.
// Others get nothing. Mask 0o037 covers group write and execute and every bit for others.
func checkKeyPerms(fi fs.FileInfo) error {
	if fi.Mode().Perm()&0o037 != 0 {
		return errors.New("secretstore: encryption key file may be readable by its service group only, and not writable by the group or others")
	}
	return nil
}
