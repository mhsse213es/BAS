package scenario

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// PayloadStore is the server-side store of external ART payload binaries
// (gsecdump.exe, etc.) that an operator drops into ART_PAYLOAD_DIR. At dispatch
// the server ships matching payloads to the agent's per-run temp dir via the
// staging pipeline — nothing is ever pre-placed on the endpoint. Atomics whose
// payload is absent are skipped cleanly instead of failing.
type PayloadStore struct {
	mu    sync.RWMutex
	dir   string
	files map[string]string // lowercase basename -> absolute path
}

// NewPayloadStore indexes every file under dir (recursively) by basename.
// A missing or empty dir yields an empty store (all lookups miss → clean skip).
func NewPayloadStore(dir string) *PayloadStore {
	ps := &PayloadStore{dir: dir, files: make(map[string]string)}
	if dir == "" {
		return ps
	}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			return nil
		}
		ps.files[strings.ToLower(d.Name())] = path
		return nil
	})
	if err != nil {
		log.Printf("[payloads] index %q: %v", dir, err)
	}
	return ps
}

// Count returns the number of indexed payload files.
func (ps *PayloadStore) Count() int {
	if ps == nil {
		return 0
	}
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return len(ps.files)
}

// Path returns the absolute path of a payload by basename, case-insensitive.
func (ps *PayloadStore) Path(basename string) (string, bool) {
	if ps == nil {
		return "", false
	}
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	p, ok := ps.files[strings.ToLower(basename)]
	return p, ok
}
