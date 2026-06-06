package scenario

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
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

// NewPayloadStoreFromDB builds the store from the art_payloads metadata table.
// Binaries remain on disk — only their storage_path is indexed, so dispatch-time
// staging reads the file exactly as before. This is the runtime constructor;
// NewPayloadStore (disk walk) is retained for tests and the seed path.
func NewPayloadStoreFromDB(ctx context.Context, pool *pgxpool.Pool) (*PayloadStore, error) {
	ps := &PayloadStore{files: make(map[string]string)}
	rows, err := pool.Query(ctx, `SELECT basename, storage_path FROM art_payloads`)
	if err != nil {
		return nil, fmt.Errorf("load payloads: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var base, path string
		if err := rows.Scan(&base, &path); err != nil {
			return nil, err
		}
		ps.files[strings.ToLower(base)] = path
	}
	return ps, rows.Err()
}

// Reload re-reads the payload metadata index from the DB and swaps it in under
// the write lock. Used by the admin reseed endpoint after a content-pack import.
func (ps *PayloadStore) Reload(ctx context.Context, pool *pgxpool.Pool) error {
	fresh, err := NewPayloadStoreFromDB(ctx, pool)
	if err != nil {
		return err
	}
	ps.mu.Lock()
	ps.files = fresh.files
	ps.mu.Unlock()
	return nil
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
