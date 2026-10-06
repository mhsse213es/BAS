// Package migrations is the embedded, immutable migration set (H1). Rules:
// README.md. Shipped files never change; CI pins them in MANIFEST.sha256.
package migrations

import (
	"embed"
	"fmt"
	"io/fs"
	"strconv"
)

// FS holds NNNNNN_name.up.sql / .down.sql at its root.
//
//go:embed *.sql
var FS embed.FS

// Latest returns the highest migration version in FS.
func Latest() (uint, error) {
	return LatestIn(FS)
}

// LatestIn returns the highest migration version in fsys.
func LatestIn(fsys fs.FS) (uint, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return 0, err
	}
	var max uint
	for _, e := range entries {
		if len(e.Name()) < 7 {
			continue
		}
		n, err := strconv.ParseUint(e.Name()[:6], 10, 32)
		if err != nil {
			return 0, fmt.Errorf("migration %s: bad version prefix", e.Name())
		}
		if uint(n) > max {
			max = uint(n)
		}
	}
	return max, nil
}
