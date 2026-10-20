// Package catalog embeds the API BAS scenario files and loads them through
// the contract validator. The files live here, not under scenarios/, so the
// live scenario engine never loads them and their IDs cannot collide with
// existing scenario IDs.
package catalog

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"

	"github.com/audspect/bas/internal/apibas/contract"
)

//go:embed *.yaml
var files embed.FS

// All loads and validates every embedded scenario, sorted by ID. It fails
// closed: one invalid file makes the whole catalog fail to load.
func All() ([]contract.Scenario, error) {
	return load(files)
}

func load(fsys fs.FS) ([]contract.Scenario, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("catalog: read: %w", err)
	}
	var out []contract.Scenario
	seen := make(map[string]string)
	for _, e := range entries {
		if e.IsDir() || path.Ext(e.Name()) != ".yaml" {
			continue
		}
		data, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return nil, fmt.Errorf("catalog: read %s: %w", e.Name(), err)
		}
		s, err := contract.Parse(data)
		if err != nil {
			return nil, fmt.Errorf("catalog: %s: %w", e.Name(), err)
		}
		if prev, dup := seen[s.ID]; dup {
			return nil, fmt.Errorf("catalog: %s duplicates id %s from %s", e.Name(), s.ID, prev)
		}
		seen[s.ID] = e.Name()
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
