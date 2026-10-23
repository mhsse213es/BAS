package bench

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Label is one ground-truth flaw. Operation is an operation id or
// "METHOD /path". Labels are held only by the owner, never committed and never
// embedded.
type Label struct {
	ID        string `json:"id"`
	Operation string `json:"operation"`
	Note      string `json:"note,omitempty"`
}

// LoadLabels reads and validates a labels file. It refuses a path inside a git
// working tree so labels cannot end up in the repository.
func LoadLabels(path string) ([]Label, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("bench: labels path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("bench: labels path: %w", err)
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		abs = real
	}
	if root, ok := insideRepo(filepath.Dir(abs)); ok {
		return nil, fmt.Errorf("bench: labels file %s is inside the repository working tree %s; keep it outside the repository", abs, root)
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("bench: read labels: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var ls []Label
	if err := dec.Decode(&ls); err != nil {
		return nil, fmt.Errorf("bench: labels: %w", err)
	}
	if dec.More() {
		return nil, errors.New("bench: labels: trailing data")
	}
	if len(ls) == 0 {
		return nil, errors.New("bench: labels: empty list")
	}
	seen := map[string]bool{}
	for i, l := range ls {
		if strings.TrimSpace(l.ID) == "" {
			return nil, fmt.Errorf("bench: labels[%d]: empty id", i)
		}
		if strings.TrimSpace(l.Operation) == "" {
			return nil, fmt.Errorf("bench: labels[%d] (%s): empty operation", i, l.ID)
		}
		if seen[l.ID] {
			return nil, fmt.Errorf("bench: labels: duplicate id %q", l.ID)
		}
		seen[l.ID] = true
	}
	return ls, nil
}

// insideRepo walks up from dir looking for a .git entry (directory, or file
// for a linked worktree).
func insideRepo(dir string) (string, bool) {
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}
