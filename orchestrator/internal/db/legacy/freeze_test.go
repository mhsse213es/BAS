package legacy_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/db/legacy"
	"github.com/audspect/bas/internal/db/pgtest"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Run(m)) }

// The legacy chain is frozen (H1 spec 7): it exists only to bring pre-H1
// installs to the baseline. Any edit must fail CI.
func TestLegacyChainIsFrozen(t *testing.T) {
	want, err := os.ReadFile("FROZEN.sha256")
	if err != nil {
		t.Fatal(err)
	}
	if got := hashSources(t); strings.TrimSpace(string(want)) != got {
		t.Fatalf("internal/db/legacy changed (got %s). The legacy chain is frozen; ship schema changes as a new migration in internal/db/migrations.", got)
	}
}

func hashSources(t *testing.T) string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	h := sha256.New()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
		fmt.Fprintf(h, "%s\x00%d\x00", f, len(b))
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Idempotent like boot today; equivalence to the baseline is pinned by the
// migrations package's baseline test.
func TestEnsureAll_RunsTwiceOnPoolAndInsideTx(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.NewPool(t)
	if err := legacy.EnsureAll(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if err := legacy.EnsureAll(ctx, pool); err != nil {
		t.Fatalf("second run: %v", err)
	}
	// Adoption runs the chain inside one transaction (plan P2).
	tx, err := pgtest.NewPool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := legacy.EnsureAll(ctx, tx); err != nil {
		t.Fatalf("inside tx: %v", err)
	}
}
