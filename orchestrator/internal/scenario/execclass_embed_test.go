package scenario

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"testing"
)

// TestExecclassEmbedFaithful proves the embedded-JSON generated catalog, merged
// with the hand-authored entries at init(), reproduces the EXACT execution
// classification catalog the previous ~3,450-literal generated file produced.
// The constant was captured from that prior form before the embed refactor; if
// a future cmd/auditcorpus run legitimately changes the catalog, regenerate
// execclass_generated.json and update this hash in the same commit.
func TestExecclassEmbedFaithful(t *testing.T) {
	type row struct{ T, A, C, D, B string }
	var full []row
	for tid, inner := range executionClassifications {
		for act, c := range inner {
			full = append(full, row{tid, act, string(c.Class), c.DestructiveAction, c.BlastRadius})
		}
	}
	sort.Slice(full, func(i, j int) bool {
		if full[i].T != full[j].T {
			return full[i].T < full[j].T
		}
		return full[i].A < full[j].A
	})

	if len(full) != 3604 {
		t.Fatalf("expected 3604 classification entries, got %d", len(full))
	}
	h := sha256.New()
	for _, r := range full {
		fmt.Fprintf(h, "%s\x1f%s\x1f%s\x1f%s\x1f%s\x1e", r.T, r.A, r.C, r.D, r.B)
	}
	const want = "c4db562e1943a55da0d614e2e33f7ca116adef40cbc16ba485786141771b639f"
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		t.Fatalf("catalog changed after embed refactor:\n got  %s\n want %s", got, want)
	}
}

// TestExecclassEmbedPreservesHandAuthoredSplit confirms the hand-authored
// snapshot still excludes generated entries (IsHandAuthored semantics), since
// the embed loader runs in init() -- after the var-init snapshot.
func TestExecclassEmbedPreservesHandAuthoredSplit(t *testing.T) {
	hand := 0
	for tid, inner := range executionClassifications {
		for act := range inner {
			if IsHandAuthored(tid, act) {
				hand++
			}
		}
	}
	if hand != 154 {
		t.Fatalf("expected 154 hand-authored entries (generated must not leak into the snapshot), got %d", hand)
	}
}
