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
//
// The 20 cloud VM entries in execclass_cloudvm.go were added after the original capture. Excluding
// them, the hash is unchanged (verified), so the pre-existing catalog is byte-for-byte the same.
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

	if len(full) != 3696 {
		t.Fatalf("expected 3696 classification entries, got %d", len(full))
	}
	h := sha256.New()
	for _, r := range full {
		fmt.Fprintf(h, "%s\x1f%s\x1f%s\x1f%s\x1f%s\x1e", r.T, r.A, r.C, r.D, r.B)
	}
	const want = "69c896c709d8fcfe8f9a2a7e05cc5169f309ce79bdf4531a73bdaa7937b3e827"
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
	// 177 original hand-authored entries plus the 20 cloud VM entries, now written into the literal.
	if hand != 246 {
		t.Fatalf("expected 246 hand-authored entries (generated must not leak into the snapshot), got %d", hand)
	}
}
