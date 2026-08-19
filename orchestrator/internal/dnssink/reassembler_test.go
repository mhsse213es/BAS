package dnssink

import (
	"encoding/base32"
	"testing"
	"time"
)

func b32(s string) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(s))
}

func TestReassembler_HeaderThenChunksCompletesAndDecodes(t *testing.T) {
	r := newReassembler(10*time.Minute, 64)
	if err := r.header("campaign1", "2"); err != nil {
		t.Fatalf("header: %v", err)
	}
	full := "hello world"
	half := len(full) / 2
	c1 := b32(full[:half])
	c2 := b32(full[half:])

	decoded, complete, err := r.chunk("campaign1", 1, c1)
	if err != nil {
		t.Fatalf("chunk 1: %v", err)
	}
	if complete {
		t.Fatal("should not be complete after only 1 of 2 chunks")
	}
	if decoded != nil {
		t.Error("decoded should be nil until complete")
	}

	decoded, complete, err = r.chunk("campaign1", 2, c2)
	if err != nil {
		t.Fatalf("chunk 2: %v", err)
	}
	if !complete {
		t.Fatal("should be complete after all declared chunks arrive")
	}
	if string(decoded) != full {
		t.Errorf("decoded = %q, want %q", decoded, full)
	}
}

func TestReassembler_ChunkBeforeHeaderRejected(t *testing.T) {
	r := newReassembler(10*time.Minute, 64)
	_, _, err := r.chunk("unknown-campaign", 1, b32("x"))
	if err == nil {
		t.Error("a chunk for a campaign with no header yet must be rejected")
	}
}

func TestReassembler_HeaderRejectsOversizedDeclaredTotal(t *testing.T) {
	r := newReassembler(10*time.Minute, 64)
	if err := r.header("campaign1", "1000"); err == nil {
		t.Error("a header declaring more than maxChunks must be rejected")
	}
}

func TestReassembler_HeaderRejectsNonNumericTotal(t *testing.T) {
	r := newReassembler(10*time.Minute, 64)
	if err := r.header("campaign1", "not-a-number"); err == nil {
		t.Error("a non-numeric declared total must be rejected")
	}
}

func TestReassembler_ChunkSeqBeyondDeclaredTotalRejected(t *testing.T) {
	r := newReassembler(10*time.Minute, 64)
	if err := r.header("campaign1", "2"); err != nil {
		t.Fatalf("header: %v", err)
	}
	_, _, err := r.chunk("campaign1", 5, b32("x"))
	if err == nil {
		t.Error("a chunk seq beyond the declared total must be rejected")
	}
}

func TestReassembler_EvictExpiredRemovesStaleCampaigns(t *testing.T) {
	r := newReassembler(1*time.Minute, 64)
	fakeNow := time.Now()
	r.now = func() time.Time { return fakeNow }
	if err := r.header("campaign1", "2"); err != nil {
		t.Fatalf("header: %v", err)
	}
	fakeNow = fakeNow.Add(2 * time.Minute) // past the 1-minute TTL
	r.evictExpired()
	_, _, err := r.chunk("campaign1", 1, b32("x"))
	if err == nil {
		t.Error("chunk should be rejected after its campaign's TTL expired and it was evicted")
	}
}

func TestReassembler_DuplicateChunkBeforeCompletionOverwritesWithoutError(t *testing.T) {
	// Exercises a resend arriving WHILE the campaign is still incomplete
	// (total=2, chunk 1 sent twice before chunk 2 ever arrives) -- the
	// scenario real network duplication actually produces. A resend
	// arriving AFTER completion has nothing to attach to, since a
	// completed campaign is deleted immediately (see chunk's doc
	// comment); that's fine, because the receipt was already recorded on
	// first completion, so a late duplicate is safe to drop.
	r := newReassembler(10*time.Minute, 64)
	if err := r.header("campaign1", "2"); err != nil {
		t.Fatalf("header: %v", err)
	}
	if _, complete, err := r.chunk("campaign1", 1, b32("wrong")); err != nil || complete {
		t.Fatalf("first chunk 1: complete=%v err=%v, want complete=false err=nil", complete, err)
	}
	// Resend of chunk 1 before chunk 2 ever arrives -- must not error, and
	// the later value must win.
	if _, complete, err := r.chunk("campaign1", 1, b32("right")); err != nil || complete {
		t.Fatalf("duplicate chunk 1: complete=%v err=%v, want complete=false err=nil", complete, err)
	}
	decoded, complete, err := r.chunk("campaign1", 2, b32("-tail"))
	if err != nil {
		t.Fatalf("chunk 2: %v", err)
	}
	if !complete {
		t.Fatal("should be complete after chunk 2 arrives")
	}
	if string(decoded) != "right-tail" {
		t.Errorf("decoded = %q, want %q (the later resend of chunk 1 should have won)", decoded, "right-tail")
	}
}
