package main

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

// The property everything else depends on: a capped writer must never signal
// back-pressure. os/exec drains the child's pipe into this writer on a
// background goroutine; an error or a short count there stops the copy, the OS
// pipe fills, and the child blocks on write() or dies on SIGPIPE. That would
// turn a memory bound into a hang -- the failure class that left steps RUNNING
// forever. Writes past the limit must be accepted and discarded, not refused.
func TestCappedBuffer_WriteNeverErrorsOrShortWrites(t *testing.T) {
	c := newCappedBuffer(16)
	chunk := bytes.Repeat([]byte("x"), 100)

	for i := 0; i < 50; i++ { // long past the limit
		n, err := c.Write(chunk)
		if err != nil {
			t.Fatalf("write %d returned error %v; a capped writer must keep draining", i, err)
		}
		if n != len(chunk) {
			t.Fatalf("write %d returned n=%d, want %d; a short count stops io.Copy", i, n, len(chunk))
		}
	}
}

func TestCappedBuffer_RetainsHeadAndCountsTotal(t *testing.T) {
	const input = "HEADHEADHEAD-and-then-a-great-deal-more"
	c := newCappedBuffer(10)
	c.Write([]byte(input))

	if got, want := c.Total(), int64(len(input)); got != want {
		t.Errorf("Total() = %d, want %d (everything the child produced)", got, want)
	}
	if !strings.HasPrefix(c.String(), "HEADHEADHE") {
		t.Errorf("retained output = %q, want the first 10 bytes", c.String())
	}
	if strings.Contains(c.String(), "great-deal-more") {
		t.Error("output past the limit was retained")
	}
}

// Truncation must be visible, and the marker must carry the true total: a step
// that emitted hundreds of megabytes is itself worth knowing about, and
// reporting only the retained slice would hide that entirely.
func TestCappedBuffer_TruncationMarkerReportsTrueTotal(t *testing.T) {
	c := newCappedBuffer(8)
	c.Write(bytes.Repeat([]byte("a"), 5000))

	s := c.String()
	if !strings.Contains(s, "output truncated") {
		t.Errorf("no truncation marker in %q", s)
	}
	if !strings.Contains(s, "of 5000 bytes") {
		t.Errorf("marker does not report the true total: %q", s)
	}
}

// Output that fits must be returned verbatim, with no marker -- otherwise every
// ordinary step's output would carry a misleading truncation note.
func TestCappedBuffer_NoMarkerWhenNothingDropped(t *testing.T) {
	c := newCappedBuffer(64)
	c.Write([]byte("short and complete"))

	if got := c.String(); got != "short and complete" {
		t.Errorf("String() = %q, want the input unchanged with no marker", got)
	}
}

// Exactly at the limit is the off-by-one that would either drop a byte or
// append a spurious marker.
func TestCappedBuffer_ExactlyAtLimit(t *testing.T) {
	c := newCappedBuffer(5)
	c.Write([]byte("12345"))

	if got := c.String(); got != "12345" {
		t.Errorf("String() = %q, want %q with no marker", got, "12345")
	}
}

// A single write larger than the whole limit must be split correctly rather
// than dropped whole or retained whole.
func TestCappedBuffer_SingleWriteLargerThanLimit(t *testing.T) {
	c := newCappedBuffer(4)
	n, err := c.Write([]byte("abcdefghij"))

	if err != nil || n != 10 {
		t.Fatalf("Write = (%d, %v), want (10, nil)", n, err)
	}
	if !strings.HasPrefix(c.String(), "abcd") {
		t.Errorf("retained %q, want the first 4 bytes", c.String())
	}
	if c.Total() != 10 {
		t.Errorf("Total() = %d, want 10", c.Total())
	}
}

// os/exec permits pointing Stdout and Stderr at the SAME writer, in which case
// two goroutines write concurrently. Guard against a future caller doing that.
func TestCappedBuffer_ConcurrentWritesAreSafe(t *testing.T) {
	c := newCappedBuffer(1024)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				c.Write([]byte("0123456789"))
			}
		}()
	}
	wg.Wait()

	if got, want := c.Total(), int64(8*200*10); got != want {
		t.Errorf("Total() = %d, want %d", got, want)
	}
	if len(c.buf) > 1024 {
		t.Errorf("retained %d bytes, exceeds the 1024 limit", len(c.buf))
	}
}
