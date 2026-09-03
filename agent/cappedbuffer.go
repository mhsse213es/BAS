package main

import (
	"fmt"
	"sync"
	"time"
)

// cappedBuffer retains at most limit bytes of what a step writes, while
// continuing to accept — and discard — everything beyond that.
//
// It replaces a plain bytes.Buffer on cmd.Stdout/Stderr. The old arrangement
// bounded only the REPORTED output: the full stream was accumulated in memory
// and trimmed to 8 KB when the result was built, so a step like
// `grep -ri password /` (a real atomic in the full ART sweep) streamed the
// whole filesystem into the agent's heap before anything trimmed it. Capping at
// the writer bounds memory while the process is still running, which is the
// only point at which the bound does any good.
//
// THE CRITICAL PROPERTY: Write ALWAYS returns (len(p), nil). Never an error,
// never a short count. os/exec copies the child's pipe into this writer on a
// background goroutine; if that copy stopped, the OS pipe would fill and the
// child would either block on write() forever or take SIGPIPE and die. Either
// outcome converts a memory problem into a hang or a spurious step failure —
// the exact failure class that made steps sit RUNNING forever (see
// executor.go's WaitDelay comment). So this type drains unconditionally and
// simply stops retaining.
//
// The mutex is not required by today's callers — os/exec uses one goroutine per
// stream, and stdout/stderr get separate buffers — but os/exec explicitly
// permits pointing both at a single writer, in which case two goroutines would
// race. Guarding here costs nothing at these volumes (io.Copy writes in 32 KB
// chunks) and removes the footgun.
type cappedBuffer struct {
	mu    sync.Mutex
	buf   []byte
	limit int
	total int64     // everything the child produced, retained or not
	last  time.Time // when the child last wrote; zero if it never did
}

func newCappedBuffer(limit int) *cappedBuffer {
	return &cappedBuffer{limit: limit}
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.total += int64(len(p))
	// Stamp when the child last wrote. The execute deadline is pure wall-clock:
	// a step that is slow but genuinely working is killed by the same code, at
	// the same moment, as one wedged on a dead socket. This timestamp does not
	// resolve that -- output is evidence of activity, not proof of progress, and
	// a process can print the same line forever -- but it is the difference
	// between reporting "killed at 120s" and "killed at 120s, still writing
	// 0.3s earlier". Costs one clock read per 32 KB copy chunk.
	c.last = time.Now()
	// Retain the head: the first bytes of a step's output are what identify
	// what it did. Everything past the limit is counted and dropped.
	if room := c.limit - len(c.buf); room > 0 {
		if len(p) < room {
			room = len(p)
		}
		c.buf = append(c.buf, p[:room]...)
	}
	return len(p), nil
}

// String returns the retained output, with a marker appended when the child
// produced more than was kept. The marker carries the true total: a step that
// emitted hundreds of megabytes is itself worth knowing about, and reporting
// only the retained slice would hide that.
func (c *cappedBuffer) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	s := string(c.buf)
	if c.total > int64(len(c.buf)) {
		s += fmt.Sprintf("\n[agent] output truncated: retained first %d of %d bytes", len(c.buf), c.total)
	}
	return s
}

// Total is everything the child wrote, including what was discarded.
func (c *cappedBuffer) Total() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.total
}

// Written reports how much the child wrote and when it last wrote. last is the
// zero Time when nothing was ever written.
func (c *cappedBuffer) Written() (total int64, last time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.total, c.last
}
