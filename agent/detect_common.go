package main

import (
	"encoding/json"
	"io"
	"os"
	"runtime"

	"audspect/agent/protocol"
)

// This file holds the parts of alert collection that are identical on every
// platform. It carries no build tag on purpose: capping and truncation decide
// how much evidence survives to the server, and a per-OS copy of that logic is
// how the platforms would drift into subtly different detection models.

// capRecords keeps at most maxEvents records and <= maxBytes of JSON
// (newest-first). The bool reports whether anything was dropped -- the server
// needs to know the difference between "nothing else happened" and "we stopped
// looking".
func capRecords(recs []protocol.AlertRecord, maxEvents, maxBytes int) ([]protocol.AlertRecord, bool) {
	truncated := false
	if len(recs) > maxEvents {
		recs = recs[:maxEvents]
		truncated = true
	}
	for {
		b, _ := json.Marshal(recs)
		if len(b) <= maxBytes || len(recs) == 0 {
			break
		}
		recs = recs[:len(recs)-1]
		truncated = true
	}
	return recs, truncated
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// readCapped reads at most limit bytes from r and reports whether more was
// available. Log sources are unbounded by nature -- `log show` on a busy Mac
// and journalctl on a chatty host can both emit far more than the agent should
// ever hold -- so collection reads through this rather than io.ReadAll.
//
// Truncation lands mid-line, which is safe by construction: every POSIX parser
// works line-at-a-time and skips a line it cannot parse, so a severed tail
// costs exactly one record.
func readCapped(r io.Reader, limit int) ([]byte, bool) {
	if limit <= 0 {
		return nil, false
	}
	buf := make([]byte, limit)
	n, err := io.ReadFull(r, buf)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return buf[:n], false
	}
	if err != nil {
		return buf[:n], false
	}
	// Filled the buffer: check whether anything remained behind it.
	var probe [1]byte
	if _, perr := r.Read(probe[:]); perr == nil {
		return buf, true
	}
	return buf, false
}

// tailFile returns the last limit bytes of a file, and whether it was longer.
// Audit and syslog files are append-only and can reach hundreds of megabytes,
// while the run window only ever concerns the end of them.
func tailFile(p string, limit int64) ([]byte, bool, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	size := st.Size()
	truncated := false
	if size > limit {
		if _, err := f.Seek(size-limit, io.SeekStart); err != nil {
			return nil, false, err
		}
		truncated = true
		size = limit
	}
	b, _ := readCapped(f, int(size)+1)
	return b, truncated, nil
}

// posixDetectionSubmitEnabled gates whether Linux and macOS agents submit
// collected alerts to the server.
//
// It is OFF because the server's correlation rule scores a bare timestamp match
// as a detection: any alert landing inside a step's window marks that technique
// "detected", so a single unrelated systemd unit failure would report a 100%
// detection rate. That is tolerable-ish against the Windows alert-tier channels
// the rule was tuned for, and badly wrong against a general-purpose system log.
//
// Collection itself is complete and verified; only the submission is held back.
// Turn this on once the server distinguishes an attributable detection from
// mere co-occurrence, and not before -- an inflated detection rate reaching a
// client is worse than no detection data at all.
const posixDetectionSubmitEnabled = false

// posixDetectionGatedOff reports whether this agent must withhold detections.
func posixDetectionGatedOff() bool {
	return !posixDetectionSubmitEnabled && runtime.GOOS != "windows"
}
