//go:build linux

package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"audspect/agent/protocol"
)

// Linux alert collection.
//
// This file only decides WHERE to look and runs the commands. Every line of
// interpretation lives in detect_parse_posix.go, which carries no build tag and
// is therefore unit-tested on the build host rather than only in the field.
//
// SOURCES. Three independent sources, not a ranked list. Each is strong
// evidence for its own claim and silent on the others, exactly as the security
// product inventory treats its own sources:
//
//	source           supports                        does NOT support
//	---------------  ------------------------------  ----------------------------
//	journald         a program logged something      that it detected anything
//	audit.log        the kernel denied/flagged an     that a rule covers what we
//	                 action, or an operator-keyed     simulated
//	                 rule fired
//	syslog files     a program logged something,      any severity ranking -- the
//	                 on hosts with no journal         text format records none
//
// The journal and the audit log are collected TOGETHER on every run: auditd
// writes its own file and does not reach the journal on a default install, so
// treating either as a fallback for the other would silently lose a source. The
// syslog text files are a true fallback, read only when neither produced
// anything, because on a systemd host they merely restate the journal.
//
// WHAT IS SELECTED, AND WHAT IS NOT. The journal is filtered to priority
// warning-and-above and the audit log to denial/anomaly record types plus
// operator-keyed rules. Both filters are content-neutral -- a severity tier and
// the kernel's own record classification -- never a match against message text.
// This mirrors the Windows collector picking alert-tier channels and letting
// the server recognise providers.
//
// The cost of that choice, stated plainly: a control that reports a detection
// at notice or info level is not collected here. Widening to every priority
// would let routine chatter fill the newest-first cap and push real denials out
// of the window, which loses more evidence than it gains. The Windows collector
// makes the same trade by scanning selected channels rather than all of them.
//
// Best-effort throughout: any failure yields no records for that source rather
// than an error, because detection collection must never affect the
// authoritative run result.

const (
	// detectCmdTimeout bounds each collection command. Generous, because it
	// runs after results are already delivered and blocks nothing.
	detectCmdTimeout = 45 * time.Second

	// detectOutputLimit bounds a single command's output.
	detectOutputLimit = 8 << 20

	// auditTailLimit bounds how far back into audit.log we read. The run
	// window is minutes; this is many times more than it can span.
	auditTailLimit = 8 << 20
)

// auditLogPath is the standard auditd log location on every supported distro,
// relative to the filesystem root.
const auditLogPath = "var/log/audit/audit.log"

// syslogFallbackPaths are read only when neither journald nor auditd yielded
// anything, in order, stopping at the first that produces records.
var syslogFallbackPaths = []string{
	"var/log/syslog",   // Debian/Ubuntu
	"var/log/messages", // RHEL/SUSE
	"var/log/auth.log", // Debian/Ubuntu auth
	"var/log/secure",   // RHEL auth
}

// collectAlerts gathers defensive evidence in [from,to], newest-first, capped
// at maxEvents / maxBytes (bool = truncated). The agent does NOT decide what is
// a detection -- it reports what the platform logged and the server correlates.
func collectAlerts(from, to time.Time, maxEvents, maxBytes int) ([]protocol.AlertRecord, bool) {
	recs := append(collectJournal(from, to, maxEvents), collectAuditdIn("/", from, to)...)
	if len(recs) == 0 {
		recs = collectSyslogFilesIn("/", from, to)
	}
	if len(recs) == 0 {
		return nil, false
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].Timestamp.After(recs[j].Timestamp) })
	return capRecords(recs, maxEvents, maxBytes)
}

// collectJournal reads warning-and-above journal entries in the window.
func collectJournal(from, to time.Time, maxEvents int) []protocol.AlertRecord {
	lines := maxEvents * 2
	if lines > 2000 {
		lines = 2000
	}
	out, ok := runDetectCmd("journalctl",
		"--no-pager",
		"--output=json",
		"--priority=4", // emerg..warning; journalctl -p takes a maximum
		// @<epoch> is systemd's unambiguous absolute time form. A formatted
		// local timestamp would be reinterpreted against the host's zone.
		"--since=@"+strconv.FormatInt(from.Unix(), 10),
		"--until=@"+strconv.FormatInt(to.Unix(), 10),
		"--lines="+strconv.Itoa(lines),
	)
	if !ok {
		return nil
	}
	return parseJournalNDJSON(out)
}

// collectAuditdIn reads the audit log directly, falling back to ausearch when
// the file is unreadable. Both yield the same raw record format, so one parser
// serves both. root is the filesystem root, injectable so the file path can be
// exercised in a test without touching the host's real /var/log.
func collectAuditdIn(root string, from, to time.Time) []protocol.AlertRecord {
	if b, _, err := tailFile(filepath.Join(root, auditLogPath), auditTailLimit); err == nil && len(b) > 0 {
		if recs := parseAuditLog(b, from, to); len(recs) > 0 {
			return recs
		}
		// The file was readable and simply held nothing for this window.
		return nil
	}
	// --raw keeps auditd's native format rather than ausearch's interpreted
	// rendering, so the same parser applies.
	out, ok := runDetectCmd("ausearch", "--raw",
		"--start", from.Local().Format("01/02/2006 15:04:05"),
		"--end", to.Local().Format("01/02/2006 15:04:05"))
	if !ok {
		return nil
	}
	return parseAuditLog(out, from, to)
}

// collectSyslogFilesIn is the no-journald fallback. See parseSyslogLines for
// what this source cannot tell us -- notably that it carries no severity at all.
func collectSyslogFilesIn(root string, from, to time.Time) []protocol.AlertRecord {
	for _, rel := range syslogFallbackPaths {
		b, _, err := tailFile(filepath.Join(root, rel), auditTailLimit)
		if err != nil || len(b) == 0 {
			continue
		}
		// Local zone: the writing host stamped these in its own wall time.
		if recs := parseSyslogLines(b, from, to, time.Local); len(recs) > 0 {
			return recs
		}
	}
	return nil
}

// runDetectCmd runs one collection command under a deadline with bounded
// output. It reports ok=false on any failure, including the tool being absent,
// so a missing journalctl or ausearch is simply a source that yielded nothing.
func runDetectCmd(name string, args ...string) ([]byte, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), detectCmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, false
	}
	if err := cmd.Start(); err != nil {
		return nil, false
	}
	b, _ := readCapped(stdout, detectOutputLimit)
	// Drain and reap. A non-zero exit still leaves whatever was written usable:
	// journalctl exits non-zero on some hosts while having produced output.
	_ = cmd.Wait()
	if len(b) == 0 {
		return nil, false
	}
	return b, true
}
