//go:build darwin

package main

import (
	"context"
	"os/exec"
	"sort"
	"strings"
	"time"

	"audspect/agent/protocol"
)

// macOS alert collection.
//
// As on Linux, this file only decides where to look and runs the command; all
// interpretation lives in the untagged parsers in detect_parse_posix.go so it
// can be tested from a non-macOS build host.
//
// SOURCE. macOS has one log: the unified log, read through `log show`. Unlike
// Linux there is no second independent store -- Endpoint Security, Gatekeeper,
// XProtect and TCC all write here -- so a single query covers the platform.
//
// WHAT IS SELECTED. Two content-neutral filters, OR'd:
//
//  1. A fixed list of Apple security subsystems, at every level. The unified
//     log's subsystem is the true analogue of a Windows Event Log channel: a
//     namespaced stream chosen by the writer, not by us. Apple's security
//     components log routine decisions at Default level, so filtering these by
//     severity would discard the Gatekeeper and XProtect verdicts that matter
//     most.
//  2. error and fault from every other subsystem. Third-party EDRs log under
//     their own vendor subsystems, which cannot be enumerated in advance
//     without guessing vendor names -- which would be the agent deciding what
//     counts as a security product. The severity tier catches them without
//     naming any. This is the same trade the Windows collector makes when it
//     sweeps the broad Application and System channels and lets the server
//     recognise providers.
//
// Neither filter looks at message text. Provider matching stays server-side.
//
// The cost, stated plainly: a third-party control that reports a detection at
// Default level, under a subsystem not on the list, is not collected. Removing
// the predicate entirely would return the whole system log for the window --
// tens of megabytes on an idle Mac -- and routine chatter would fill the
// newest-first cap and push real alerts out of it.
//
// Best-effort throughout: any failure yields no records rather than an error.

const (
	detectCmdTimeout  = 45 * time.Second
	detectOutputLimit = 8 << 20
)

// appleSecuritySubsystems are collected at every log level. These are Apple's
// own namespaces for policy evaluation, code signing, malware remediation and
// privacy decisions -- the macOS analogue of the Windows alert-tier channels.
var appleSecuritySubsystems = []string{
	"com.apple.syspolicy",         // Gatekeeper / notarisation verdicts
	"com.apple.securityd",         // keychain and code-signing
	"com.apple.security",          // Security framework
	"com.apple.xprotect",          // XProtect signature scanning
	"com.apple.XProtectFramework", // XProtect Remediator
	"com.apple.TCC",               // privacy / consent decisions
	"com.apple.endpointsecurity",  // ES client activity
	"com.apple.SystemPolicy",      // system policy daemon
}

// collectAlerts gathers defensive evidence in [from,to], newest-first, capped
// at maxEvents / maxBytes (bool = truncated). The agent does NOT decide what is
// a detection -- it reports what the platform logged and the server correlates.
func collectAlerts(from, to time.Time, maxEvents, maxBytes int) ([]protocol.AlertRecord, bool) {
	out, ok := runLogShow(from, to, unifiedPredicate())
	if !ok {
		// A rejected predicate must not cost us the whole window. Retry on the
		// severity tier alone, which uses only the most stable predicate
		// syntax and still catches third-party error and fault records.
		out, ok = runLogShow(from, to, severityPredicate)
		if !ok {
			return nil, false
		}
	}
	recs := parseUnifiedLogNDJSON(out)
	if len(recs) == 0 {
		return nil, false
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].Timestamp.After(recs[j].Timestamp) })
	return capRecords(recs, maxEvents, maxBytes)
}

// severityPredicate is the fallback: the narrowest widely-supported filter.
const severityPredicate = `messageType == error OR messageType == fault`

// unifiedPredicate builds the full filter described in the file comment.
func unifiedPredicate() string {
	parts := make([]string, 0, len(appleSecuritySubsystems)+1)
	for _, s := range appleSecuritySubsystems {
		parts = append(parts, `subsystem == "`+s+`"`)
	}
	parts = append(parts, severityPredicate)
	return strings.Join(parts, " OR ")
}

// runLogShow executes one `log show` query with bounded output and a deadline.
//
// Times are passed with an explicit UTC offset. `log show` interprets a bare
// timestamp in the host's local zone, so an offset-less window would shift by
// hours on any Mac not set to UTC -- and silently return the wrong minutes.
func runLogShow(from, to time.Time, predicate string) ([]byte, bool) {
	const layout = "2006-01-02 15:04:05-0700"
	ctx, cancel := context.WithTimeout(context.Background(), detectCmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "log", "show",
		"--style", "ndjson",
		"--start", from.UTC().Format(layout),
		"--end", to.UTC().Format(layout),
		"--predicate", predicate,
		"--info",  // include Info level; Default alone omits some ES records
		"--debug", // XProtect Remediator reports at debug on some releases
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, false
	}
	if err := cmd.Start(); err != nil {
		return nil, false
	}
	b, _ := readCapped(stdout, detectOutputLimit)
	_ = cmd.Wait()
	if len(b) == 0 {
		return nil, false
	}
	return b, true
}
