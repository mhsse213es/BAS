package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"path"
	"strconv"
	"strings"
	"time"

	"audspect/agent/protocol"
)

// POSIX alert parsing.
//
// These parsers carry no build tag deliberately. Keeping them off the
// linux/darwin tags is what makes them testable from any build host, including
// the Windows machine this project is built on -- a tagged parser could only
// ever be verified by shipping it somewhere first.
//
// The parsers are pure: bytes in, records out, no host state, no clock. Every
// process spawn lives in detect_linux.go / detect_darwin.go.
//
// EVIDENCE, NOT VERDICTS. These functions translate a log line into an
// AlertRecord and nothing more. An AlertRecord is an observation that something
// was logged; whether it constitutes a detection of a simulated action is
// decided server-side, exactly as it already is for Windows. Two consequences
// are load-bearing and enforced by TestPOSIXParsers_NeverManufactureADetection:
//
//   - ThreatName stays empty. It is a defender's own verdict string. No POSIX
//     source emits one in a structured field, and scraping it out of message
//     text would be the agent deciding what counts as malicious.
//   - EventID stays 0. It is a Windows Event Log concept with no POSIX
//     equivalent, and inventing a stable numbering would create a second,
//     divergent detection model.
//
// What the parsers DO decide is which records are worth carrying at all. That
// selection is content-neutral by construction -- severity tier, kernel record
// type, or an operator-chosen audit rule key -- never a match on message text.

const (
	journalChannel = "journal"
	auditChannel   = "auditd"
	syslogChannel  = "syslog"

	// maxMessageLen matches the Windows collector so a record costs the same
	// against maxBytes regardless of which platform produced it.
	maxMessageLen = 1000

	// scanBufLimit bounds a single log line. Journal entries carrying a full
	// command line comfortably exceed bufio's 64KB default.
	scanBufLimit = 1 << 20
)

// lineScanner returns a scanner sized for real log lines rather than bufio's
// default, which would silently truncate the batch at the first long entry.
func lineScanner(b []byte) *bufio.Scanner {
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), scanBufLimit)
	return sc
}

// ---------------------------------------------------------------------------
// journald
// ---------------------------------------------------------------------------

// journalEntry mirrors `journalctl -o json`. Every field is RawMessage because
// journald types them inconsistently: a value is normally a string, but becomes
// an array of byte values when it is not valid UTF-8, and _PID-style fields can
// arrive as bare numbers.
type journalEntry struct {
	Realtime json.RawMessage `json:"__REALTIME_TIMESTAMP"`
	Priority json.RawMessage `json:"PRIORITY"`
	Ident    json.RawMessage `json:"SYSLOG_IDENTIFIER"`
	Comm     json.RawMessage `json:"_COMM"`
	Exe      json.RawMessage `json:"_EXE"`
	Cmdline  json.RawMessage `json:"_CMDLINE"`
	UID      json.RawMessage `json:"_UID"`
	Message  json.RawMessage `json:"MESSAGE"`
}

// jstr decodes one journald value to text, tolerating all three shapes above.
func jstr(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var by []byte
	if err := json.Unmarshal(raw, &by); err == nil {
		return string(by)
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err == nil {
		return n.String()
	}
	return ""
}

// parseJournalNDJSON converts `journalctl -o json` output into alert records,
// preserving input order. Lines that do not parse, or that carry no usable
// timestamp, are skipped rather than failing the batch: one corrupt entry must
// not cost us the rest of the window's evidence.
func parseJournalNDJSON(b []byte) []protocol.AlertRecord {
	var out []protocol.AlertRecord
	sc := lineScanner(b)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var e journalEntry
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}
		usec, err := strconv.ParseInt(jstr(e.Realtime), 10, 64)
		if err != nil || usec <= 0 {
			continue // no timestamp means the record cannot be correlated
		}
		provider := jstr(e.Ident)
		comm := jstr(e.Comm)
		if provider == "" {
			provider = comm
		}
		user := ""
		if uid := jstr(e.UID); uid != "" {
			// The numeric id is what the journal actually recorded. Resolving
			// it to a name would need a host lookup this parser must not do,
			// so it is labelled rather than passed off as a username.
			user = "uid=" + uid
		}
		out = append(out, protocol.AlertRecord{
			Channel:   journalChannel,
			Provider:  provider,
			Level:     levelFromSyslogPriority(jstr(e.Priority)),
			Timestamp: time.Unix(usec/1e6, (usec%1e6)*1000).UTC(),
			// journald keeps the kernel's NUL argument separators in _CMDLINE.
			ProcessName: comm,
			ProcessPath: jstr(e.Exe),
			CommandLine: strings.ReplaceAll(jstr(e.Cmdline), "\x00", " "),
			User:        user,
			Message:     truncate(strings.TrimSpace(jstr(e.Message)), maxMessageLen),
		})
	}
	return out
}

// levelFromSyslogPriority maps a syslog priority (RFC 5424, 0 = emerg) onto the
// same level vocabulary the Windows collector emits, so the server has one set
// of level names to reason about rather than one per platform.
func levelFromSyslogPriority(p string) string {
	switch p {
	case "0", "1", "2":
		return "Critical"
	case "3":
		return "Error"
	case "4":
		return "Warning"
	case "5", "6":
		return "Information"
	case "7":
		return "Verbose"
	}
	return ""
}

// ---------------------------------------------------------------------------
// auditd
// ---------------------------------------------------------------------------

// auditAlertTypes are the kernel record types that report a denial, a policy
// change, or an anomaly. Selecting on record type is content-neutral: it is the
// audit subsystem's own classification, not our reading of the message. This is
// the direct analogue of the Windows collector picking alert-tier channels.
var auditAlertTypes = map[string]bool{
	"AVC":                true,
	"USER_AVC":           true,
	"AVC_PATH":           true,
	"SELINUX_ERR":        true,
	"USER_SELINUX_ERR":   true,
	"APPARMOR_DENIED":    true,
	"ANOM_ABEND":         true,
	"ANOM_ACCESS_FS":     true,
	"ANOM_EXEC":          true,
	"ANOM_LINK":          true,
	"ANOM_PROMISCUOUS":   true,
	"SECCOMP":            true,
	"MAC_POLICY_LOAD":    true,
	"MAC_STATUS":         true,
	"INTEGRITY_DATA":     true,
	"INTEGRITY_METADATA": true,
	"INTEGRITY_PCR":      true,
	"INTEGRITY_RULE":     true,
	"FANOTIFY":           true,
}

// parseAuditLog converts raw audit.log text into alert records for the window
// [from,to], preserving input order.
//
// A record is carried when either:
//   - its type is in auditAlertTypes, or
//   - it carries a non-null rule key, meaning an operator wrote a watch rule
//     and tagged it. That tag is the operator's own statement that the rule is
//     noteworthy, so honouring it adds signal without us judging content.
//
// Everything else is dropped at the source. audit.log on a busy host is
// dominated by routine SYSCALL records; carrying them would flood the cap and
// push real denials out of the newest-first window.
func parseAuditLog(b []byte, from, to time.Time) []protocol.AlertRecord {
	var out []protocol.AlertRecord
	sc := lineScanner(b)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "type=") {
			continue
		}
		rtype := auditField(line, "type=")
		if rtype == "" {
			continue
		}
		ts, ok := parseAuditTimestamp(line)
		if !ok || ts.Before(from) || ts.After(to) {
			continue
		}
		key := auditQuoted(line, "key=")
		keyed := key != "" && key != "(null)"
		if !auditAlertTypes[rtype] && !keyed {
			continue
		}
		comm := auditQuoted(line, "comm=")
		level := "Information"
		if auditAlertTypes[rtype] {
			// The record type itself states a denial or anomaly occurred.
			// That is the kernel's classification, not our interpretation.
			level = "Warning"
		}
		out = append(out, protocol.AlertRecord{
			Channel:     auditChannel,
			Provider:    comm,
			Level:       level,
			Timestamp:   ts,
			ProcessName: comm,
			ProcessPath: auditQuoted(line, "exe="),
			User:        auditUser(line),
			// The whole raw line is the evidence, and it already carries the
			// record type, so nothing has to be synthesised to preserve it.
			Message: truncate(line, maxMessageLen),
		})
	}
	return out
}

// parseAuditTimestamp reads the msg=audit(<secs>.<millis>:<serial>) stamp.
func parseAuditTimestamp(line string) (time.Time, bool) {
	i := strings.Index(line, "msg=audit(")
	if i < 0 {
		return time.Time{}, false
	}
	rest := line[i+len("msg=audit("):]
	j := strings.IndexByte(rest, ':')
	if j < 0 {
		return time.Time{}, false
	}
	stamp := rest[:j]
	dot := strings.IndexByte(stamp, '.')
	if dot < 0 {
		return time.Time{}, false
	}
	secs, err := strconv.ParseInt(stamp[:dot], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	millis, err := strconv.ParseInt(stamp[dot+1:], 10, 64)
	if err != nil || millis < 0 || millis > 999 {
		return time.Time{}, false
	}
	return time.Unix(secs, millis*int64(time.Millisecond)).UTC(), true
}

// auditField reads an unquoted key=value token.
func auditField(line, key string) string {
	i := strings.Index(line, key)
	if i < 0 {
		return ""
	}
	v := line[i+len(key):]
	if j := strings.IndexAny(v, " \t"); j >= 0 {
		v = v[:j]
	}
	return v
}

// auditQuoted reads a key="value" token, falling back to the unquoted form
// that auditd uses for hex-encoded or null values.
func auditQuoted(line, key string) string {
	i := strings.Index(line, key)
	if i < 0 {
		return ""
	}
	v := line[i+len(key):]
	if strings.HasPrefix(v, `"`) {
		v = v[1:]
		if j := strings.IndexByte(v, '"'); j >= 0 {
			return v[:j]
		}
		return ""
	}
	if j := strings.IndexAny(v, " \t"); j >= 0 {
		v = v[:j]
	}
	return v
}

// auditUser prefers the audit login uid, which survives su/sudo and so names
// the human behind the action rather than the effective account.
func auditUser(line string) string {
	for _, k := range []string{"auid=", "uid="} {
		if v := auditField(line, k); v != "" && v != "4294967295" {
			return "uid=" + v
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// macOS unified log
// ---------------------------------------------------------------------------

// unifiedEntry mirrors one object from `log show --style ndjson`.
type unifiedEntry struct {
	Timestamp        string `json:"timestamp"`
	MessageType      string `json:"messageType"`
	Subsystem        string `json:"subsystem"`
	Category         string `json:"category"`
	ProcessImagePath string `json:"processImagePath"`
	SenderImagePath  string `json:"senderImagePath"`
	EventMessage     string `json:"eventMessage"`
}

// unifiedTimeLayouts covers the stamp shapes `log show` emits across releases.
var unifiedTimeLayouts = []string{
	"2006-01-02 15:04:05.999999-0700",
	"2006-01-02 15:04:05-0700",
	time.RFC3339Nano,
}

// parseUnifiedLogNDJSON converts `log show --style ndjson` output into alert
// records, preserving input order.
//
// The stream is not purely log entries: it is interleaved with bookkeeping
// objects such as {"gap":...} that describe coverage rather than events.
// Requiring both a parseable timestamp and a message drops those, so a gap
// marker can never surface as a phantom alert with an empty body.
func parseUnifiedLogNDJSON(b []byte) []protocol.AlertRecord {
	var out []protocol.AlertRecord
	sc := lineScanner(b)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var e unifiedEntry
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}
		msg := strings.TrimSpace(e.EventMessage)
		if msg == "" {
			continue
		}
		ts, ok := parseUnifiedTimestamp(e.Timestamp)
		if !ok {
			continue
		}
		channel := e.Subsystem
		if channel == "" {
			channel = "unifiedlog"
		}
		procPath := e.ProcessImagePath
		if procPath == "" {
			procPath = e.SenderImagePath
		}
		procName := ""
		if procPath != "" {
			// These are always POSIX paths, so path.Base is correct here even
			// though this file also compiles on Windows.
			procName = path.Base(procPath)
		}
		out = append(out, protocol.AlertRecord{
			Channel:     channel,
			Provider:    procName,
			Level:       levelFromUnifiedMessageType(e.MessageType),
			Timestamp:   ts,
			ProcessName: procName,
			ProcessPath: procPath,
			Message:     truncate(msg, maxMessageLen),
		})
	}
	return out
}

func parseUnifiedTimestamp(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range unifiedTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// levelFromUnifiedMessageType maps os_log levels onto the Windows collector's
// level vocabulary, for the same single-vocabulary reason as the syslog map.
func levelFromUnifiedMessageType(t string) string {
	switch strings.ToLower(t) {
	case "fault":
		return "Critical"
	case "error":
		return "Error"
	case "default":
		return "Information"
	case "info":
		return "Information"
	case "debug":
		return "Verbose"
	}
	return ""
}

// ---------------------------------------------------------------------------
// syslog text files (hosts with no journald)
// ---------------------------------------------------------------------------

// syslogStamp is the RFC 3164 timestamp: month, space-padded day, wall time.
// It carries neither a year nor a zone, which is the source of both quirks
// this parser has to handle.
const syslogStamp = "Jan _2 15:04:05"

// parseSyslogLines converts a classic /var/log/syslog style file into alert
// records for the window [from,to], preserving input order.
//
// This is the last-resort source, used only when journald produced nothing --
// a container or a non-systemd host. It is strictly weaker than the journal
// and the record shape says so rather than papering over it:
//
//   - Level stays empty. The text file records no priority, so any level would
//     be invented. An empty level is the honest statement that this source
//     cannot rank severity, and it is why the collector cannot pre-filter to
//     an alert tier here the way it does on the journal.
//   - There is no command line, executable path or uid to read.
//
// loc is the zone the timestamps are interpreted in -- time.Local in
// production, since the writing host stamped them in its own wall time. Taking
// it as an argument is what keeps the tests independent of the build host.
func parseSyslogLines(b []byte, from, to time.Time, loc *time.Location) []protocol.AlertRecord {
	if loc == nil {
		loc = time.Local
	}
	var out []protocol.AlertRecord
	sc := lineScanner(b)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r\n")
		if len(line) < len(syslogStamp) {
			continue
		}
		ts, ok := parseSyslogTimestamp(line[:15], from, to, loc)
		if !ok || ts.Before(from) || ts.After(to) {
			continue
		}
		// After the stamp: "<host> <tag>[<pid>]: <message>".
		rest := strings.TrimSpace(line[15:])
		sp := strings.IndexByte(rest, ' ')
		if sp < 0 {
			continue
		}
		rest = strings.TrimSpace(rest[sp+1:]) // drop the hostname
		colon := strings.IndexByte(rest, ':')
		if colon < 0 {
			continue
		}
		tag := rest[:colon]
		msg := strings.TrimSpace(rest[colon+1:])
		if br := strings.IndexByte(tag, '['); br >= 0 {
			tag = tag[:br] // strip the [pid] suffix
		}
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		out = append(out, protocol.AlertRecord{
			Channel:     syslogChannel,
			Provider:    tag,
			Timestamp:   ts,
			ProcessName: tag,
			Message:     truncate(msg, maxMessageLen),
		})
	}
	return out
}

// parseSyslogTimestamp dates a yearless stamp against the collection window.
//
// The stamp has no year, so it is first read against the window's start year.
// A run that spans New Year then misdates one side by twelve months, in either
// direction, and the misdated records fall outside the window and vanish:
//   - a December line read against a window that started in January lands ~12
//     months in the future, so it steps back a year;
//   - a January line read against a window that started in December lands ~12
//     months in the past, so it steps forward a year.
//
// A shifted candidate is only accepted when it actually lands inside the
// window, so an ordinary out-of-window line is never dragged into it.
func parseSyslogTimestamp(stamp string, from, to time.Time, loc *time.Location) (time.Time, bool) {
	t, err := time.ParseInLocation(syslogStamp, stamp, loc)
	if err != nil {
		return time.Time{}, false
	}
	ts := time.Date(from.In(loc).Year(), t.Month(), t.Day(),
		t.Hour(), t.Minute(), t.Second(), 0, loc)
	inWindow := func(c time.Time) bool { return !c.Before(from) && !c.After(to) }
	if !inWindow(ts) {
		for _, shift := range []int{-1, 1} {
			if c := ts.AddDate(shift, 0, 0); inWindow(c) {
				ts = c
				break
			}
		}
	}
	return ts, true
}
