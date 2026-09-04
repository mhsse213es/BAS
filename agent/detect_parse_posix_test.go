package main

import (
	"strings"
	"testing"
	"time"

	"audspect/agent/protocol"
)

// ---------------------------------------------------------------------------
// journald
// ---------------------------------------------------------------------------

const journalSample = `{"__REALTIME_TIMESTAMP":"1757000553123456","PRIORITY":"3","SYSLOG_IDENTIFIER":"falcon-sensor","_COMM":"falconctl","_EXE":"/opt/CrowdStrike/falconctl","_CMDLINE":"falconctl -g --aid","_UID":"0","MESSAGE":"quarantined /tmp/evil.sh","_PID":"991"}
{"__REALTIME_TIMESTAMP":"1757000554000000","PRIORITY":"4","_COMM":"auditd","MESSAGE":"backlog limit exceeded"}
`

func TestParseJournalNDJSON_MapsFields(t *testing.T) {
	recs := parseJournalNDJSON([]byte(journalSample))
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d", len(recs))
	}
	r := recs[0]
	if r.Channel != journalChannel {
		t.Errorf("Channel = %q, want %q", r.Channel, journalChannel)
	}
	if r.Provider != "falcon-sensor" {
		t.Errorf("Provider = %q, want falcon-sensor", r.Provider)
	}
	if r.Level != "Error" {
		t.Errorf("Level = %q, want Error (PRIORITY 3)", r.Level)
	}
	want := time.Unix(1757000553, 123456000).UTC()
	if !r.Timestamp.Equal(want) {
		t.Errorf("Timestamp = %v, want %v", r.Timestamp, want)
	}
	if r.ProcessName != "falconctl" || r.ProcessPath != "/opt/CrowdStrike/falconctl" {
		t.Errorf("process = %q / %q", r.ProcessName, r.ProcessPath)
	}
	if r.CommandLine != "falconctl -g --aid" {
		t.Errorf("CommandLine = %q", r.CommandLine)
	}
	if r.Message != "quarantined /tmp/evil.sh" {
		t.Errorf("Message = %q", r.Message)
	}
}

func TestParseJournalNDJSON_ProviderFallsBackToComm(t *testing.T) {
	recs := parseJournalNDJSON([]byte(journalSample))
	if recs[1].Provider != "auditd" {
		t.Errorf("Provider = %q, want auditd (fallback to _COMM)", recs[1].Provider)
	}
	if recs[1].Level != "Warning" {
		t.Errorf("Level = %q, want Warning (PRIORITY 4)", recs[1].Level)
	}
}

// journald encodes a MESSAGE that is not valid UTF-8 as an array of byte
// values. Dropping those records would silently lose exactly the binary-ish
// output a defender emits when it logs a raw payload.
func TestParseJournalNDJSON_ByteArrayMessage(t *testing.T) {
	line := `{"__REALTIME_TIMESTAMP":"1757000553000000","PRIORITY":"3","_COMM":"x","MESSAGE":[104,105]}`
	recs := parseJournalNDJSON([]byte(line))
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	if recs[0].Message != "hi" {
		t.Errorf("Message = %q, want hi", recs[0].Message)
	}
}

func TestParseJournalNDJSON_SkipsJunkKeepsGood(t *testing.T) {
	in := "\n{ not json\n" + journalSample + "\n\n"
	recs := parseJournalNDJSON([]byte(in))
	if len(recs) != 2 {
		t.Fatalf("want 2 records from a batch with junk, got %d", len(recs))
	}
}

// journald stores _CMDLINE with the kernel's NUL argument separators intact.
// Left alone they corrupt the JSON the server stores, so they become spaces.
func TestParseJournalNDJSON_CmdlineNULsBecomeSpaces(t *testing.T) {
	line := `{"__REALTIME_TIMESTAMP":"1757000553000000","PRIORITY":"3","_COMM":"x","_CMDLINE":"bash\u0000-c\u0000id","MESSAGE":"m"}`
	recs := parseJournalNDJSON([]byte(line))
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	if recs[0].CommandLine != "bash -c id" {
		t.Errorf("CommandLine = %q, want %q", recs[0].CommandLine, "bash -c id")
	}
}

// ---------------------------------------------------------------------------
// auditd
// ---------------------------------------------------------------------------

const auditSample = `type=AVC msg=audit(1757000553.123:4567): avc:  denied  { execute } for  pid=1234 comm="curl" exe="/usr/bin/curl" path="/tmp/x" scontext=system_u:system_r:httpd_t:s0
type=SYSCALL msg=audit(1757000554.500:4568): arch=c000003e syscall=59 success=yes exit=0 uid=1000 comm="bash" exe="/usr/bin/bash" key="susp_exec"
type=SYSCALL msg=audit(1757000555.000:4569): arch=c000003e syscall=59 success=yes uid=0 comm="ls" exe="/usr/bin/ls" key=(null)
type=CRED_ACQ msg=audit(1757000556.000:4570): pid=9 uid=0 comm="sudo"
`

func auditWindow() (time.Time, time.Time) {
	return time.Unix(1757000553, 0), time.Unix(1757000560, 0)
}

func TestParseAuditLog_KeepsDenialsAndKeyedRecords(t *testing.T) {
	from, to := auditWindow()
	recs := parseAuditLog([]byte(auditSample), from, to)
	if len(recs) != 2 {
		t.Fatalf("want 2 records (AVC + keyed SYSCALL), got %d: %+v", len(recs), recs)
	}
	avc := recs[0]
	if avc.Channel != auditChannel {
		t.Errorf("Channel = %q, want %q", avc.Channel, auditChannel)
	}
	if avc.Provider != "curl" {
		t.Errorf("Provider = %q, want curl", avc.Provider)
	}
	if avc.ProcessPath != "/usr/bin/curl" {
		t.Errorf("ProcessPath = %q", avc.ProcessPath)
	}
	if !strings.HasPrefix(avc.Message, "type=AVC ") {
		t.Errorf("Message must retain the raw record type, got %q", avc.Message)
	}
	want := time.Unix(1757000553, 123000000).UTC()
	if !avc.Timestamp.Equal(want) {
		t.Errorf("Timestamp = %v, want %v", avc.Timestamp, want)
	}
}

// key=(null) means no operator rule key was set. Treating it as keyed would
// pull in every syscall on the box.
func TestParseAuditLog_NullKeyIsNotKeyed(t *testing.T) {
	from, to := auditWindow()
	for _, r := range parseAuditLog([]byte(auditSample), from, to) {
		if strings.Contains(r.Message, `comm="ls"`) {
			t.Fatalf("record with key=(null) must not be collected: %q", r.Message)
		}
	}
}

func TestParseAuditLog_DropsRecordsOutsideWindow(t *testing.T) {
	from := time.Unix(1757000554, 0)
	to := time.Unix(1757000554, 900000000)
	recs := parseAuditLog([]byte(auditSample), from, to)
	if len(recs) != 1 {
		t.Fatalf("want 1 in-window record, got %d", len(recs))
	}
	if recs[0].Provider != "bash" {
		t.Errorf("Provider = %q, want bash", recs[0].Provider)
	}
}

func TestParseAuditLog_SkipsUnparseableLines(t *testing.T) {
	from, to := auditWindow()
	in := "garbage\ntype=AVC msg=audit(nope): x\n" + auditSample
	if got := len(parseAuditLog([]byte(in), from, to)); got != 2 {
		t.Fatalf("want 2 records despite junk, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// macOS unified log
// ---------------------------------------------------------------------------

const unifiedSample = `{"gap":{"start":"a","end":"b"}}
{"timestamp":"2026-09-04 11:22:33.123456+0000","messageType":"Error","subsystem":"com.apple.syspolicy","category":"default","processImagePath":"/usr/libexec/syspolicyd","eventMessage":"GK evaluateScanResult: blocked","processID":123}
{"timestamp":"2026-09-04 11:22:34.000000+0000","messageType":"Fault","subsystem":"com.apple.xprotect","processImagePath":"/usr/libexec/XProtectRemediator","eventMessage":"remediation failed"}
`

func TestParseUnifiedLogNDJSON_MapsFields(t *testing.T) {
	recs := parseUnifiedLogNDJSON([]byte(unifiedSample))
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d", len(recs))
	}
	r := recs[0]
	if r.Channel != "com.apple.syspolicy" {
		t.Errorf("Channel = %q, want the subsystem", r.Channel)
	}
	if r.Provider != "syspolicyd" {
		t.Errorf("Provider = %q, want syspolicyd (basename of the image path)", r.Provider)
	}
	if r.Level != "Error" {
		t.Errorf("Level = %q, want Error", r.Level)
	}
	if r.ProcessPath != "/usr/libexec/syspolicyd" {
		t.Errorf("ProcessPath = %q", r.ProcessPath)
	}
	want := time.Date(2026, 9, 4, 11, 22, 33, 123456000, time.UTC)
	if !r.Timestamp.Equal(want) {
		t.Errorf("Timestamp = %v, want %v", r.Timestamp, want)
	}
}

func TestParseUnifiedLogNDJSON_FaultIsCritical(t *testing.T) {
	recs := parseUnifiedLogNDJSON([]byte(unifiedSample))
	if recs[1].Level != "Critical" {
		t.Errorf("Level = %q, want Critical for a Fault", recs[1].Level)
	}
}

func TestParseUnifiedLogNDJSON_SkipsNonLogLines(t *testing.T) {
	// The gap object in the sample carries no timestamp or message and must
	// not become a phantom alert.
	for _, r := range parseUnifiedLogNDJSON([]byte(unifiedSample)) {
		if r.Message == "" {
			t.Fatalf("collected a record with no message: %+v", r)
		}
	}
}

// ---------------------------------------------------------------------------
// Cross-parser invariant: the agent observes, it never concludes.
// ---------------------------------------------------------------------------

func TestPOSIXParsers_NeverManufactureADetection(t *testing.T) {
	from, to := auditWindow()
	batches := map[string][]protocol.AlertRecord{
		"journal": parseJournalNDJSON([]byte(journalSample)),
		"audit":   parseAuditLog([]byte(auditSample), from, to),
		"unified": parseUnifiedLogNDJSON([]byte(unifiedSample)),
	}
	for name, recs := range batches {
		if len(recs) == 0 {
			t.Fatalf("%s: fixture produced no records", name)
		}
		for _, r := range recs {
			// ThreatName is a defender's own verdict. No POSIX source states
			// one, so inferring it from message text would be the agent
			// deciding what counts as a detection -- the server's job.
			if r.ThreatName != "" {
				t.Errorf("%s: ThreatName = %q, must stay empty on POSIX", name, r.ThreatName)
			}
			// EventID is a Windows concept with no POSIX equivalent.
			if r.EventID != 0 {
				t.Errorf("%s: EventID = %d, must stay 0 on POSIX", name, r.EventID)
			}
			if r.Timestamp.IsZero() {
				t.Errorf("%s: record has no timestamp: %+v", name, r)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// syslog text fallback (hosts with no journald)
// ---------------------------------------------------------------------------

const syslogSample = `Sep  4 11:22:33 web01 falcon-sensor[991]: quarantined /tmp/evil.sh
Sep  4 11:22:34 web01 sshd[1234]: Failed password for root from 10.0.0.5
Sep  6 00:00:01 web01 cron: outside the window
not a syslog line at all
`

func TestParseSyslogLines_MapsFields(t *testing.T) {
	from := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC)
	recs := parseSyslogLines([]byte(syslogSample), from, to, time.UTC)
	if len(recs) != 2 {
		t.Fatalf("want 2 in-window records, got %d: %+v", len(recs), recs)
	}
	r := recs[0]
	if r.Channel != syslogChannel {
		t.Errorf("Channel = %q, want %q", r.Channel, syslogChannel)
	}
	if r.Provider != "falcon-sensor" || r.ProcessName != "falcon-sensor" {
		t.Errorf("Provider/ProcessName = %q / %q", r.Provider, r.ProcessName)
	}
	if r.Message != "quarantined /tmp/evil.sh" {
		t.Errorf("Message = %q", r.Message)
	}
	want := time.Date(2026, 9, 4, 11, 22, 33, 0, time.UTC)
	if !r.Timestamp.Equal(want) {
		t.Errorf("Timestamp = %v, want %v", r.Timestamp, want)
	}
}

// A syslog text file records no priority, so claiming a level would be an
// invention. The field stays empty and the server sees the difference.
func TestParseSyslogLines_HasNoLevel(t *testing.T) {
	from := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC)
	for _, r := range parseSyslogLines([]byte(syslogSample), from, to, time.UTC) {
		if r.Level != "" {
			t.Errorf("Level = %q, must stay empty: syslog text carries no priority", r.Level)
		}
	}
}

// Syslog timestamps carry no year. A run spanning New Year must not date
// December lines a year into the future and drop them from the window.
func TestParseSyslogLines_HandlesYearRollover(t *testing.T) {
	from := time.Date(2026, 12, 31, 23, 0, 0, 0, time.UTC)
	to := time.Date(2027, 1, 1, 1, 0, 0, 0, time.UTC)
	in := "Dec 31 23:30:00 h prog: before midnight\nJan  1 00:30:00 h prog: after midnight\n"
	recs := parseSyslogLines([]byte(in), from, to, time.UTC)
	if len(recs) != 2 {
		t.Fatalf("want both sides of the rollover, got %d: %+v", len(recs), recs)
	}
	if recs[0].Timestamp.Year() != 2026 {
		t.Errorf("Dec line year = %d, want 2026", recs[0].Timestamp.Year())
	}
	if recs[1].Timestamp.Year() != 2027 {
		t.Errorf("Jan line year = %d, want 2027", recs[1].Timestamp.Year())
	}
}

func TestParseSyslogLines_TagWithoutPID(t *testing.T) {
	from := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC)
	in := "Sep  4 11:22:33 web01 auditd: rules loaded\n"
	recs := parseSyslogLines([]byte(in), from, to, time.UTC)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	if recs[0].Provider != "auditd" {
		t.Errorf("Provider = %q, want auditd", recs[0].Provider)
	}
	if recs[0].Message != "rules loaded" {
		t.Errorf("Message = %q", recs[0].Message)
	}
}
