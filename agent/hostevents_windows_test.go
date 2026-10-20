//go:build windows

package main

import (
	"strings"
	"testing"
)

// Fixture shaped like the collector's output: one process creation, one network
// logon, and nothing else (4648 and other logon types are filtered on the host).
const hostEventsFixture = `[
 {"recordId":817845,"eventId":4688,"host":"WS-01","ts":"2026-10-20T09:01:03Z",
  "subject":"svc-test","newProcess":"rundll32.exe",
  "commandLine":"rundll32 svc-cred-dump-7f3a","logonType":0,"targetUser":""},
 {"recordId":820385,"eventId":4624,"host":"WS-01","ts":"2026-10-20T09:02:00Z",
  "subject":"","newProcess":"","commandLine":"","logonType":3,"targetUser":"svc-test"}
]`

func TestParseHostEvents_ReadsNamedFields(t *testing.T) {
	recs, err := parseHostEvents(hostEventsFixture)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	if recs[0].EventID != 4688 || recs[0].RecordID != 817845 || !strings.Contains(recs[0].CommandLine, "svc-cred-dump-7f3a") {
		t.Fatalf("4688 not read: %+v", recs[0])
	}
	if recs[1].EventID != 4624 || recs[1].LogonType != 3 || recs[1].TargetUser != "svc-test" {
		t.Fatalf("4624 not read: %+v", recs[1])
	}
}

// PowerShell prints nothing, or null, when there are no events. That is no events,
// not an error and not a failure to collect.
func TestParseHostEvents_EmptyIsNoEvents(t *testing.T) {
	for _, raw := range []string{"", "null", "  \n"} {
		recs, err := parseHostEvents(raw)
		if err != nil || len(recs) != 0 {
			t.Fatalf("raw %q: recs=%d err=%v", raw, len(recs), err)
		}
	}
}

func TestParseHostEvents_GarbageIsAnError(t *testing.T) {
	if _, err := parseHostEvents("not json"); err == nil {
		t.Fatalf("unparseable output must be an error, not zero events")
	}
}

// Output from `auditpol /get /r` on this build. The Inclusion Setting is the
// fifth field.
func TestParseAuditSetting_ReadsInclusionSetting(t *testing.T) {
	header := "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting\n"
	cases := map[string]string{
		"No Auditing":         "DESKTOP,System,Process Creation,{0CCE922B-69AE-11D9-BED3-505054503030},No Auditing,\n",
		"Success":             "DESKTOP,System,Process Creation,{0CCE922B-69AE-11D9-BED3-505054503030},Success,\n",
		"Success and Failure": "DESKTOP,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,\n",
	}
	want := map[string]string{"No Auditing": "disabled", "Success": "enabled", "Success and Failure": "enabled"}
	for in, line := range cases {
		if got := parseAuditSetting(header + line); got != want[in] {
			t.Errorf("%s: got %q, want %q", in, got, want[in])
		}
	}
}

// Output that cannot be read is unknown. It is never read as disabled, because that
// would hide a gap as if it were a setting.
func TestParseAuditSetting_UnreadableIsUnknownNotDisabled(t *testing.T) {
	if got := parseAuditSetting("Usage: AuditPol command"); got != "unknown" {
		t.Fatalf("got %q, want unknown", got)
	}
	if got := parseAuditSetting(""); got != "unknown" {
		t.Fatalf("empty output: got %q, want unknown", got)
	}
}
