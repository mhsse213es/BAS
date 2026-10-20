//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"audspect/agent/protocol"
)

// Subcategory GUIDs for the two audit settings the host events depend on.
const (
	auditProcessCreationGUID = "{0CCE922B-69AE-11D9-BED3-505054503030}"
	auditLogonGUID           = "{0CCE9215-69AE-11D9-BED3-505054503030}"
)

// hostEventScript collects only Security 4688, 4624 and 4648 in the window. It keeps
// interactive and network logons (types 3 and 10) and drops the rest, so the
// upload stays small. Fields come from the event's named EventData, not positions.
func hostEventScript(from, to time.Time, maxEvents int) string {
	return fmt.Sprintf(`
$from=[datetime]'%s'; $to=[datetime]'%s'
$out=New-Object System.Collections.ArrayList
try{
  $evts=Get-WinEvent -MaxEvents %d -FilterHashtable @{LogName='Security';Id=4688,4624,4648;StartTime=$from;EndTime=$to} -ErrorAction SilentlyContinue
  foreach($e in $evts){
    $x=[xml]$e.ToXml()
    $d=@{}
    foreach($n in $x.Event.EventData.Data){ if($n.Name){ $d[$n.Name]=$n.'#text' } }
    if($e.Id -eq 4624 -and @('3','10') -notcontains [string]$d['LogonType']){ continue }
    [void]$out.Add([pscustomobject]@{
      recordId=[uint64]$e.RecordId; eventId=$e.Id; host=$e.MachineName;
      ts=$e.TimeCreated.ToUniversalTime().ToString('o');
      subject=$d['SubjectUserName']; newProcess=$d['NewProcessName']; commandLine=$d['CommandLine'];
      logonType=[int]$d['LogonType']; targetUser=$d['TargetUserName']
    })
  }
}catch{}
ConvertTo-Json -InputObject @($out) -Depth 3 -Compress
`, from.UTC().Format("2006-01-02T15:04:05"), to.UTC().Format("2006-01-02T15:04:05"), maxEvents)
}

// parseHostEvents reads the collector's JSON. An empty or null result is no events,
// not an error.
func parseHostEvents(raw string) ([]protocol.HostEventRecord, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "null" {
		return nil, nil
	}
	var recs []protocol.HostEventRecord
	if err := json.Unmarshal([]byte(raw), &recs); err != nil {
		return nil, fmt.Errorf("parse host events: %w", err)
	}
	return recs, nil
}

// parseAuditSetting reads one line of `auditpol /get /r` output. The Inclusion
// Setting is the fifth field. Any success or failure state counts as enabled. A
// line it cannot read is unknown, never disabled.
func parseAuditSetting(auditpolOut string) string {
	lines := strings.Split(strings.TrimSpace(auditpolOut), "\n")
	last := strings.TrimSpace(lines[len(lines)-1])
	cols := strings.Split(last, ",")
	if len(cols) < 6 {
		return "unknown"
	}
	setting := strings.TrimSpace(cols[4])
	switch {
	case strings.Contains(setting, "Success") || strings.Contains(setting, "Failure"):
		return "enabled"
	case setting == "No Auditing":
		return "disabled"
	default:
		return "unknown"
	}
}

// probeAudit reads the two audit subcategories the host events depend on.
func probeAudit() protocol.AuditSnapshot {
	return protocol.AuditSnapshot{
		ProcessCreation: readAudit(auditProcessCreationGUID),
		Logon:           readAudit(auditLogonGUID),
		CommandLine:     readCommandLineCapture(),
	}
}

func readAudit(guid string) string {
	out, err := exec.Command("auditpol", "/get", "/subcategory:"+guid, "/r").Output()
	if err != nil {
		return "unknown"
	}
	return parseAuditSetting(string(out))
}

// collectHostEvents reads the required Security events in [from, to]. It reports
// whether the result hit maxEvents, so the caller knows it may be incomplete.
func collectHostEvents(from, to time.Time, maxEvents int) ([]protocol.HostEventRecord, bool, error) {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-Command", hostEventScript(from, to, maxEvents)).Output()
	if err != nil {
		return nil, false, fmt.Errorf("collect host events: %w", err)
	}
	recs, err := parseHostEvents(string(out))
	if err != nil {
		return nil, false, err
	}
	return recs, len(recs) >= maxEvents, nil
}

// parseCommandLineCapture reads `reg query` output for the command-line value. Only
// an explicit 0x1 or 0x0 is a setting. Anything else, including a missing value,
// is unknown.
func parseCommandLineCapture(regOut string, err error) string {
	if err != nil {
		return "unknown"
	}
	for _, line := range strings.Split(regOut, "\n") {
		if !strings.Contains(line, "ProcessCreationIncludeCmdLine_Enabled") {
			continue
		}
		switch {
		case strings.Contains(line, "0x1"):
			return "enabled"
		case strings.Contains(line, "0x0"):
			return "disabled"
		}
	}
	return "unknown"
}

const commandLineCaptureKey = `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit`

func readCommandLineCapture() string {
	out, err := exec.Command("reg", "query", commandLineCaptureKey, "/v", "ProcessCreationIncludeCmdLine_Enabled").Output()
	return parseCommandLineCapture(string(out), err)
}
