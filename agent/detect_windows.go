//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// alertChannels are the alert-tier Windows logs scanned for detections. Defender
// Operational carries real AV/EDR detections; AppLocker/WDAC carry block events.
// Third-party EDRs land in Application/System and are recognised server-side by
// provider regex — so we collect those channels too and let the server filter.
var alertChannels = []string{
	"Microsoft-Windows-Windows Defender/Operational",
	"Microsoft-Windows-AppLocker/EXE and DLL",
	"Microsoft-Windows-AppLocker/MSI and Script",
	"Microsoft-Windows-CodeIntegrity/Operational",
	"Microsoft-Windows-Sysmon/Operational",
	"Application",
	"System",
}

// collectAlerts reads alertChannels in [from,to] and returns structured records,
// newest-first, capped at maxEvents / maxBytes (bool = truncated). Best-effort:
// any failure returns (nil,false). The agent does NOT decide what is a detection.
func collectAlerts(from, to time.Time, maxEvents, maxBytes int) ([]AlertRecord, bool) {
	fromStr := from.UTC().Format("2006-01-02T15:04:05")
	toStr := to.UTC().Format("2006-01-02T15:04:05")
	logsArr := "'" + strings.Join(alertChannels, "','") + "'"
	// Emit one JSON object per event; the agent parses, never interprets.
	ps := fmt.Sprintf(`
$from=[datetime]'%s'; $to=[datetime]'%s'
$logs=@(%s)
$out=New-Object System.Collections.ArrayList
foreach($log in $logs){
  try{
    $evts=Get-WinEvent -MaxEvents 300 -FilterHashtable @{LogName=$log;StartTime=$from;EndTime=$to} -ErrorAction SilentlyContinue
    foreach($e in $evts){
      $x=[xml]$e.ToXml()
      $data=@{}
      if($x.Event.EventData.Data){ foreach($d in $x.Event.EventData.Data){ if($d.Name){ $data[$d.Name]=$d.'#text' } } }
      [void]$out.Add([pscustomobject]@{
        channel=$log; provider=$e.ProviderName; eventId=$e.Id;
        level=$e.LevelDisplayName; ts=$e.TimeCreated.ToUniversalTime().ToString('o');
        threatName=$data['Threat Name']; processName=$data['Process Name'];
        processPath=$data['Path']; commandLine=$data['Command Line'];
        user=$data['User']; message=($e.Message -replace '\s+',' ');
      })
    }
  }catch{}
}
$out | ConvertTo-Json -Depth 3 -Compress
`, fromStr, toStr, logsArr)

	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-Command", ps).Output()
	if err != nil || len(out) == 0 {
		return nil, false
	}
	raw := strings.TrimSpace(string(out))
	if raw == "" || raw == "null" {
		return nil, false
	}
	if raw[0] == '{' { // ConvertTo-Json emits a bare object for a single event
		raw = "[" + raw + "]"
	}
	var wire []struct {
		Channel, Provider, Level, TS, ThreatName, ProcessName, ProcessPath, CommandLine, User, Message string
		EventID int
	}
	if err := json.Unmarshal([]byte(raw), &wire); err != nil {
		return nil, false
	}
	recs := make([]AlertRecord, 0, len(wire))
	for _, w := range wire {
		ts, _ := time.Parse(time.RFC3339, w.TS)
		recs = append(recs, AlertRecord{
			Channel: w.Channel, Provider: w.Provider, EventID: w.EventID, Level: w.Level,
			Timestamp: ts, ThreatName: strings.TrimSpace(w.ThreatName),
			ProcessName: w.ProcessName, ProcessPath: w.ProcessPath,
			CommandLine: w.CommandLine, User: w.User,
			Message: truncate(w.Message, 1000),
		})
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].Timestamp.After(recs[j].Timestamp) })
	return capRecords(recs, maxEvents, maxBytes)
}

// capRecords keeps at most maxEvents records and ≤ maxBytes of JSON (newest-first).
func capRecords(recs []AlertRecord, maxEvents, maxBytes int) ([]AlertRecord, bool) {
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
