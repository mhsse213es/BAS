package detect

import (
	"regexp"
	"strings"
)

// BlockingControl identifies the specific security control that prevented a
// technique from executing. Populated only for "prevented" verdicts where a
// matching block event is found in the post-run alert sweep.
type BlockingControl struct {
	Name    string `json:"name"`              // human label, e.g. "Defender ASR: Block obfuscated scripts"
	RuleID  string `json:"ruleId,omitempty"`  // ASR GUID or AppLocker policy name
	EventID int    `json:"eventId"`           // Windows Event ID that confirmed the block
	Channel string `json:"channel"`           // source event log channel
}

// blockEventIDs maps channel → set of event IDs that confirm a block (not just
// an audit). Only IDs that mean "action taken / access denied" are included.
var blockEventIDs = map[string]map[int]bool{
	"Microsoft-Windows-Windows Defender/Operational": {
		1117: true, // Threat action taken (quarantine/remove)
		1118: true, // Remediation in progress
		1119: true, // Remediation succeeded
		1121: true, // ASR rule BLOCKED (enforce mode)
	},
	"Microsoft-Windows-AppLocker/EXE and DLL": {
		8004: true, // EXE blocked
		8007: true, // DLL blocked
	},
	"Microsoft-Windows-AppLocker/MSI and Script": {
		8004: true, // Script/MSI blocked
		8010: true, // Packaged app blocked
	},
	"Microsoft-Windows-CodeIntegrity/Operational": {
		3077: true, // WDAC kernel block
		3033: true, // Code Integrity: file not allowed (policy enforce)
	},
}

// asrGUIDRE extracts an ASR rule GUID from a Defender EID 1121/1122 event message.
var asrGUIDRE = regexp.MustCompile(`(?i)[{(]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})[})]?`)

// asrRuleNames maps well-known ASR rule GUIDs to their short human names.
var asrRuleNames = map[string]string{
	"be9ba2d9-53ea-4cdc-84e5-9b1eeee46550": "Block untrusted/unsigned executables",
	"d4f940ab-401b-4efc-aadc-ad5f3c50688a": "Block Office child processes",
	"3b576869-a4ec-4529-8536-b80a7769e899": "Block Office executable content creation",
	"75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84": "Block Office code injection",
	"d3e037e1-3eb8-44c8-a917-57927947596d": "Block JS/VBScript downloaded exec",
	"5beb7efe-fd9a-4556-801d-275e5ffc04cc": "Block obfuscated scripts",
	"92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b": "Block Win32 API calls from Office macros",
	"01443614-cd74-433a-b99e-2ecdc07bfc25": "Block exec content from email/webmail",
	"c1db55ab-c21a-4637-bb3f-a12568109d35": "Advanced ransomware protection",
	"9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0": "Block credential theft from LSASS",
	"e6db77e5-3df2-4cf1-b95a-636979351e5b": "Block WMI event subscription persistence",
	"b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4": "Block untrusted USB process execution",
	"26190899-1602-49e8-8b27-eb1d0a1ce869": "Block Office communication app child processes",
	"7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c": "Block Adobe Reader child processes",
}

// AttributeControl inspects an alert record and returns the specific security
// control that fired if the event confirms a block action. Returns nil for
// audit-only or unrecognised events.
func AttributeControl(a AlertRecord) *BlockingControl {
	ids, ok := blockEventIDs[a.Channel]
	if !ok {
		return nil
	}
	if !ids[a.EventID] {
		return nil
	}

	switch {
	// ── Defender ASR block (EID 1121) ────────────────────────────────────────
	case a.Channel == "Microsoft-Windows-Windows Defender/Operational" && a.EventID == 1121:
		ruleID := extractASRGUID(a.Message)
		name := "Defender ASR"
		if n, ok := asrRuleNames[strings.ToLower(ruleID)]; ok {
			name = "Defender ASR: " + n
		} else if ruleID != "" {
			name = "Defender ASR rule " + ruleID
		}
		return &BlockingControl{Name: name, RuleID: ruleID, EventID: a.EventID, Channel: a.Channel}

	// ── Defender AV block (EID 1117–1119) ────────────────────────────────────
	case a.Channel == "Microsoft-Windows-Windows Defender/Operational":
		label := "Defender Antivirus"
		if a.ThreatName != "" {
			label += " (" + a.ThreatName + ")"
		}
		return &BlockingControl{Name: label, EventID: a.EventID, Channel: a.Channel}

	// ── AppLocker EXE/DLL block ───────────────────────────────────────────────
	case strings.HasSuffix(a.Channel, "/EXE and DLL") && (a.EventID == 8004 || a.EventID == 8007):
		kind := "EXE"
		if a.EventID == 8007 {
			kind = "DLL"
		}
		return &BlockingControl{Name: "AppLocker (" + kind + " policy)", EventID: a.EventID, Channel: a.Channel}

	// ── AppLocker Script/MSI/Packaged block ───────────────────────────────────
	case strings.HasSuffix(a.Channel, "/MSI and Script") && (a.EventID == 8004 || a.EventID == 8010):
		kind := "Script/MSI"
		if a.EventID == 8010 {
			kind = "Packaged App"
		}
		return &BlockingControl{Name: "AppLocker (" + kind + " policy)", EventID: a.EventID, Channel: a.Channel}

	// ── WDAC / Code Integrity block ───────────────────────────────────────────
	case a.Channel == "Microsoft-Windows-CodeIntegrity/Operational":
		return &BlockingControl{Name: "WDAC / Code Integrity", EventID: a.EventID, Channel: a.Channel}
	}

	return nil
}

func extractASRGUID(msg string) string {
	m := asrGUIDRE.FindStringSubmatch(msg)
	if len(m) >= 2 {
		return strings.ToLower(m[1])
	}
	return ""
}
