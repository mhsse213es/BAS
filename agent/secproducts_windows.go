//go:build windows

package main

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// enumerateSecurityProducts gathers the security products present on this
// endpoint so the report can state what was protecting it during the run. This
// is pure data collection (the dumb-executor's job); the server decides what the
// inventory means. Sources, in order of reliability:
//   - WMI root/SecurityCenter2 AntiVirusProduct — registered AV/EDR (incl. Defender)
//   - Get-MpComputerStatus — Microsoft Defender real-time protection state
//   - service-name probe — EDRs that do not register in SecurityCenter2
//
// Third-party EDR ALERTS are not locally observable; we only report presence.
func enumerateSecurityProducts() []string {
	const ps = `
$out = New-Object System.Collections.Generic.List[string]
try {
  $av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
  foreach ($a in $av) { if ($a.displayName) { $out.Add("AV: " + $a.displayName) } }
} catch {}
try {
  $d = Get-MpComputerStatus -ErrorAction SilentlyContinue
  if ($d) {
    if ($d.RealTimeProtectionEnabled) { $out.Add("Microsoft Defender (real-time protection ON)") }
    else { $out.Add("Microsoft Defender (real-time protection OFF)") }
  }
} catch {}
$svc = [ordered]@{
  "CSFalconService"="CrowdStrike Falcon"; "SentinelAgent"="SentinelOne";
  "xagt"="Trellix/FireEye HX"; "mfemms"="Trellix/McAfee ENS"; "masvc"="McAfee Agent";
  "CylanceSvc"="Cylance"; "cbdefense"="Carbon Black Defense"; "CarbonBlack"="VMware Carbon Black";
  "Sysmon"="Sysmon"; "Sysmon64"="Sysmon"; "TaniumClient"="Tanium"
}
foreach ($k in $svc.Keys) {
  try { if (Get-Service -Name $k -ErrorAction SilentlyContinue) { $out.Add("EDR: " + $svc[$k]) } } catch {}
}
($out | Sort-Object -Unique) -join "` + "`n" + `"
`
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "powershell",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-Command", ps).Output()
	if err != nil || len(out) == 0 {
		return nil
	}

	var products []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(out), "\n") {
		p := strings.TrimSpace(line)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		products = append(products, p)
	}
	return products
}
