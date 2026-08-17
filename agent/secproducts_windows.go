//go:build windows

package main

import (
	"context"
	"fmt"
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
//   - registry Uninstall-key scan — catches a product whose service is
//     stopped, not yet started at agent boot, or hidden from Get-Service by
//     EDR self-protection/tamper-protection; reading Uninstall keys doesn't
//     touch the live process/WMI surface those protections police
//
// Third-party EDR ALERTS are not locally observable; we only report presence.
//
// enumerateSecurityProducts is a single one-shot pass cached for the agent's
// lifetime (see agent.go), so a product whose service starts after this runs
// will not appear until the agent restarts.
//
// Every sub-check here can legitimately find nothing (product not installed)
// or fail to look (query error, EDR blocking, timeout). Those two cases used
// to be indistinguishable — both silently produced an empty result. diag now
// carries the failure reasons so the caller can log them instead of the
// absence looking identical to "not installed".
func enumerateSecurityProducts() (products []string, diag []string) {
	const ps = `
$out = New-Object System.Collections.Generic.List[string]
$diag = New-Object System.Collections.Generic.List[string]
try {
  $av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop
  foreach ($a in $av) { if ($a.displayName) { $out.Add("AV: " + $a.displayName) } }
  if (-not $av) { $diag.Add("DIAG: SecurityCenter2 returned no products") }
} catch { $diag.Add("DIAG: SecurityCenter2 query failed: " + $_.Exception.Message) }
try {
  $d = Get-MpComputerStatus -ErrorAction Stop
  if ($d) {
    if ($d.RealTimeProtectionEnabled) { $out.Add("Microsoft Defender (real-time protection ON)") }
    else { $out.Add("Microsoft Defender (real-time protection OFF)") }
  }
} catch { $diag.Add("DIAG: Get-MpComputerStatus failed: " + $_.Exception.Message) }
$svc = [ordered]@{
  "CSFalconService"="CrowdStrike Falcon"; "SentinelAgent"="SentinelOne";
  "xagt"="Trellix/FireEye HX"; "mfemms"="Trellix/McAfee ENS"; "masvc"="McAfee Agent";
  "CylanceSvc"="Cylance"; "cbdefense"="Carbon Black Defense"; "CarbonBlack"="VMware Carbon Black";
  "Sysmon"="Sysmon"; "Sysmon64"="Sysmon"; "TaniumClient"="Tanium"
}
$foundViaSvc = New-Object System.Collections.Generic.List[string]
foreach ($k in $svc.Keys) {
  try {
    if (Get-Service -Name $k -ErrorAction Stop) {
      $out.Add("EDR: " + $svc[$k])
      $foundViaSvc.Add($svc[$k])
    }
  } catch {}
}
$regPatterns = [ordered]@{
  "CrowdStrike" = "CrowdStrike Falcon"; "SentinelOne" = "SentinelOne";
  "FireEye" = "Trellix/FireEye HX"; "Trellix" = "Trellix"; "McAfee" = "McAfee";
  "Cylance" = "Cylance"; "Carbon Black" = "Carbon Black"; "Tanium" = "Tanium";
  "Sophos" = "Sophos"; "Symantec" = "Symantec Endpoint Protection"
}
try {
  $installed = Get-ItemProperty -ErrorAction Stop -Path @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
  ) | Where-Object { $_.DisplayName } | Select-Object -ExpandProperty DisplayName -Unique
  foreach ($pat in $regPatterns.Keys) {
    $name = $regPatterns[$pat]
    if ($foundViaSvc.Contains($name)) { continue }
    if ($installed | Where-Object { $_ -like "*$pat*" }) { $out.Add("Installed (registry): " + $name) }
  }
} catch { $diag.Add("DIAG: registry uninstall-key scan failed: " + $_.Exception.Message) }
(($out | Sort-Object -Unique) + ($diag | Sort-Object -Unique)) -join "` + "`n" + `"
`
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "powershell",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-Command", ps).Output()
	if err != nil {
		return nil, []string{fmt.Sprintf("enumeration script failed to run: %v", err)}
	}
	if len(out) == 0 {
		return nil, []string{"enumeration script returned no output"}
	}

	seen := make(map[string]bool)
	for _, line := range strings.Split(string(out), "\n") {
		p := strings.TrimSpace(line)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		if d, ok := strings.CutPrefix(p, "DIAG: "); ok {
			diag = append(diag, d)
			continue
		}
		products = append(products, p)
	}
	return products, diag
}
