# Cobalt Group BFSI - Subdomain Enumeration (recon-01)
$domain = 'bas-sim.test'
$names = @('www', 'mail', 'api', 'vpn', 'portal', 'intranet', 'sso', 'dev')
$attempted = 0
$answered = 0
$nxdomain = 0
$unclassifiable = 0
foreach ($n in $names) {
  $fqdn = "$n.$domain"
  if (-not $fqdn.EndsWith('.test')) { Complete-CgStep @{ Outcome = 'error'; Reason = "Refusing to query non-.test name $fqdn" } 'RECON-01' }
  $attempted++
  try {
    $r = Resolve-DnsName -Name $fqdn -Type A -DnsOnly -ErrorAction Stop
    if ($r) { $answered++ } else { $nxdomain++ }
  } catch {
    if ($_.Exception.Message -match 'not exist|DNS name does not exist|NameError|NXDOMAIN') { $nxdomain++ } else { $unclassifiable++ }
  }
}

if ($attempted -eq $names.Count -and $unclassifiable -eq 0) {
  $res = @{ Outcome = 'pass'; Reason = "Attempted $attempted subdomain queries under $domain ($answered answered, $nxdomain NXDOMAIN)" }
} elseif ($unclassifiable -gt 0) {
  $res = @{ Outcome = 'error'; Reason = "$unclassifiable of $attempted subdomain queries returned an unclassifiable error" }
} else {
  $res = @{ Outcome = 'fail'; Reason = "Only $attempted of $($names.Count) subdomain queries were attempted" }
}
Complete-CgStep $res 'RECON-01'
