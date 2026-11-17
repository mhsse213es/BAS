#region core needs=
# AD CS audit library. READ ONLY: nothing here requests a certificate, changes a template or CA object, or writes to the
# registry. Analysis functions take plain descriptors (see the fixtures) and do no I/O, so they are tested without AD.
# Collectors (the "collect_*" regions) build the descriptors from LDAP, the CA registry and one optional HTTP probe.
$script:AdcsTier0 = @('S-1-5-18','S-1-5-32-544','S-1-5-9','*-512','*-516','*-519','*-518','*-521','*-498','*-500','*-517')
$script:AdcsBroad = @{ 'S-1-1-0' = 'Everyone'; 'S-1-5-11' = 'Authenticated Users'; 'S-1-5-32-545' = 'BUILTIN\Users' }
function Test-AdcsTier0([string]$sid) { foreach ($t in $script:AdcsTier0) { if ($sid -like $t) { return $true } }; return $false }
function Get-AdcsPrincipalLabel([string]$sid) {
  if ($script:AdcsBroad.ContainsKey($sid)) { return "$sid ($($script:AdcsBroad[$sid]))" }
  if ($sid -like '*-513') { return "$sid (Domain Users)" }
  if ($sid -like '*-515') { return "$sid (Domain Computers)" }
  return $sid
}
# Low-privileged principal -> right -> vulnerable object -> issuance conditions -> privileged identity impact.
function Format-AdcsPath($principals, [string]$right, [string]$object, [string]$conditions, [string]$impact) {
  $p = 'any principal'
  $list = @($principals | Where-Object { $_ } | Select-Object -Unique)
  if ($list.Count -gt 0) { $p = (($list | ForEach-Object { Get-AdcsPrincipalLabel ([string]$_) }) -join ', ') }
  return "$p -> $right -> $object -> $conditions -> $impact"
}
# State is one of: confirmed (misconfiguration present), path (exploitable issuance path), potential (needs live
# verification), insufficient (could not be read, so no conclusion).
function New-AdcsFinding([string]$esc, [string]$state, [string]$subject, [string]$why, [string]$path) {
  [pscustomobject]@{ Esc = $esc; State = $state; Subject = $subject; Why = $why; Path = $path }
}
# One verdict per stage. Only a complete, clean read is a PASS: unread or unconfirmed evidence is never clean.
function Write-AdcsVerdict([string]$label, [string]$tag, $findings, [bool]$complete, [string]$incompleteWhy, [string]$passText, [string]$failText, [string]$failTextNoPath = '') {
  $f = @($findings | Where-Object { $_ })
  foreach ($x in $f) { Write-Output ("ADCS-FINDING: state=" + $x.State + " esc=" + $x.Esc + " subject=" + $x.Subject + " why=" + $x.Why + " path=" + $x.Path) }
  $hard = @($f | Where-Object { $_.State -eq 'confirmed' -or $_.State -eq 'path' })
  $pot = @($f | Where-Object { $_.State -eq 'potential' })
  $ins = @($f | Where-Object { $_.State -eq 'insufficient' })
  if ($hard.Count -gt 0) {
    $paths = @($f | Where-Object { $_.State -eq 'path' }).Count
    Write-Output ("EXEC T1649: " + $label + ": " + $hard.Count + " confirmed finding(s), " + $paths + " exploitable issuance path(s), " + $pot.Count + " potential, " + $ins.Count + " not readable. Reads configuration only; no certificate is requested. [" + $tag + "]")
    if ($failTextNoPath -and $paths -eq 0) { $failText = $failTextNoPath }
    Write-Output ("FAIL: " + $failText + " Configuration exposure only; no certificate was requested and exploitability was not tested. [" + $tag + "]")
  } elseif ($pot.Count -gt 0 -or $ins.Count -gt 0 -or -not $complete) {
    $why = $incompleteWhy
    if (-not $why) { $why = 'see the ADCS-FINDING lines' }
    Write-Output ("SKIP: " + $label + " not concluded: " + $pot.Count + " potential exposure(s) need live verification, " + $ins.Count + " object(s) could not be read (" + $why + "). Not scored, and never treated as clean. [" + $tag + "]")
  } else {
    Write-Output ("PASS: " + $passText + " [" + $tag + "]")
  }
}
#endregion

#region ace needs=core
$script:AdcsEnrollGuid = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
$script:AdcsAutoEnrollGuid = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
$script:AdcsZeroGuid = '00000000-0000-0000-0000-000000000000'
# Non-tier-0 principals that can enroll (Enroll, Autoenroll, all extended rights, GenericAll) and that can write
# (GenericAll, GenericWrite, WriteDacl, WriteOwner, WriteProperty). An explicit Deny of Enroll removes a principal.
function Get-AdcsAceFacts($aces) {
  $enrollers = @(); $writers = @(); $denied = @()
  foreach ($a in @($aces)) {
    $sid = [string]$a.sid
    if (Test-AdcsTier0 $sid) { continue }
    $mask = [int64]$a.mask
    $ot = ([string]$a.objectType).ToLower()
    $isExt = ($mask -band 0x100) -ne 0
    $allExt = ($ot -eq '' -or $ot -eq $script:AdcsZeroGuid)
    $enrollRight = (($mask -band 0x10000000) -ne 0) -or ($isExt -and ($allExt -or $ot -eq $script:AdcsEnrollGuid -or $ot -eq $script:AdcsAutoEnrollGuid))
    if ($a.type -eq 'Deny') { if ($enrollRight) { $denied += $sid }; continue }
    if ($a.type -ne 'Allow') { continue }
    if ($enrollRight) { $enrollers += $sid }
    $specificExt = $isExt -and (-not $allExt)
    if ((-not $specificExt) -and (($mask -band 0x500C0020) -ne 0)) { $writers += $sid }
  }
  [pscustomobject]@{
    Enrollers = @($enrollers | Select-Object -Unique | Where-Object { $denied -notcontains $_ })
    Writers = @($writers | Select-Object -Unique)
  }
}
#endregion

#region tfacts needs=core,ace
$script:AdcsAuthEku = @('1.3.6.1.5.5.7.3.2', '1.3.6.1.4.1.311.20.2.2', '1.3.6.1.5.2.3.4', '2.5.29.37.0')
$script:AdcsAgentEku = '1.3.6.1.4.1.311.20.2.1'
$script:AdcsAnyEku = '2.5.29.37.0'
function Get-AdcsTemplateFacts($t) {
  $ekus = @($t.ekus | Where-Object { $_ } | ForEach-Object { [string]$_ })
  $apps = @($t.appPolicies | Where-Object { $_ } | ForEach-Object { [string]$_ })
  $nameFlag = [int64]$t.nameFlag; $enrollFlag = [int64]$t.enrollFlag
  $hasAuth = $false
  foreach ($e in $ekus) { if ($script:AdcsAuthEku -contains $e) { $hasAuth = $true } }
  $af = $null
  if ($t.aclReadable) { $af = Get-AdcsAceFacts $t.aces }
  $enrollers = @(); $writers = @()
  if ($af) { $enrollers = @($af.Enrollers); $writers = @($af.Writers) }
  [pscustomobject]@{
    Name = [string]$t.name
    SchemaVersion = [int]$t.schemaVersion
    # 0x1 = enrollee supplies the subject, 0x10000 = enrollee supplies the subject alternative name; either lets the requester name any identity.
    SuppliesSubject = (($nameFlag -band 0x10001) -ne 0)
    MgrApproval = (($enrollFlag -band 0x2) -ne 0)
    NoSecExt = (($enrollFlag -band 0x80000) -ne 0)
    RaSig = [int]$t.raSignature
    HasAuthEku = $hasAuth
    HasAgentEku = ($ekus -contains $script:AdcsAgentEku)
    HasAnyOrNoEku = (($ekus.Count -eq 0) -or ($ekus -contains $script:AdcsAnyEku))
    AppPolicies = $apps
    IssuancePolicies = @($t.issuancePolicies | Where-Object { $_ } | ForEach-Object { [string]$_ })
    AclReadable = [bool]$t.aclReadable
    Enrollers = $enrollers
    Writers = $writers
    PublishedOn = @($t.publishedOn | Where-Object { $_ })
  }
}
# A template finding: the configuration must match, then who can enroll decides whether it is real. A template whose
# ACL cannot be read is "insufficient" only when its configuration already matches; otherwise it is simply not a match.
function New-AdcsTemplateFinding($f, [string]$esc, [bool]$match, [string]$conditions, [string]$impact, [string]$why, [string]$state) {
  if (-not $match) { return $null }
  if (-not $f.AclReadable) { return (New-AdcsFinding $esc 'insufficient' $f.Name ("template configuration matches ESC" + $esc + " but its ACL could not be read, so enrollment rights are unknown") '') }
  if ($f.Enrollers.Count -eq 0) { return $null }
  $pub = 'not published on any CA'
  if ($f.PublishedOn.Count -gt 0) { $pub = 'published on ' + ($f.PublishedOn -join ',') }
  return (New-AdcsFinding $esc $state $f.Name ($why + ' (' + $pub + ')') (Format-AdcsPath $f.Enrollers 'Enroll' ('template ' + $f.Name) $conditions $impact))
}
function Test-AdcsEnrollGate($f) { return ((-not $f.MgrApproval) -and ($f.RaSig -eq 0)) }
#endregion

#region patch needs=core
# Windows build thresholds, each from Microsoft's own pages (see docs/adcs-mastery-qa-log.md). A build is [number, ubr].
#  cve49019: first build that fixes CVE-2024-49019 (ESC15). The second value is a hotpatch baseline already fixed, so
#            a revision between the two is unknown rather than vulnerable.
#  sep2025:  September 9, 2025 update, after which StrongCertificateBindingEnforcement is no longer honored (KB5014754).
#            Only the server versions that page lists are recognised.
$script:AdcsFixBuilds = @{
  cve49019 = @{ '14393' = @(7515, 0); '17763' = @(6532, 0); '20348' = @(2849, 2819); '25398' = @(1251, 0); '26100' = @(2314, 2240) }
  sep2025 = @{ '14393' = @(8422, 0); '17763' = @(7792, 0); '20348' = @(4171, 0) }
  # may2022: the May 10, 2022 update, the first to carry the KB5014754 strong certificate mapping changes. Below it a DC has
  #          no StrongCertificateBindingEnforcement support at all. Only Server 2022 (KB5013944, 20348.707) is listed: the
  #          KB5014754 page names no build for 2019 or 2016, and the date-match for 2022 is an inference (see the QA log).
  may2022 = @{ '20348' = @(707, 0) }
}
function Format-AdcsBuild($b) { if ($null -eq $b) { return 'unknown build' }; return ('10.0.' + $b.number + '.' + $b.ubr) }
# fixed, vulnerable or unknown. A build that cannot be read, or is not in the table, is unknown, never fixed.
function Get-AdcsBuildState($b, [string]$kind) {
  if ($null -eq $b -or $null -eq $b.ubr -or -not $b.number) { return 'unknown' }
  $row = $script:AdcsFixBuilds[$kind][[string]$b.number]
  if (-not $row) { return 'unknown' }
  $u = [int64]$b.ubr
  if ($u -ge $row[0]) { return 'fixed' }
  if ($row[1] -gt 0 -and $u -ge $row[1]) { return 'unknown' }
  return 'vulnerable'
}
#endregion

#region reach needs=core
# A short TCP check before an SMB-based registry read: an unreachable host otherwise waits out a long RPC timeout.
function Test-AdcsPort([string]$hostName, [int]$port = 445, [int]$ms = 3000) {
  try {
    $c = New-Object System.Net.Sockets.TcpClient
    $r = $c.BeginConnect($hostName, $port, $null, $null)
    $ok = ($r.AsyncWaitHandle.WaitOne($ms, $false) -and $c.Connected)
    $c.Close()
    return $ok
  } catch { return $false }
}
#endregion

#region readbuild needs=core,reach
# The Windows build of a host from its remote registry: CurrentBuildNumber and UBR. Null when it cannot be read.
function Read-AdcsBuildFrom($base) {
  try {
    $k = $base.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion')
    if (-not $k) { return $null }
    $n = [string]$k.GetValue('CurrentBuildNumber'); $u = $k.GetValue('UBR')
    $k.Close()
    if (-not $n -or $null -eq $u) { return $null }
    return [pscustomobject]@{ number = $n; ubr = [int64]$u }
  } catch { return $null }
}
function Read-AdcsBuild([string]$hostName) {
  if (-not (Test-AdcsPort $hostName)) { return $null }
  try {
    $b = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $hostName)
    $r = Read-AdcsBuildFrom $b
    $b.Close()
    return $r
  } catch { return $null }
}
#endregion

#region cafield_build needs=core,readbuild
function Read-AdcsCaField_build($ca, [string]$conf, $ctx) { return (Read-AdcsBuild $ca.host) }
#endregion

#region esc1 needs=core,ace,tfacts
function Test-AdcsEsc1($f) {
  $m = $f.SuppliesSubject -and ($f.HasAuthEku -or $f.HasAnyOrNoEku) -and (Test-AdcsEnrollGate $f)
  New-AdcsTemplateFinding $f '1' $m 'enrollee supplies the subject, client-authentication EKU, no manager approval, no RA signature' 'request a certificate naming any identity, including a Domain Admin, then authenticate as it' 'enrollee-supplied subject with a client-authentication EKU and low-privilege enrollment' 'confirmed'
}
#endregion

#region esc2 needs=core,ace,tfacts
function Test-AdcsEsc2($f) {
  $m = $f.HasAnyOrNoEku -and (Test-AdcsEnrollGate $f)
  New-AdcsTemplateFinding $f '2' $m 'Any Purpose or no EKU, no manager approval, no RA signature' 'obtain a certificate valid for every purpose: client authentication, enrollment-agent use or subordinate signing' 'Any-Purpose or empty EKU with low-privilege enrollment' 'confirmed'
}
#endregion

#region esc3 needs=core,ace,tfacts
function Test-AdcsEsc3($f, $all) {
  $m = $f.HasAgentEku -and (Test-AdcsEnrollGate $f)
  if (-not $m) { return $null }
  $second = $false
  foreach ($g in @($all)) {
    if ($g.RaSig -ge 1 -and ($g.AppPolicies -contains $script:AdcsAgentEku) -and ($g.HasAuthEku -or $g.HasAnyOrNoEku) -and $g.Enrollers.Count -gt 0 -and (-not $g.MgrApproval)) { $second = $true }
  }
  $state = 'potential'
  $why = 'enrollment-agent template is enrollable, but no template that accepts agent-signed requests was found; the CA enrollment-agent restrictions are not readable from AD, so this needs live verification'
  if ($second) { $state = 'confirmed'; $why = 'enrollment-agent template is enrollable and another enrollable template accepts agent-signed requests' }
  New-AdcsTemplateFinding $f '3' $true 'enrollment-agent EKU, then enrol on behalf of another principal through a template that accepts agent requests' 'request certificates on behalf of any user, including a Domain Admin' $why $state
}
#endregion

#region esc4 needs=core,ace,tfacts
function Test-AdcsEsc4($f) {
  if (-not $f.AclReadable) { return (New-AdcsFinding '4' 'insufficient' $f.Name 'template ACL could not be read, so write rights are unknown' '') }
  if ($f.Writers.Count -eq 0) { return $null }
  $pub = 'not published on any CA'
  if ($f.PublishedOn.Count -gt 0) { $pub = 'published on ' + ($f.PublishedOn -join ',') }
  New-AdcsFinding '4' 'confirmed' $f.Name ('a non-tier-0 principal can write the template (' + $pub + ')') (Format-AdcsPath $f.Writers 'Write (WriteProperty, WriteDacl, WriteOwner or GenericWrite)' ('template ' + $f.Name) 'can rewrite the subject, EKU and approval settings' 'turn the template into an ESC1 template and request a certificate as any identity')
}
#endregion

#region esc9 needs=core,ace,tfacts
function Test-AdcsEsc9($f) {
  $m = $f.NoSecExt -and ($f.HasAuthEku -or $f.HasAnyOrNoEku) -and (Test-AdcsEnrollGate $f)
  New-AdcsTemplateFinding $f '9' $m 'no security extension (CT_FLAG_NO_SECURITY_EXTENSION): issued certificates carry no SID; works only where the DC still accepts weak mapping (see ESC10) and the enrollee can change a victim account UPN' 'authenticate as another account whose UPN the enrollee can write' 'no-security-extension flag with low-privilege enrollment' 'confirmed'
}
#endregion

#region esc13 needs=core,ace,tfacts
function Test-AdcsEsc13($f, $oids) {
  if ($f.IssuancePolicies.Count -eq 0) { return $null }
  if (-not ($f.HasAuthEku -or $f.HasAnyOrNoEku) -or -not (Test-AdcsEnrollGate $f)) { return $null }
  if ($null -eq $oids) {
    return (New-AdcsFinding '13' 'insufficient' $f.Name 'template carries an issuance policy, but the issuance-policy objects could not be read' '')
  }
  $out = @()
  foreach ($p in $f.IssuancePolicies) {
    $o = @($oids | Where-Object { [string]$_.oid -eq $p })
    if ($o.Count -eq 0 -or -not $o[0].linkedGroupSid) { continue }
    if ($o[0].linkResolved -eq $false) { $out += (New-AdcsFinding '13' 'insufficient' $f.Name ('issuance policy ' + $p + ' links to a group that could not be resolved') ''); continue }
    if (-not $o[0].linkedGroupPrivileged) { continue }
    $r = New-AdcsTemplateFinding $f '13' $true ('issuance policy ' + $p + ' (' + [string]$o[0].name + ') linked to a privileged group') ('authenticating with the issued certificate adds the privileged group ' + [string]$o[0].linkedGroupSid) ('issuance-policy-to-group mapping on ' + $f.Name) 'confirmed'
    if ($r) { $out += $r }
  }
  return $out
}
#endregion

#region esc15 needs=core,ace,tfacts,patch
# Schema-version-1 template with an enrollee-supplied subject (CVE-2024-49019). The CA build decides it: below the fix on a
# CA that publishes the template is confirmed; every publishing CA at or above the fix is clean; anything else is potential.
function Test-AdcsEsc15($f, $cas) {
  $m = ($f.SchemaVersion -eq 1) -and $f.SuppliesSubject -and (Test-AdcsEnrollGate $f)
  if (-not $m) { return $null }
  $vuln = @(); $unknown = @(); $pub = @($cas | Where-Object { $f.PublishedOn -contains $_.name })
  foreach ($c in $pub) {
    $st = Get-AdcsBuildState $c.build 'cve49019'
    if ($st -eq 'vulnerable') { $vuln += ([string]$c.name + ' (' + (Format-AdcsBuild $c.build) + ')') }
    elseif ($st -ne 'fixed') { $unknown += [string]$c.name }
  }
  $state = 'potential'
  $why = 'schema version 1 template with an enrollee-supplied subject: an Application Policy can be injected in place of the EKU (CVE-2024-49019). '
  if ($vuln.Count -gt 0) { $state = 'confirmed'; $why += 'A CA that publishes it is below the fixed build: ' + ($vuln -join ', ') }
  elseif ($pub.Count -gt 0 -and $unknown.Count -eq 0) { return $null }
  elseif ($pub.Count -eq 0) { $why += 'It is not published on any CA, so it is latent; the CA patch level was not checked' }
  else { $why += 'The CA build could not be matched to a fixed build for: ' + ($unknown -join ', ') + ', so it needs live verification' }
  New-AdcsTemplateFinding $f '15' $true 'schema-version-1 template with enrollee-supplied subject, exploitable only on a CA without the CVE-2024-49019 fix' 'obtain a client-authentication or enrollment-agent certificate through a template that should not allow it' $why $state
}
#endregion

#region esc5 needs=core,ace
function Test-AdcsEsc5($objs) {
  $out = @()
  foreach ($o in @($objs)) {
    if (-not $o.aclReadable) { $out += (New-AdcsFinding '5' 'insufficient' ([string]$o.name) 'PKI object ACL could not be read' ''); continue }
    $w = @((Get-AdcsAceFacts $o.aces).Writers)
    if ($w.Count -eq 0) { continue }
    $impact = 'alter PKI configuration to issue certificates trusted for any identity'
    if ([string]$o.name -like '*NTAuthCertificates*') { $impact = 'add a rogue CA certificate trusted for domain authentication' }
    elseif ([string]$o.name -like '*Enrollment Services*' -or [string]$o.name -like 'pKIEnrollmentService*') { $impact = 'change CA enrollment settings or publish templates' }
    $out += (New-AdcsFinding '5' 'confirmed' ([string]$o.name) 'a non-tier-0 principal can write this PKI object' (Format-AdcsPath $w 'Write' ('PKI object ' + [string]$o.name) 'the object controls CA trust or enrollment' $impact))
  }
  return $out
}
#endregion

#region esc6 needs=core
function Test-AdcsEsc6($cas) {
  $out = @()
  foreach ($c in @($cas)) {
    if ($null -eq $c.editFlags) { $out += (New-AdcsFinding '6' 'insufficient' ([string]$c.name) 'the CA EditFlags policy value could not be read' ''); continue }
    if ((([int64]$c.editFlags) -band 0x40000) -ne 0) {
      $out += (New-AdcsFinding '6' 'confirmed' ([string]$c.name) 'the CA accepts a requester-supplied subject alternative name on any template (EDITF_ATTRIBUTESUBJECTALTNAME2)' (Format-AdcsPath @() 'Enroll on any published template with an authentication EKU' ('CA ' + [string]$c.name) 'the CA honours a SAN supplied in the request' 'request a certificate for any identity, including a Domain Admin'))
    }
  }
  return $out
}
#endregion

#region esc7 needs=core,ace
# CA security-descriptor masks: ManageCA 0x1, ManageCertificates 0x2.
function Test-AdcsEsc7($cas) {
  $out = @()
  foreach ($c in @($cas)) {
    if ($null -eq $c.caAces) { $out += (New-AdcsFinding '7' 'insufficient' ([string]$c.name) 'the CA security descriptor could not be read (remote registry unavailable or denied)' ''); continue }
    $mgr = @(); $mc = @()
    foreach ($a in @($c.caAces)) {
      if ($a.type -ne 'Allow' -or (Test-AdcsTier0 ([string]$a.sid))) { continue }
      if (([int64]$a.mask -band 0x1) -ne 0) { $mgr += [string]$a.sid }
      if (([int64]$a.mask -band 0x2) -ne 0) { $mc += [string]$a.sid }
    }
    if ($mgr.Count -gt 0) { $out += (New-AdcsFinding '7' 'confirmed' ([string]$c.name) 'a non-tier-0 principal holds ManageCA on the CA' (Format-AdcsPath $mgr 'ManageCA' ('CA ' + [string]$c.name) 'can set EDITF_ATTRIBUTESUBJECTALTNAME2 and enable templates' 'request a certificate for any identity')) }
    if ($mc.Count -gt 0) { $out += (New-AdcsFinding '7' 'confirmed' ([string]$c.name) 'a non-tier-0 principal holds ManageCertificates on the CA' (Format-AdcsPath $mc 'ManageCertificates' ('CA ' + [string]$c.name) 'can approve pending requests, including requests held for manager approval' 'obtain a certificate that approval was meant to withhold')) }
  }
  return $out
}
#endregion

#region esc8 needs=core
function Test-AdcsEsc8($cas, [bool]$live) {
  $out = @()
  foreach ($c in @($cas)) {
    if (-not $live) { $out += (New-AdcsFinding '8' 'potential' ([string]$c.name) 'web enrollment relay exposure needs a live check; set BAS_ADCS_LIVE_PROBE=true to send one unauthenticated HTTP GET per CA' ''); continue }
    $w = $c.web
    if ($null -ne $w -and $w.refused) { continue }   # nothing listens on HTTP: the relayable HTTP endpoint is not offered
    if ($null -eq $w -or -not $w.answered) { $out += (New-AdcsFinding '8' 'insufficient' ([string]$c.name) 'no answer from the CA web enrollment endpoint (timed out or filtered), so it cannot be ruled out' ''); continue }
    if ($w.httpNtlm) { $out += (New-AdcsFinding '8' 'confirmed' ([string]$c.name) 'web enrollment answers over plain HTTP and offers NTLM or Negotiate' (Format-AdcsPath @() 'relay a coerced NTLM authentication' ('CA web enrollment on ' + [string]$c.host) 'integrated authentication over HTTP, no Extended Protection' 'obtain a certificate as the relayed account, for example a domain controller')) }
  }
  return $out
}
#endregion

#region esc10 needs=core,patch
# Weak certificate mapping on a DC. After the September 9, 2025 update the KDC ignores the StrongCertificateBindingEnforcement
# registry value, so a weak value there is not a finding on a DC at or above that build (Server 2016, 2019, 2022 are recognised).
# The Schannel CertificateMappingMethods UPN bit (0x4) is a separate setting and still counts.
function Test-AdcsEsc10($dcs) {
  $out = @()
  foreach ($d in @($dcs)) {
    if (-not $d.readable) { $out += (New-AdcsFinding '10' 'insufficient' ([string]$d.name) 'the domain controller certificate-mapping settings could not be read' ''); continue }
    $bs = Get-AdcsBuildState $d.build 'sep2025'
    if ((Get-AdcsBuildState $d.build 'may2022') -eq 'vulnerable') {
      $pp = Format-AdcsPath @() 'change a victim UPN, then enrol' ('domain controller ' + [string]$d.name) 'the DC predates strong certificate mapping' 'authenticate as another account'
      $out += (New-AdcsFinding '10' 'confirmed' ([string]$d.name) ('the DC build ' + (Format-AdcsBuild $d.build) + ' is below the May 10, 2022 update (20348.707), the first with strong certificate mapping, so it has no StrongCertificateBindingEnforcement support and maps certificates by UPN or SAN alone') $pp)
      continue
    }
    $upn = ($null -ne $d.certMappingMethods) -and ((([int64]$d.certMappingMethods) -band 0x4) -ne 0)
    $path = Format-AdcsPath @() 'change a victim UPN, then enrol' ('domain controller ' + [string]$d.name) 'weak certificate-to-account mapping' 'authenticate as another account'
    if ($bs -eq 'fixed') {
      if ($upn) { $out += (New-AdcsFinding '10' 'potential' ([string]$d.name) ('Schannel CertificateMappingMethods allows UPN mapping (weak); the KDC registry value is ignored on this build (' + (Format-AdcsBuild $d.build) + ')') $path) }
      continue
    }
    $weak = @()
    if ($null -ne $d.strongBinding -and ([int64]$d.strongBinding) -lt 2) { $weak += ('StrongCertificateBindingEnforcement=' + $d.strongBinding) }
    if ($upn) { $weak += 'Schannel CertificateMappingMethods allows UPN mapping' }
    if ($weak.Count -gt 0) {
      $state = 'potential'; $note = 'the DC update level could not be matched to the September 2025 build, so it needs live verification'
      if ($bs -eq 'vulnerable') { $note = 'the DC build ' + (Format-AdcsBuild $d.build) + ' is below the September 9, 2025 update, so the value is honored'; if ($null -ne $d.strongBinding -and ([int64]$d.strongBinding) -eq 0) { $state = 'confirmed' } }
      $out += (New-AdcsFinding '10' $state ([string]$d.name) ('explicit weak certificate-mapping setting (' + ($weak -join '; ') + '); ' + $note) $path)
    } elseif ($null -eq $d.strongBinding) {
      $out += (New-AdcsFinding '10' 'insufficient' ([string]$d.name) 'StrongCertificateBindingEnforcement is not set; the effective default depends on the DC update level, which could not be established' '')
    }
  }
  return $out
}
#endregion

#region esc11 needs=core
function Test-AdcsEsc11($cas) {
  $out = @()
  foreach ($c in @($cas)) {
    if ($null -eq $c.interfaceFlags) { $out += (New-AdcsFinding '11' 'insufficient' ([string]$c.name) 'the CA InterfaceFlags value could not be read' ''); continue }
    if ((([int64]$c.interfaceFlags) -band 0x200) -eq 0) {
      $out += (New-AdcsFinding '11' 'confirmed' ([string]$c.name) 'the CA does not enforce an encrypted certificate request interface (IF_ENFORCEENCRYPTICERTREQUEST is clear)' (Format-AdcsPath @() 'relay a coerced NTLM authentication to the RPC enrollment interface' ('CA ' + [string]$c.name) 'RPC requests are accepted without packet privacy' 'obtain a certificate as the relayed account'))
    }
  }
  return $out
}
#endregion

#region esc12 needs=core
$script:AdcsSoftProviders = @('Microsoft Software Key Storage Provider', 'Microsoft Strong Cryptographic Provider', 'Microsoft Enhanced Cryptographic Provider v1.0', 'Microsoft Base Cryptographic Provider v1.0', 'Microsoft Enhanced RSA and AES Cryptographic Provider', 'Microsoft Base DSS Cryptographic Provider')
function Test-AdcsEsc12($cas) {
  $out = @()
  foreach ($c in @($cas)) {
    if (-not $c.keyProvider) { $out += (New-AdcsFinding '12' 'insufficient' ([string]$c.name) 'the CA key provider could not be read' ''); continue }
    if ($script:AdcsSoftProviders -contains [string]$c.keyProvider) {
      $out += (New-AdcsFinding '12' 'potential' ([string]$c.name) ('the CA signing key is held by the software provider "' + [string]$c.keyProvider + '"; this is a hardening posture, not an exploitable misconfiguration, so it is not scored. A hardware security module is recommended') (Format-AdcsPath @() 'administrator access to the CA host' ('CA ' + [string]$c.name) 'the signing key is exportable from software' 'forge certificates for any identity'))
    }
  }
  return $out
}
#endregion

#region esc14 needs=core
function Test-AdcsEsc14($accounts) {
  $out = @()
  foreach ($a in @($accounts)) {
    foreach ($m in @($a.mappings)) {
      $s = [string]$m
      if ($s -notmatch '^(?i)X509:') { continue }
      $weak = $false
      if ($s -match '^(?i)X509:<RFC822>') { $weak = $true }
      elseif ($s -match '^(?i)X509:<S>') { $weak = $true }
      elseif ($s -match '^(?i)X509:<I>' -and $s -notmatch '(?i)<SR>|<SKI>|<SHA1-PUKEY>') { $weak = $true }
      if ($weak) {
        $who = [string]$a.sam
        $imp = 'authenticate as ' + $who
        if ($a.tier0) { $imp = 'authenticate as the privileged account ' + $who }
        $out += (New-AdcsFinding '14' 'confirmed' $who ('weak explicit certificate mapping ' + $s) (Format-AdcsPath @() 'obtain any certificate matching the weak identifier' ('altSecurityIdentities on ' + $who) 'mapping by RFC822, subject or issuer only' $imp))
        break
      }
    }
  }
  return $out
}
#endregion

#region dispatch needs=core
# What each ESC analyzer is called with: t = each template, tc = each template plus the CAs, tt = each template plus all templates, to = each template plus
# the issuance-policy objects, p = PKI objects, c = CAs, cl = CAs and the live-probe flag, d = domain controllers, a = accounts.
$script:AdcsEscKind = @{ '1' = 't'; '2' = 't'; '3' = 'tt'; '4' = 't'; '9' = 't'; '15' = 'tc'; '13' = 'to'; '5' = 'p'; '6' = 'c'; '7' = 'c'; '11' = 'c'; '12' = 'c'; '8' = 'cl'; '10' = 'd'; '14' = 'a' }
# Run the analyzer for one ESC number against a context.
function Get-AdcsEscFindings([string]$esc, $ctx) {
  $fn = 'Test-AdcsEsc' + $esc
  $kind = $script:AdcsEscKind[$esc]
  $tf = @()
  if ($kind -like 't*' -and $null -ne $ctx.Templates) { $tf = @($ctx.Templates | ForEach-Object { Get-AdcsTemplateFacts $_ }) }
  $out = @()
  switch ($kind) {
    't' { foreach ($f in $tf) { $out += & $fn $f } }
    'tt' { foreach ($f in $tf) { $out += & $fn $f $tf } }
    'to' { foreach ($f in $tf) { $out += & $fn $f $ctx.Oids } }
    'tc' { foreach ($f in $tf) { $out += & $fn $f $ctx.CAs } }
    'p' { $out += & $fn $ctx.PkiObjects }
    'c' { $out += & $fn $ctx.CAs }
    'cl' { $out += & $fn $ctx.CAs ([bool]$ctx.LiveProbe) }
    'd' { $out += & $fn $ctx.DCs }
    'a' { $out += & $fn $ctx.Accounts }
  }
  return @($out | Where-Object { $_ })
}
# Invoke one ESC stage: read what it needs, analyze, write one verdict. $collect is false in the fixture tests, which
# supply the context in $script:AdcsCtx.
function Invoke-AdcsStage([string]$esc, $needs, [string]$label, [string]$passText, [string]$failText, [bool]$collect) {
  $ctx = $script:AdcsCtx
  if ($collect) { $ctx = Read-AdcsContext $needs }
  $why = ''
  $complete = $true
  foreach ($n in $needs) {
    $err = $ctx.Errors[$n]
    if ($err) { $complete = $false; $why = ($why + $n + ': ' + $err + '; ') }
  }
  $findings = @()
  if ($complete) { $findings = Get-AdcsEscFindings $esc $ctx }
  Write-AdcsVerdict $label ('BAS-SIM-ADCS-ESC' + $esc) $findings $complete $why $passText $failText
}
#endregion

#region collect needs=core
function New-AdcsContext { [pscustomobject]@{ Templates = $null; CAs = $null; PkiObjects = $null; Oids = $null; DCs = $null; Accounts = $null; NtAuth = $null; LiveProbe = $false; Errors = @{} } }
function ConvertTo-AdcsAces($rules) {
  $o = @()
  foreach ($r in @($rules)) {
    $o += [pscustomobject]@{ sid = $r.IdentityReference.Value; mask = [int64]$r.ActiveDirectoryRights; objectType = [string]$r.ObjectType; type = [string]$r.AccessControlType }
  }
  return $o
}
function Read-AdcsAcl($entry) {
  try {
    $rules = $entry.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    $aces = @(ConvertTo-AdcsAces $rules)
    # A DACL always has entries; none means the descriptor was not readable.
    $readable = ($aces.Count -gt 0)
    # The owner holds an implicit WriteDacl whatever the DACL says, so it counts as a writer.
    try { $own = $entry.ObjectSecurity.GetOwner([System.Security.Principal.SecurityIdentifier]); if ($own) { $aces += [pscustomobject]@{ sid = $own.Value; mask = [int64]0x40000; objectType = ''; type = 'Allow' } } } catch { }
    return [pscustomobject]@{ readable = $readable; aces = $aces }
  } catch { return [pscustomobject]@{ readable = $false; aces = @() } }
}
# Not being domain joined is answered locally and at once; an LDAP bind off-domain waits out a long network timeout.
function Read-AdcsConfigDN {
  if ($script:AdcsCfgChecked) { return $script:AdcsCfgDn }
  $script:AdcsCfgChecked = $true; $script:AdcsCfgDn = $null
  try { if (-not (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain) { return $null } } catch { return $null }
  try { $d = ([ADSI]'LDAP://RootDSE').configurationNamingContext; if ($d) { $script:AdcsCfgDn = [string]$d } } catch { }
  return $script:AdcsCfgDn
}
function Read-AdcsEnrollmentServices([string]$cfg) {
  if ($script:AdcsSvcFor -eq $cfg) { return ,@($script:AdcsSvc) }
  $list = @()
  $s = New-Object System.DirectoryServices.DirectorySearcher
  $s.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,$cfg")
  $s.Filter = '(objectClass=pKIEnrollmentService)'
  foreach ($p in @('cn', 'dNSHostName', 'certificateTemplates', 'distinguishedName')) { [void]$s.PropertiesToLoad.Add($p) }
  foreach ($r in @($s.FindAll())) {
    $list += [pscustomobject]@{ name = [string]$r.Properties['cn'][0]; host = [string]$r.Properties['dnshostname'][0]; dn = [string]$r.Properties['distinguishedname'][0]; published = @($r.Properties['certificatetemplates'] | ForEach-Object { [string]$_ }) }
  }
  $script:AdcsSvc = $list; $script:AdcsSvcFor = $cfg
  return $list
}
# Read the named parts into one context. A part that cannot be read leaves its collection null and names the reason in
# Errors, so unread evidence is never mistaken for an empty (clean) collection.
function Read-AdcsContext($needs) {
  $ctx = New-AdcsContext
  $cfg = Read-AdcsConfigDN
  if (-not $cfg) { foreach ($n in $needs) { $ctx.Errors[$n] = 'no Configuration naming context (host not domain-joined or DC unreachable)' }; return $ctx }
  foreach ($n in $needs) {
    try { & ('Read-AdcsPart_' + $n) $ctx $cfg } catch { $ctx.Errors[$n] = ($n + ' could not be read') }
  }
  return $ctx
}
#endregion

#region collect_web needs=core
# One unauthenticated HTTP GET per CA, only when BAS_ADCS_LIVE_PROBE=true. No credentials, no redirects, no certificate request.
function Read-AdcsWebProbe([string]$hostName) {
  $none = [pscustomobject]@{ answered = $false; refused = $false; httpNtlm = $false }
  try {
    $req = [System.Net.WebRequest]::Create("http://$hostName/certsrv/")
    $req.Method = 'GET'; $req.Timeout = 10000; $req.AllowAutoRedirect = $false; $req.UseDefaultCredentials = $false
    $code = $null; $auth = ''
    try { $resp = $req.GetResponse(); $code = [int]$resp.StatusCode; $auth = [string]$resp.Headers['WWW-Authenticate']; $resp.Close() }
    catch [System.Net.WebException] {
      if ($_.Exception.Response) { $r = $_.Exception.Response; $code = [int]$r.StatusCode; $auth = [string]$r.Headers['WWW-Authenticate']; $r.Close() }
      elseif ($_.Exception.Status -eq [System.Net.WebExceptionStatus]::ConnectFailure) { return [pscustomobject]@{ answered = $false; refused = $true; httpNtlm = $false } }
    }
    if ($null -eq $code) { return $none }
    return [pscustomobject]@{ answered = $true; refused = $false; httpNtlm = (($code -eq 401) -and ($auth -match '(?i)NTLM|Negotiate')) }
  } catch { return $none }
}
#endregion

#region part_templates needs=core,collect
function Read-AdcsPart_templates($ctx, [string]$cfg) {
  $pks = "CN=Public Key Services,CN=Services,$cfg"
  $svc = @()
  try { $svc = @(Read-AdcsEnrollmentServices $cfg) } catch { $svc = @() }
  $c = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Certificate Templates,$pks")
  if (-not $c.Name) { $ctx.Errors['templates'] = 'no certificate templates container (AD CS not deployed or not readable)'; return }
  $t = @()
  foreach ($tmpl in $c.Children) {
    if ($tmpl.SchemaClassName -ne 'pKICertificateTemplate') { continue }
    $acl = Read-AdcsAcl $tmpl
    $name = [string]$tmpl.Properties['cn'].Value
    $pub = @(); foreach ($ca in $svc) { if ($ca.published -contains $name) { $pub += $ca.name } }
    $t += [pscustomobject]@{
      name = $name; schemaVersion = [int]($tmpl.Properties['msPKI-Template-Schema-Version'].Value)
      nameFlag = [int64]($tmpl.Properties['msPKI-Certificate-Name-Flag'].Value); enrollFlag = [int64]($tmpl.Properties['msPKI-Enrollment-Flag'].Value)
      raSignature = [int]($tmpl.Properties['msPKI-RA-Signature'].Value)
      ekus = @($tmpl.Properties['pKIExtendedKeyUsage'] | ForEach-Object { [string]$_ })
      appPolicies = @($tmpl.Properties['msPKI-RA-Application-Policies'] | ForEach-Object { [string]$_ })
      issuancePolicies = @($tmpl.Properties['msPKI-Certificate-Policy'] | ForEach-Object { [string]$_ })
      aclReadable = $acl.readable; aces = $acl.aces; publishedOn = $pub
    }
  }
  if ($t.Count -eq 0) { $ctx.Errors['templates'] = 'no certificate templates were returned'; return }
  $ctx.Templates = $t
}
#endregion

#region certutil needs=core
function Read-CertutilDword([string]$config, [string]$value, [string]$name) {
  try {
    $out = (& certutil -config $config -getreg $value 2>&1 | Out-String)
    if ($out -match ('(?i)' + $name + '\s+REG_DWORD\s*=\s*([0-9a-f]+)')) { return [Convert]::ToInt64($matches[1], 16) }
  } catch { }
  return $null
}
function Read-CertutilString([string]$config, [string]$value, [string]$name) {
  try {
    $out = (& certutil -config $config -getreg $value 2>&1 | Out-String)
    if ($out -match ('(?i)' + $name + '\s+REG_SZ\s*=\s*([^\r\n]+)')) { return $matches[1].Trim() }
  } catch { }
  return $null
}
#endregion

#region cafield_editFlags needs=core,certutil
function Read-AdcsCaField_editFlags($ca, [string]$conf, $ctx) { return (Read-CertutilDword $conf 'policy\EditFlags' 'EditFlags') }
#endregion

#region cafield_interfaceFlags needs=core,certutil
function Read-AdcsCaField_interfaceFlags($ca, [string]$conf, $ctx) { return (Read-CertutilDword $conf 'CA\InterfaceFlags' 'InterfaceFlags') }
#endregion

#region cafield_keyProvider needs=core,certutil
function Read-AdcsCaField_keyProvider($ca, [string]$conf, $ctx) { return (Read-CertutilString $conf 'CA\CSP\Provider' 'Provider') }
#endregion

#region cafield_caAces needs=core,reach
function Read-AdcsRemoteSecurity([string]$hostName, [string]$caName) {
  if (-not (Test-AdcsPort $hostName)) { return $null }
  try {
    $base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $hostName)
    $key = $base.OpenSubKey('SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\' + $caName)
    if (-not $key) { return $null }
    $bytes = $key.GetValue('Security')
    if (-not $bytes) { return $null }
    $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($bytes, 0)
    $o = @()
    foreach ($a in $sd.DiscretionaryAcl) {
      $type = 'Other'
      if ($a.AceType -eq [System.Security.AccessControl.AceType]::AccessAllowed) { $type = 'Allow' }
      elseif ($a.AceType -eq [System.Security.AccessControl.AceType]::AccessDenied) { $type = 'Deny' }
      $o += [pscustomobject]@{ sid = $a.SecurityIdentifier.Value; mask = [int64]$a.AccessMask; objectType = ''; type = $type }
    }
    return $o
  } catch { return $null }
}
function Read-AdcsCaField_caAces($ca, [string]$conf, $ctx) { return (Read-AdcsRemoteSecurity $ca.host $ca.name) }
#endregion

#region cafield_web needs=core,collect_web
# Only when BAS_ADCS_LIVE_PROBE=true; otherwise the field stays null and ESC8 reports the CA as needing live verification.
function Read-AdcsCaField_web($ca, [string]$conf, $ctx) {
  if ($env:BAS_ADCS_LIVE_PROBE -ne 'true') { return $null }
  $ctx.LiveProbe = $true
  return (Read-AdcsWebProbe $ca.host)
}
#endregion

#region part_cas needs=core,collect
# Reads the enrolment services and only the CA fields the stage asked for in $script:AdcsCaFields; a field not requested
# stays null, which an analyzer reports as unreadable rather than clean.
function Read-AdcsPart_cas($ctx, [string]$cfg) {
  $svc = @(Read-AdcsEnrollmentServices $cfg)
  if ($svc.Count -eq 0) { $ctx.Errors['cas'] = 'no enrollment service (CA) found in the Configuration partition'; return }
  $fields = @($script:AdcsCaFields | Where-Object { $_ })
  $cas = @()
  foreach ($ca in $svc) {
    $conf = $ca.host + '\' + $ca.name
    $o = [ordered]@{ name = $ca.name; host = $ca.host; published = $ca.published; editFlags = $null; interfaceFlags = $null; keyProvider = $null; caAces = $null; web = $null }
    foreach ($f in $fields) {
      $fn = 'Read-AdcsCaField_' + $f
      if (Get-Command $fn -ErrorAction SilentlyContinue) { $o[$f] = & $fn $ca $conf $ctx }
    }
    $cas += [pscustomobject]$o
  }
  $ctx.CAs = $cas
}
#endregion

#region part_pki needs=core,collect
function Read-AdcsPart_pki($ctx, [string]$cfg) {
  $pks = "CN=Public Key Services,CN=Services,$cfg"
  $objs = @()
  foreach ($n in @('NTAuthCertificates', 'Certification Authorities', 'Enrollment Services', 'AIA', 'CDP', 'OID')) {
    $e = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=$n,$pks")
    if (-not $e.Name) { continue }
    $acl = Read-AdcsAcl $e
    $objs += [pscustomobject]@{ name = $n; aclReadable = $acl.readable; aces = $acl.aces }
  }
  foreach ($ca in @(Read-AdcsEnrollmentServices $cfg)) {
    $e = New-Object System.DirectoryServices.DirectoryEntry("LDAP://" + $ca.dn)
    $acl = Read-AdcsAcl $e
    $objs += [pscustomobject]@{ name = 'pKIEnrollmentService ' + $ca.name; aclReadable = $acl.readable; aces = $acl.aces }
  }
  if ($objs.Count -eq 0) { $ctx.Errors['pki'] = 'no Public Key Services objects could be read'; return }
  $ctx.PkiObjects = $objs
}
#endregion

#region part_oids needs=core,collect
function Read-AdcsPart_oids($ctx, [string]$cfg) {
  $pks = "CN=Public Key Services,CN=Services,$cfg"
  $o = @()
  $s = New-Object System.DirectoryServices.DirectorySearcher
  $s.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=OID,$pks")
  $s.Filter = '(&(objectClass=msPKI-Enterprise-Oid)(msDS-OIDToGroupLink=*))'
  foreach ($p in @('msPKI-Cert-Template-OID', 'displayName', 'msDS-OIDToGroupLink')) { [void]$s.PropertiesToLoad.Add($p) }
  foreach ($r in @($s.FindAll())) {
    $gdn = [string]$r.Properties['msds-oidtogrouplink'][0]
    $sid = $null; $priv = $false; $resolved = $false
    try {
      $g = [ADSI]("LDAP://" + $gdn)
      $sid = (New-Object System.Security.Principal.SecurityIdentifier([byte[]]$g.Properties['objectSid'].Value, 0)).Value
      $resolved = $true
      $priv = (Test-AdcsTier0 $sid) -or (([int]$g.Properties['adminCount'].Value) -eq 1)
    } catch { }
    $link = $gdn; if ($sid) { $link = $sid }
    $o += [pscustomobject]@{ oid = [string]$r.Properties['mspki-cert-template-oid'][0]; name = [string]$r.Properties['displayname'][0]; linkedGroupSid = $link; linkResolved = $resolved; linkedGroupPrivileged = $priv }
  }
  $ctx.Oids = $o
}
#endregion

#region part_accounts needs=core,collect
function Read-AdcsPart_accounts($ctx, [string]$cfg) {
  $dom = ([ADSI]'LDAP://RootDSE').defaultNamingContext
  if (-not $dom) { $ctx.Errors['accounts'] = 'no domain naming context'; return }
  $s = New-Object System.DirectoryServices.DirectorySearcher
  $s.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dom")
  $s.PageSize = 500
  $s.Filter = '(&(|(objectClass=user)(objectClass=computer))(altSecurityIdentities=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
  foreach ($p in @('sAMAccountName', 'altSecurityIdentities', 'adminCount')) { [void]$s.PropertiesToLoad.Add($p) }
  $acc = @()
  foreach ($r in @($s.FindAll())) {
    $acc += [pscustomobject]@{ sam = [string]$r.Properties['samaccountname'][0]; tier0 = ($r.Properties['admincount'].Count -gt 0 -and [int]$r.Properties['admincount'][0] -eq 1); mappings = @($r.Properties['altsecurityidentities'] | ForEach-Object { [string]$_ }) }
  }
  $ctx.Accounts = $acc
}
#endregion

#region part_dcs needs=core,collect,readbuild,reach
function Read-AdcsPart_dcs($ctx, [string]$cfg) {
  $list = @([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers)
  if ($list.Count -eq 0) { $ctx.Errors['dcs'] = 'no domain controllers found'; return }
  $dcs = @()
  foreach ($dc in $list) {
    $rec = [pscustomobject]@{ name = $dc.Name; readable = $false; strongBinding = $null; certMappingMethods = $null; build = $null }
    if (Test-AdcsPort $dc.Name) {
      try {
        $b = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc.Name)
        $rec.build = Read-AdcsBuildFrom $b
        $k = $b.OpenSubKey('SYSTEM\CurrentControlSet\Services\Kdc')
        $rec.readable = ($null -ne $k)
        if ($k) { $v = $k.GetValue('StrongCertificateBindingEnforcement'); if ($null -ne $v) { $rec.strongBinding = [int64]$v }; $k.Close() }
        $sc = $b.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel')
        if ($sc) { $m = $sc.GetValue('CertificateMappingMethods'); if ($null -ne $m) { $rec.certMappingMethods = [int64]$m }; $sc.Close() }
        $b.Close()
      } catch { $rec.readable = $false }
    }
    $dcs += $rec
  }
  $ctx.DCs = $dcs
}
#endregion

#region context_stage needs=core,collect,part_templates,part_cas,cafield_editFlags,cafield_interfaceFlags,cafield_keyProvider,cafield_caAces,cafield_web,cafield_build
function Invoke-AdcsContextStage {
  $ctx = Read-AdcsContext @('templates', 'cas')
  foreach ($n in @('templates', 'cas')) { if ($ctx.Errors[$n]) { Write-Output ("ADCS-CONTEXT: " + $n + "=NOT READ (" + $ctx.Errors[$n] + ")") } }
  if ($null -ne $ctx.Templates) {
    $unread = @($ctx.Templates | Where-Object { -not $_.aclReadable }).Count
    $pub = @($ctx.Templates | Where-Object { $_.publishedOn.Count -gt 0 }).Count
    Write-Output ("ADCS-CONTEXT: templates=" + @($ctx.Templates).Count + " published=" + $pub + " acl_unreadable=" + $unread)
  }
  if ($null -ne $ctx.CAs) {
    foreach ($c in $ctx.CAs) { Write-Output ("ADCS-CONTEXT: ca=" + $c.name + " host=" + $c.host + " published_templates=" + @($c.published).Count + " editflags_read=" + ($null -ne $c.editFlags) + " security_read=" + ($null -ne $c.caAces)) }
  }
  if (Read-AdcsConfigDN) { try { Write-Output ("ADCS-CONTEXT: forest=" + [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Name) } catch { Write-Output 'ADCS-CONTEXT: forest=NOT READ' } } else { Write-Output 'ADCS-CONTEXT: forest=NOT READ (host not domain-joined)' }
  Write-Output 'SKIP: context-only step; it builds the AD CS audit context and has no control outcome to score. Not scored. [BAS-SIM-ADCS-CTX]'
}
#endregion

#region publication needs=core,collect,part_templates,part_cas
function Get-AdcsPublicationFindings($ctx) {
  $out = @()
  foreach ($c in @($ctx.CAs)) {
    foreach ($tn in @($c.published)) {
      $hit = @($ctx.Templates | Where-Object { $_.name -eq $tn })
      if ($hit.Count -eq 0) { $out += (New-AdcsFinding 'PUB' 'potential' ([string]$c.name) ("CA publishes template '" + $tn + "' that was not found in the template container (stale publication)") '') }
    }
  }
  $trust = $ctx.NtAuth
  if ($null -ne $trust) {
    foreach ($t in @($trust.unknown)) { $out += (New-AdcsFinding 'PUB' 'potential' ([string]$t) 'NTAuthCertificates trusts a certificate that matches no enterprise CA; confirm it is expected' '') }
    foreach ($w in @($trust.weak)) { $out += (New-AdcsFinding 'PUB' 'confirmed' ([string]$w.subject) ('CA certificate is weak: ' + [string]$w.why) (Format-AdcsPath @() 'certificate chains to this CA' ('CA certificate ' + [string]$w.subject) 'weak key or signature algorithm' 'forged or collided certificates are trusted')) }
  }
  return $out
}
function Invoke-AdcsPublicationStage {
  $ctx = Read-AdcsContext @('templates', 'cas')
  $ctx.NtAuth = Read-AdcsNtAuth
  $why = ''; $complete = $true
  foreach ($n in @('templates', 'cas')) { if ($ctx.Errors[$n]) { $complete = $false; $why += $n + ': ' + $ctx.Errors[$n] + '; ' } }
  if ($null -eq $ctx.NtAuth) { $complete = $false; $why += 'NTAuthCertificates could not be read; ' }
  $f = @(); if ($complete) { $f = Get-AdcsPublicationFindings $ctx }
  Write-AdcsVerdict 'certificate publication and trust' 'BAS-SIM-ADCS-PUB' $f $complete $why 'every published template exists, NTAuthCertificates trusts only enterprise CA certificates and no CA certificate is weak.' 'a CA certificate is weak.'
}
function Read-AdcsNtAuth {
  try {
    $cfg = Read-AdcsConfigDN
    if (-not $cfg) { return $null }
    $e = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=NTAuthCertificates,CN=Public Key Services,CN=Services,$cfg")
    $vals = @($e.Properties['cACertificate'])
    if ($vals.Count -eq 0) { return $null }
    $known = @{}
    $ca = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,$cfg")
    foreach ($c in $ca.Children) { foreach ($b in @($c.Properties['cACertificate'])) { $x = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,[byte[]]$b); $known[$x.Thumbprint] = $true } }
    $unknown = @(); $weak = @()
    foreach ($b in $vals) {
      $x = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,[byte[]]$b)
      if (-not $known.ContainsKey($x.Thumbprint)) { $unknown += $x.Subject }
      $why = @()
      # RSA and ECDSA keys are read through the extension methods; PublicKey.Key throws for ECDSA on Windows PowerShell 5.1.
      try {
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($x)
        if ($rsa) { if ($rsa.KeySize -lt 2048) { $why += ('RSA key size ' + $rsa.KeySize) } }
        else {
          $ec = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($x)
          if ($ec -and $ec.KeySize -lt 256) { $why += ('ECDSA key size ' + $ec.KeySize) }
        }
      } catch { }
      if ($x.SignatureAlgorithm.FriendlyName -match '(?i)sha1|md5') { $why += ('signature ' + $x.SignatureAlgorithm.FriendlyName) }
      if ($x.NotAfter -lt (Get-Date)) { $why += 'expired' }
      if ($why.Count -gt 0) { $weak += [pscustomobject]@{ subject = $x.Subject; why = ($why -join ', ') } }
    }
    return [pscustomobject]@{ unknown = $unknown; weak = $weak }
  } catch { return $null }
}
#endregion

#region correlate needs=core,ace,tfacts,dispatch,cafield_editFlags,cafield_interfaceFlags,cafield_keyProvider,cafield_caAces,cafield_web,cafield_build,esc1,esc2,esc3,esc4,esc5,esc6,esc7,esc8,esc9,esc10,esc11,esc12,esc13,esc14,esc15,collect,part_templates,part_cas,part_pki,part_oids,part_accounts,part_dcs
$script:AdcsCorrFail = 'at least one low-privileged principal has an exploitable certificate-issuance path to a privileged identity.'
$script:AdcsCorrFailNoPath = 'a confirmed misconfiguration is present, but no complete low-privilege issuance path to a privileged identity was established (see the ADCS-FINDING lines).'
function Get-AdcsCorrelation($ctx) {
  $tf = @($ctx.Templates | ForEach-Object { Get-AdcsTemplateFacts $_ })
  $out = @()
  $all = @()
  foreach ($e in @('1', '2', '3', '4', '9', '13')) { $all += @(Get-AdcsEscFindings $e $ctx) }
  foreach ($f in $all) {
    if ($f.State -ne 'confirmed') { $out += $f; continue }
    $tmpl = @($tf | Where-Object { $_.Name -eq $f.Subject })
    if ($tmpl.Count -gt 0 -and $tmpl[0].PublishedOn.Count -gt 0) {
      $out += (New-AdcsFinding $f.Esc 'path' $f.Subject $f.Why $f.Path)
    } else {
      $out += (New-AdcsFinding $f.Esc 'potential' $f.Subject ('latent: ' + $f.Why + '; exploitable only if the template is published') $f.Path)
    }
  }
  # CA-level conditions are paths when the CA can really issue to a low-privileged enrollee.
  $reach = @($tf | Where-Object { $_.PublishedOn.Count -gt 0 -and $_.Enrollers.Count -gt 0 -and ($_.HasAuthEku -or $_.HasAnyOrNoEku) -and (Test-AdcsEnrollGate $_) })
  foreach ($f in @(Get-AdcsEscFindings '6' $ctx)) {
    if ($f.State -ne 'confirmed') { $out += $f; continue }
    $here = @($reach | Where-Object { $_.PublishedOn -contains $f.Subject })
    if ($here.Count -gt 0) { $out += (New-AdcsFinding '6' 'path' $f.Subject $f.Why (Format-AdcsPath $here[0].Enrollers 'Enroll' ('published template ' + $here[0].Name + ' on CA ' + $f.Subject) 'the CA accepts a requester-supplied SAN' 'request a certificate for any identity, including a Domain Admin')) }
    else { $out += (New-AdcsFinding '6' 'potential' $f.Subject ($f.Why + '; no published template enrollable by a low-privileged principal with an authentication EKU was found') $f.Path) }
  }
  foreach ($f in @(Get-AdcsEscFindings '7' $ctx)) {
    if ($f.State -eq 'confirmed') { $out += (New-AdcsFinding '7' 'path' $f.Subject $f.Why $f.Path) } else { $out += $f }
  }
  # ESC8 is assessed only with the live probe, and ESC12 is posture, so neither decides the correlation verdict.
  $rest = @('5', '10', '11', '14', '15'); if ($ctx.LiveProbe) { $rest += '8' }
  foreach ($e in $rest) {
    foreach ($f in @(Get-AdcsEscFindings $e $ctx)) { $out += $f }
  }
  return $out
}
function Invoke-AdcsCorrelationStage {
  $ctx = Read-AdcsContext @('templates', 'cas', 'pki', 'oids', 'dcs', 'accounts')
  $why = ''; $complete = $true
  foreach ($n in @('templates', 'cas', 'pki', 'oids', 'dcs', 'accounts')) { if ($ctx.Errors[$n]) { $complete = $false; $why += $n + ': ' + $ctx.Errors[$n] + '; ' } }
  $f = @(); if ($null -ne $ctx.Templates -and $null -ne $ctx.CAs) { $f = Get-AdcsCorrelation $ctx }
  if ($null -eq $ctx.Templates -or $null -eq $ctx.CAs) { $complete = $false }
  if (-not $ctx.LiveProbe) { Write-Output 'ADCS-CONTEXT: esc8=NOT ASSESSED (BAS_ADCS_LIVE_PROBE is not true), so web enrollment relay exposure is not part of this verdict' }
  Write-AdcsVerdict 'certificate-based privilege escalation correlation' 'BAS-SIM-ADCS-CORR' $f $complete $why 'no low-privileged principal has a path to a privileged certificate and every source was read (ESC8 web enrollment and ESC12 key posture are not part of this verdict).' $script:AdcsCorrFail $script:AdcsCorrFailNoPath
}
#endregion
