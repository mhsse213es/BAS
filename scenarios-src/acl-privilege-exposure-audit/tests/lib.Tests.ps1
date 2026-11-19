param([Parameter(Mandatory=$true)][string]$Lib)
# Offline tests: no domain needed. Builds ActiveDirectorySecurity objects in memory.
$ErrorActionPreference = 'Stop'
. $Lib
$script:fail = 0
function Test-Case([string]$Name, [scriptblock]$Body) {
  try { & $Body; Write-Output "TEST PASS $Name" }
  catch { $script:fail++; Write-Output "TEST FAIL $Name : $($_.Exception.Message)" }
}
function Assert([bool]$c, [string]$m) { if (-not $c) { throw $m } }

$DomSid = 'S-1-5-21-1111-2222-3333'
$LowSid = "$DomSid-1105"; $LowSid2 = "$DomSid-1106"; $GrpSid = "$DomSid-1200"
$DaSid = "$DomSid-512"
$AD = [System.DirectoryServices.ActiveDirectoryRights]
function New-Rule($sid, $rights, $type='Allow', [guid]$ot=[guid]::Empty, $inh='None', [guid]$iot=[guid]::Empty) {
  New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    (New-Object System.Security.Principal.SecurityIdentifier($sid)), $rights, $type, $ot, $inh, $iot)
}
function New-Sec($owner, $rules) {
  $s = New-Object System.DirectoryServices.ActiveDirectorySecurity
  $s.SetOwner((New-Object System.Security.Principal.SecurityIdentifier($owner)))
  foreach ($r in $rules) { $s.AddAccessRule($r) }
  return $s
}
function Reset-Env {
  $script:AclReadErrors = @()
  $script:TargetOverride = @{}
  $script:MembersOverride = @{}
  $script:Offline = $true
  $script:SearchOverride = @{}
  $script:GmsaDescOverride = @{}
  $script:SidToDnOverride = @{}
  $script:TrusteeNameOverride = @{ $LowSid='LOW-user1'; $LowSid2='LOW-user2'; $GrpSid='LOW-grp'; "$DomSid-1300"='LOW-helpdesk'; "$DomSid-1401"='LOW-a'; "$DomSid-1402"='LOW-b' }
  $script:SchemaGuidOverride = @{ 'msDS-KeyCredentialLink' = [guid]'5b47d60f-6090-40b2-9f37-2a4de88f3063' }
  $script:CtxOverride = [pscustomobject]@{ DomainDN='DC=t,DC=local'; ConfigDN='CN=Configuration,DC=t,DC=local'; SchemaDN='CN=Schema,CN=Configuration,DC=t,DC=local'; DomainSid=$DomSid }
}
$DaDn = 'CN=Domain Admins,CN=Users,DC=t,DC=local'

Test-Case 'AddMember ACE for low-priv SID is a finding' {
  Reset-Env
  $script:TargetOverride[$DaDn] = [pscustomobject]@{ Ok=$true; Class='group'; ClassGuid=[guid]::Empty
    Security = (New-Sec $DaSid @((New-Rule $LowSid $AD::WriteProperty 'Allow' ([guid]'bf9679c0-0de6-11d0-a285-00aa003049e2')))) }
  $f = @(Find-CapabilityExposure -TargetDns @($DaDn) -CapNames @('AddMember'))
  Assert ($f.Count -eq 1) "expected 1 finding, got $($f.Count)"
  Assert ($f[0].Trustee -eq $LowSid) 'wrong trustee'
}
Test-Case 'same ACE for Domain Admins is not a finding' {
  Reset-Env
  $script:TargetOverride[$DaDn] = [pscustomobject]@{ Ok=$true; Class='group'; ClassGuid=[guid]::Empty
    Security = (New-Sec $DaSid @((New-Rule $DaSid $AD::GenericAll))) }
  $f = @(Find-CapabilityExposure -TargetDns @($DaDn) -CapNames @('GenericAll'))
  Assert ($f.Count -eq 0) "expected 0, got $($f.Count)"
}
Test-Case 'all-property WriteProperty grants AddMember' {
  Reset-Env
  $script:TargetOverride[$DaDn] = [pscustomobject]@{ Ok=$true; Class='group'; ClassGuid=[guid]::Empty
    Security = (New-Sec $DaSid @((New-Rule $LowSid $AD::WriteProperty))) }
  $f = @(Find-CapabilityExposure -TargetDns @($DaDn) -CapNames @('AddMember'))
  Assert ($f.Count -eq 1) "expected 1, got $($f.Count)"
}
Test-Case 'unrelated property WriteProperty does not grant AddMember' {
  Reset-Env
  $script:TargetOverride[$DaDn] = [pscustomobject]@{ Ok=$true; Class='group'; ClassGuid=[guid]::Empty
    Security = (New-Sec $DaSid @((New-Rule $LowSid $AD::WriteProperty 'Allow' ([guid]'11111111-2222-3333-4444-555555555555')))) }
  $f = @(Find-CapabilityExposure -TargetDns @($DaDn) -CapNames @('AddMember'))
  Assert ($f.Count -eq 0) "expected 0, got $($f.Count)"
}
Test-Case 'explicit Deny keeps the finding at MEDIUM' {
  Reset-Env
  $script:TargetOverride[$DaDn] = [pscustomobject]@{ Ok=$true; Class='group'; ClassGuid=[guid]::Empty
    Security = (New-Sec $DaSid @((New-Rule $LowSid $AD::GenericAll 'Allow'), (New-Rule $LowSid $AD::GenericAll 'Deny'))) }
  $f = @(Find-CapabilityExposure -TargetDns @($DaDn) -CapNames @('GenericAll'))
  Assert ($f.Count -eq 1) "expected 1, got $($f.Count)"
  Assert ($f[0].Confidence -eq 'MEDIUM') "expected MEDIUM, got $($f[0].Confidence)"
}
Test-Case 'inherit-only ACE is ignored' {
  Reset-Env
  $script:TargetOverride[$DaDn] = [pscustomobject]@{ Ok=$true; Class='group'; ClassGuid=[guid]::Empty
    Security = (New-Sec $DaSid @((New-Rule $LowSid $AD::GenericAll 'Allow' ([guid]::Empty) 'Descendents'))) }
  $f = @(Find-CapabilityExposure -TargetDns @($DaDn) -CapNames @('GenericAll'))
  Assert ($f.Count -eq 0) "expected 0, got $($f.Count)"
}
Test-Case 'InheritedObjectType mismatch is ignored' {
  Reset-Env
  $g = [guid]'aaaaaaaa-0000-0000-0000-000000000001'; $other = [guid]'bbbbbbbb-0000-0000-0000-000000000002'
  $script:TargetOverride[$DaDn] = [pscustomobject]@{ Ok=$true; Class='group'; ClassGuid=$g
    Security = (New-Sec $DaSid @((New-Rule $LowSid $AD::GenericAll 'Allow' ([guid]::Empty) 'All' $other))) }
  $f = @(Find-CapabilityExposure -TargetDns @($DaDn) -CapNames @('GenericAll'))
  Assert ($f.Count -eq 0) "expected 0, got $($f.Count)"
}
Test-Case 'SELF and CREATOR OWNER are expected principals' {
  Reset-Env
  $script:TargetOverride[$DaDn] = [pscustomobject]@{ Ok=$true; Class='group'; ClassGuid=[guid]::Empty
    Security = (New-Sec $DaSid @((New-Rule 'S-1-5-10' $AD::WriteProperty), (New-Rule 'S-1-3-0' $AD::GenericAll))) }
  $f = @(Find-CapabilityExposure -TargetDns @($DaDn) -CapNames @('GenericAll','GenericWriteSensitive'))
  Assert ($f.Count -eq 0) "expected 0, got $($f.Count)"
}
Test-Case 'unresolved SID is reported with LOW confidence' {
  Reset-Env
  $script:TargetOverride[$DaDn] = [pscustomobject]@{ Ok=$true; Class='group'; ClassGuid=[guid]::Empty
    Security = (New-Sec $DaSid @((New-Rule "$DomSid-9999" $AD::GenericAll))) }
  $f = @(Find-CapabilityExposure -TargetDns @($DaDn) -CapNames @('GenericAll'))
  Assert ($f.Count -eq 1) "expected 1, got $($f.Count)"
  Assert ($f[0].Confidence -eq 'LOW') "expected LOW, got $($f[0].Confidence)"
}
Test-Case 'group whose only members are tier-0 is not a finding' {
  Reset-Env
  $script:MembersOverride[$GrpSid] = @($DaSid)
  $script:TargetOverride[$DaDn] = [pscustomobject]@{ Ok=$true; Class='group'; ClassGuid=[guid]::Empty
    Security = (New-Sec $DaSid @((New-Rule $GrpSid $AD::GenericAll))) }
  $f = @(Find-CapabilityExposure -TargetDns @($DaDn) -CapNames @('GenericAll'))
  Assert ($f.Count -eq 0) "expected 0, got $($f.Count)"
}
Test-Case 'group with a low-priv member is a finding with a path' {
  Reset-Env
  $script:MembersOverride[$GrpSid] = @($LowSid)
  $script:TargetOverride[$DaDn] = [pscustomobject]@{ Ok=$true; Class='group'; ClassGuid=[guid]::Empty
    Security = (New-Sec $DaSid @((New-Rule $GrpSid $AD::GenericAll))) }
  $f = @(Find-CapabilityExposure -TargetDns @($DaDn) -CapNames @('GenericAll'))
  Assert ($f.Count -eq 1) "expected 1, got $($f.Count)"
  Assert ($f[0].Via -like "*$LowSid*") 'path does not name the member'
}
Test-Case 'unreadable target gives SKIP, not PASS' {
  Reset-Env
  $script:TargetOverride[$DaDn] = [pscustomobject]@{ Ok=$false; Class=''; ClassGuid=[guid]::Empty; Security=$null }
  $r = Invoke-AclStage -Id 'T1' -Plan @(@{ Scope='dn:' + $DaDn; Caps=@('GenericAll') }) -PassText 'clean' -PassThru
  Assert ($r.Verdict -eq 'SKIP') "expected SKIP, got $($r.Verdict)"
}
Test-Case 'clean target gives PASS and exposure gives FAIL' {
  Reset-Env
  $script:TargetOverride[$DaDn] = [pscustomobject]@{ Ok=$true; Class='group'; ClassGuid=[guid]::Empty
    Security = (New-Sec $DaSid @((New-Rule $DaSid $AD::GenericAll))) }
  $r = Invoke-AclStage -Id 'T2' -Plan @(@{ Scope='dn:' + $DaDn; Caps=@('GenericAll') }) -PassText 'clean' -PassThru
  Assert ($r.Verdict -eq 'PASS') "expected PASS, got $($r.Verdict)"
  $script:TargetOverride[$DaDn].Security = (New-Sec $DaSid @((New-Rule $LowSid $AD::GenericAll)))
  $r = Invoke-AclStage -Id 'T3' -Plan @(@{ Scope='dn:' + $DaDn; Caps=@('GenericAll') }) -PassText 'clean' -PassThru
  Assert ($r.Verdict -eq 'FAIL') "expected FAIL, got $($r.Verdict)"
}
Test-Case 'owner check flags a non-tier-0 owner' {
  Reset-Env
  $script:TargetOverride[$DaDn] = [pscustomobject]@{ Ok=$true; Class='group'; ClassGuid=[guid]::Empty
    Security = (New-Sec $LowSid @((New-Rule $DaSid $AD::GenericAll))) }
  $f = @(Find-OwnerExposure -TargetDns @($DaDn))
  Assert ($f.Count -eq 1) "expected 1, got $($f.Count)"
}
Test-Case 'missing schema attribute reports not deployed' {
  Reset-Env
  $script:SchemaGuidOverride['ms-Mcs-AdmPwd'] = $null
  $script:TargetOverride[$DaDn] = [pscustomobject]@{ Ok=$true; Class='group'; ClassGuid=[guid]::Empty
    Security = (New-Sec $DaSid @()) }
  $r = Invoke-AclStage -Id 'T4' -Plan @(@{ Scope='dn:' + $DaDn; Caps=@('LapsLegacyRead') }) -PassText 'clean' -PassThru
  Assert ($r.Verdict -eq 'PASS') "expected PASS, got $($r.Verdict)"
  Assert ($r.Notes -like '*not deployed*') 'missing not-deployed note'
}
Test-Case 'two-hop path to tier-0 is found' {
  Reset-Env
  $BDn = 'CN=HelpDesk,OU=x,DC=t,DC=local'; $BSid = "$DomSid-1300"
  $script:SidToDnOverride = @{ $BSid = $BDn }
  $script:TargetOverride[$DaDn] = [pscustomobject]@{ Ok=$true; Class='group'; ClassGuid=[guid]::Empty
    Security = (New-Sec $DaSid @((New-Rule $BSid $AD::GenericAll))) }
  $script:TargetOverride[$BDn] = [pscustomobject]@{ Ok=$true; Class='group'; ClassGuid=[guid]::Empty
    Security = (New-Sec $DaSid @((New-Rule $LowSid $AD::WriteProperty 'Allow' ([guid]'bf9679c0-0de6-11d0-a285-00aa003049e2')))) }
  $p = @(Find-AttackPaths -Tier0Dns @($DaDn) -MaxDepth 3)
  Assert ($p.Count -ge 1) 'no path found'
  $two = @($p | Where-Object { $_.Start -eq $LowSid -and $_.Hops -eq 2 })
  Assert ($two.Count -eq 1) "two-hop path missing (got $($two.Count))"
}
Test-Case 'attack-path search terminates on cycles' {
  Reset-Env
  $ADn = 'CN=A,DC=t,DC=local'; $ASid = "$DomSid-1401"; $BDn = 'CN=B,DC=t,DC=local'; $BSid = "$DomSid-1402"
  $script:SidToDnOverride = @{ $ASid = $ADn; $BSid = $BDn }
  $script:TargetOverride[$DaDn] = [pscustomobject]@{ Ok=$true; Class='group'; ClassGuid=[guid]::Empty; Security = (New-Sec $DaSid @((New-Rule $ASid $AD::GenericAll))) }
  $script:TargetOverride[$ADn] = [pscustomobject]@{ Ok=$true; Class='group'; ClassGuid=[guid]::Empty; Security = (New-Sec $DaSid @((New-Rule $BSid $AD::GenericAll))) }
  $script:TargetOverride[$BDn] = [pscustomobject]@{ Ok=$true; Class='group'; ClassGuid=[guid]::Empty; Security = (New-Sec $DaSid @((New-Rule $ASid $AD::GenericAll))) }
  $p = @(Find-AttackPaths -Tier0Dns @($DaDn) -MaxDepth 3)
  Assert ($p.Count -lt 50) 'path explosion'
}
Test-Case 'stale adminCount is reported apart from exposure' {
  Reset-Env
  $AdminSid = "$DomSid-500"; $AdminDn = 'CN=Administrator,CN=Users,DC=t,DC=local'; $OldDn = 'CN=oldadmin,CN=Users,DC=t,DC=local'
  $script:SidToDnOverride = @{ $AdminSid = $AdminDn }
  $script:MembersOverride["$DomSid-512"] = @($AdminSid)
  $script:SearchOverride = @{ '(adminCount=1)' = @($AdminDn, $OldDn) }
  $script:TargetOverride[$AdminDn] = [pscustomobject]@{ Ok=$true; Class='user'; ClassGuid=[guid]::Empty; Security = (New-Sec $DaSid @((New-Rule $DaSid $AD::GenericAll))) }
  $script:TargetOverride[$OldDn] = [pscustomobject]@{ Ok=$true; Class='user'; ClassGuid=[guid]::Empty; Security = (New-Sec $DaSid @((New-Rule $DaSid $AD::GenericAll))) }
  $r = Invoke-StaleAdminCountStage -Id 'T5' -PassThru
  Assert ($r.Verdict -eq 'PASS') "stale-only must not FAIL, got $($r.Verdict)"
  Assert (@($r.Stale).Count -eq 1 -and @($r.Stale)[0] -eq $OldDn) 'stale list wrong'
  $script:SearchOverride = @{}
}
Test-Case 'gMSA readable by a user principal is a finding' {
  Reset-Env
  $GDn = 'CN=svc1,CN=Managed Service Accounts,DC=t,DC=local'
  $script:SearchOverride = @{ '(objectClass=msDS-GroupManagedServiceAccount)' = @($GDn) }
  $script:GmsaDescOverride = @{ $GDn = @('S-1-5-11') }
  $script:TargetOverride[$GDn] = [pscustomobject]@{ Ok=$true; Class='msDS-GroupManagedServiceAccount'; ClassGuid=[guid]::Empty; Security = (New-Sec $DaSid @()) }
  $r = Invoke-GmsaStage -Id 'T6' -PassThru
  Assert ($r.Verdict -eq 'FAIL') "expected FAIL, got $($r.Verdict)"
  $script:SearchOverride = @{}; $script:GmsaDescOverride = @{}
}
Test-Case 'no gMSA objects is a PASS marked not deployed' {
  Reset-Env
  $script:SearchOverride = @{ '(objectClass=msDS-GroupManagedServiceAccount)' = @() }
  $r = Invoke-GmsaStage -Id 'T7' -PassThru
  Assert ($r.Verdict -eq 'PASS') "expected PASS, got $($r.Verdict)"
  $script:SearchOverride = @{}
}
# ---- audit-driven realism tests ----
Test-Case 'AUDIT: Authenticated Users default read-all does not make a LAPS finding' {
  Reset-Env
  $script:SchemaGuidOverride['ms-Mcs-AdmPwd'] = [guid]'11111111-aaaa-bbbb-cccc-000000000001'
  $OuDn = 'OU=Servers,DC=t,DC=local'
  $script:TargetOverride[$OuDn] = [pscustomobject]@{ Ok=$true; Class='organizationalUnit'; ClassGuid=[guid]::Empty
    Security = (New-Sec $DaSid @((New-Rule 'S-1-5-11' ($AD::ReadProperty -bor $AD::ListChildren -bor $AD::ListObject -bor $AD::ReadControl)))) }
  $f = @(Find-CapabilityExposure -TargetDns @($OuDn) -CapNames @('LapsLegacyRead'))
  Assert ($f.Count -eq 0) "default Authenticated Users read produced $($f.Count) LAPS finding(s)"
}
Test-Case 'AUDIT: LAPS read needs control access too (both bits => finding)' {
  Reset-Env
  $script:SchemaGuidOverride['ms-Mcs-AdmPwd'] = [guid]'11111111-aaaa-bbbb-cccc-000000000001'
  $OuDn = 'OU=Servers,DC=t,DC=local'
  $script:TargetOverride[$OuDn] = [pscustomobject]@{ Ok=$true; Class='organizationalUnit'; ClassGuid=[guid]::Empty
    Security = (New-Sec $DaSid @((New-Rule $LowSid $AD::ReadProperty 'Allow' ([guid]'11111111-aaaa-bbbb-cccc-000000000001')), (New-Rule $LowSid $AD::ExtendedRight))) }
  $f = @(Find-CapabilityExposure -TargetDns @($OuDn) -CapNames @('LapsLegacyRead'))
  Assert ($f.Count -eq 1) "expected 1 LAPS finding, got $($f.Count)"
  Assert ($f[0].Confidence -eq 'HIGH') "expected HIGH, got $($f[0].Confidence)"
}
Test-Case 'AUDIT: tier0-parents scope never includes the parent of the domain head' {
  Reset-Env
  $p = @(Scope-tier0-parents)
  Assert (-not ($p -contains 'DC=local')) "scope includes non-object parent DC=local: $($p -join ' | ')"
}
Test-Case 'AUDIT: forest-root Enterprise Admins on a child-domain object is not a finding' {
  Reset-Env
  $script:TargetOverride[$DaDn] = [pscustomobject]@{ Ok=$true; Class='group'; ClassGuid=[guid]::Empty
    Security = (New-Sec $DaSid @((New-Rule 'S-1-5-21-9-9-9-519' $AD::GenericAll), (New-Rule 'S-1-5-21-9-9-9-518' $AD::WriteDacl))) }
  $f = @(Find-CapabilityExposure -TargetDns @($DaDn) -CapNames @('GenericAll','WriteDacl'))
  Assert ($f.Count -eq 0) "forest-level EA/SA flagged: $($f.Count)"
}
Test-Case 'AUDIT: Protected Users is not an expected principal' {
  Reset-Env
  $script:TargetOverride[$DaDn] = [pscustomobject]@{ Ok=$true; Class='group'; ClassGuid=[guid]::Empty
    Security = (New-Sec $DaSid @((New-Rule "$DomSid-525" $AD::GenericAll))) }
  $f = @(Find-CapabilityExposure -TargetDns @($DaDn) -CapNames @('GenericAll'))
  Assert ($f.Count -eq 1) "Protected Users hidden: $($f.Count)"
}
Test-Case 'AUDIT: path stage with an unreadable tier-0 object is not a PASS' {
  Reset-Env
  $script:TargetOverride['DC=t,DC=local'] = [pscustomobject]@{ Ok=$true; Class='domainDNS'; ClassGuid=[guid]::Empty; Security = (New-Sec $DaSid @((New-Rule $DaSid $AD::GenericAll))) }
  $script:TargetOverride['CN=AdminSDHolder,CN=System,DC=t,DC=local'] = [pscustomobject]@{ Ok=$false; Class=''; ClassGuid=[guid]::Empty; Security=$null }
  $out = (Invoke-PathStage -Id 'T8' | Out-String)
  Assert ($out -notmatch '^PASS') "path stage printed PASS despite an unreadable object: $out"
}
Test-Case 'AUDIT: gMSA membership-descriptor write is a finding, default read is not' {
  Reset-Env
  $script:SchemaGuidOverride['msDS-GroupMSAMembership'] = [guid]'22222222-aaaa-bbbb-cccc-000000000002'
  $GDn = 'CN=svc1,CN=Managed Service Accounts,DC=t,DC=local'
  $script:TargetOverride[$GDn] = [pscustomobject]@{ Ok=$true; Class='msDS-GroupManagedServiceAccount'; ClassGuid=[guid]::Empty
    Security = (New-Sec $DaSid @((New-Rule 'S-1-5-11' ($AD::ReadProperty -bor $AD::ListChildren)), (New-Rule $LowSid $AD::WriteProperty 'Allow' ([guid]'22222222-aaaa-bbbb-cccc-000000000002')))) }
  $f = @(Find-CapabilityExposure -TargetDns @($GDn) -CapNames @('GmsaMembershipWrite'))
  Assert ($f.Count -eq 1 -and $f[0].Trustee -eq $LowSid) "expected exactly the low-priv writer, got $($f.Count)"
}
Test-Case 'AUDIT: GPO property-specific write is a finding' {
  Reset-Env
  $script:SchemaGuidOverride['gPCFileSysPath'] = [guid]'33333333-aaaa-bbbb-cccc-000000000003'
  $Gpo = 'CN={X},CN=Policies,CN=System,DC=t,DC=local'
  $script:TargetOverride[$Gpo] = [pscustomobject]@{ Ok=$true; Class='groupPolicyContainer'; ClassGuid=[guid]::Empty
    Security = (New-Sec $DaSid @((New-Rule $LowSid $AD::WriteProperty 'Allow' ([guid]'33333333-aaaa-bbbb-cccc-000000000003')))) }
  $f = @(Find-CapabilityExposure -TargetDns @($Gpo) -CapNames @('GpoWrite'))
  Assert ($f.Count -eq 1) "GPO file-path write missed: $($f.Count)"
}
Test-Case 'AUDIT: gMSA reader group of computers only is not a finding; with a user it is' {
  Reset-Env
  $GDn = 'CN=svc2,CN=Managed Service Accounts,DC=t,DC=local'; $RG = "$DomSid-2000"; $Comp = "$DomSid-3001"; $Usr = "$DomSid-3002"
  $script:SearchOverride = @{ '(objectClass=msDS-GroupManagedServiceAccount)' = @($GDn) }
  $script:GmsaDescOverride = @{ $GDn = @($RG) }
  $script:KindOverride = @{ $RG = 'group'; $Comp = 'computer'; $Usr = 'user' }
  $script:TargetOverride[$GDn] = [pscustomobject]@{ Ok=$true; Class='msDS-GroupManagedServiceAccount'; ClassGuid=[guid]::Empty; Security = (New-Sec $DaSid @()) }
  $script:MembersOverride[$RG] = @($Comp)
  $r = Invoke-GmsaStage -Id 'T9' -PassThru
  Assert ($r.Verdict -eq 'PASS') "computer-only reader group: expected PASS, got $($r.Verdict)"
  $script:MembersOverride[$RG] = @($Comp, $Usr)
  $r = Invoke-GmsaStage -Id 'T10' -PassThru
  Assert ($r.Verdict -eq 'FAIL') "reader group with a user: expected FAIL, got $($r.Verdict)"
  $script:KindOverride = @{}
}
if ($script:fail -gt 0) { Write-Output "FAILED: $($script:fail)"; exit 1 }
Write-Output 'ALL TESTS PASSED'
