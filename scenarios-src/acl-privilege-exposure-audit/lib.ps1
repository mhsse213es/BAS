# ---- Audspect ACL audit library (read-only; generated into every stage) ----
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.DirectoryServices
$script:AclReadErrors = @()
$script:SchemaCache = @{}
$script:MemberCache = @{}
$script:Truncated = @()
$AdR = [System.DirectoryServices.ActiveDirectoryRights]
$script:G = @{
  Member     = [guid]'bf9679c0-0de6-11d0-a285-00aa003049e2'
  Spn        = [guid]'f3a64788-5306-11d1-a9c5-00c04fd8d5cd'
  DnsHost    = [guid]'72e39547-7b18-11d1-adef-00c04fd8d5cd'
  ResetPwd   = [guid]'00299570-246d-11d0-a768-00aa006e0529'
  GetChanges = [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
  GetChgAll  = [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
  GetChgFilt = [guid]'89e95b76-444d-4c62-991a-0facbeda640c'
}
$script:Broad = @('S-1-1-0','S-1-5-11','S-1-5-32-545')
$script:PrivRids = @(512,516,518,519,520,521,526,527,498,500)
$script:BuiltinTier0 = @('S-1-5-18','S-1-5-9','S-1-5-10','S-1-3-0','S-1-5-32-544','S-1-5-32-548','S-1-5-32-549','S-1-5-32-550','S-1-5-32-551','S-1-5-32-552')
$script:PrivGroupSids = @('S-1-5-32-544','S-1-5-32-548','S-1-5-32-549','S-1-5-32-550','S-1-5-32-551')
$script:PrivGroupRids = @(512,518,519,516,520,526,527)

# Capability registry. Attrs are LDAP display names resolved against the schema at run time.
# Rights is a rights mask; Any=$true means an ACE with an empty ObjectType also grants.
$script:Caps = @{
  GenericAll            = @{ Rights=$AdR::GenericAll; Full=$true }
  WriteDacl             = @{ Rights=$AdR::WriteDacl }
  WriteOwner            = @{ Rights=$AdR::WriteOwner }
  GenericWriteSensitive = @{ Rights=$AdR::WriteProperty; Attrs=@('member','servicePrincipalName','msDS-KeyCredentialLink','msDS-AllowedToActOnBehalfOfOtherIdentity','userAccountControl','msDS-AllowedToDelegateTo','scriptPath','gPLink','altSecurityIdentities') }
  WriteAllProperties    = @{ Rights=$AdR::WriteProperty; AllOnly=$true }
  Delete                = @{ Rights=$AdR::Delete }
  DeleteTree            = @{ Rights=$AdR::DeleteTree }
  DeleteChild           = @{ Rights=$AdR::DeleteChild }
  ForceChangePassword   = @{ Rights=$AdR::ExtendedRight; Guids=@('ResetPwd') }
  AddMember             = @{ Rights=$AdR::WriteProperty; Guids=@('Member') }
  AddSelf               = @{ Rights=$AdR::Self; Guids=@('Member') }
  ShadowCredentials     = @{ Rights=$AdR::WriteProperty; Attrs=@('msDS-KeyCredentialLink') }
  SpnWrite              = @{ Rights=$AdR::WriteProperty; Guids=@('Spn') }
  ValidatedSpn          = @{ Rights=$AdR::Self; Guids=@('Spn') }
  ValidatedDnsHostName  = @{ Rights=$AdR::Self; Guids=@('DnsHost') }
  RbcdWrite             = @{ Rights=$AdR::WriteProperty; Attrs=@('msDS-AllowedToActOnBehalfOfOtherIdentity') }
  LapsLegacyRead        = @{ Rights=$AdR::ReadProperty; Attrs=@('ms-Mcs-AdmPwd'); Companion=$true }
  LapsWindowsRead       = @{ Rights=$AdR::ReadProperty; Attrs=@('msLAPS-Password','msLAPS-EncryptedPassword'); Companion=$true }
  GmsaMembershipWrite   = @{ Rights=$AdR::WriteProperty; Attrs=@('msDS-GroupMSAMembership') }
  AccountRestrictions   = @{ Rights=$AdR::WriteProperty; Attrs=@('userAccountControl','msDS-AllowedToDelegateTo','msDS-SupportedEncryptionTypes','scriptPath','altSecurityIdentities','userParameters') }
  DcSync                = @{ Rights=$AdR::ExtendedRight; Guids=@('GetChanges','GetChgAll','GetChgFilt') }
  GpLinkWrite           = @{ Rights=$AdR::WriteProperty; Attrs=@('gPLink','gPOptions') }
  GpoWrite              = @{ Rights=$AdR::WriteProperty; Attrs=@('gPCFileSysPath','gPCMachineExtensionNames','gPCUserExtensionNames') }
  CreateChild           = @{ Rights=$AdR::CreateChild }
}

function Get-SchemaGuid([string]$Name, [string]$Kind = 'attributeSchema') {
  $k = "$Kind|$Name"
  if ($script:SchemaGuidOverride -and $script:SchemaGuidOverride.ContainsKey($Name)) { return $script:SchemaGuidOverride[$Name] }
  if ($script:SchemaCache.ContainsKey($k)) { return $script:SchemaCache[$k] }
  if ($script:Offline) { return $null }
  $g = $null
  try {
    $ctx = Get-AclContext
    $s = New-Object System.DirectoryServices.DirectorySearcher((New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($ctx.SchemaDN)")))
    $s.Filter = "(&(objectClass=$Kind)(lDAPDisplayName=$Name))"
    [void]$s.PropertiesToLoad.Add('schemaIDGUID')
    $r = $s.FindOne()
    if ($r) { $g = [guid]([byte[]]$r.Properties['schemaidguid'][0]) }
  } catch {
    # a failed lookup is not proof the attribute is absent: record it and do not cache it
    $script:AclReadErrors += "schema:$Name"
    return $null
  }
  $script:SchemaCache[$k] = $g
  return $g
}

function Get-AclContext {
  if ($script:CtxOverride) { return $script:CtxOverride }
  if ($script:CtxReal) { return $script:CtxReal }
  $root = [ADSI]'LDAP://RootDSE'
  $dn = [string]$root.defaultNamingContext
  if (-not $dn) { throw 'no domain' }
  $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn")
  $sid = (New-Object System.Security.Principal.SecurityIdentifier([byte[]]$de.Properties['objectSid'][0], 0)).Value
  $script:CtxReal = [pscustomobject]@{ DomainDN=$dn; ConfigDN=[string]$root.configurationNamingContext; SchemaDN=[string]$root.schemaNamingContext; DomainSid=$sid }
  return $script:CtxReal
}

function Test-ExpectedPrincipal([string]$Sid) {
  if ($script:BuiltinTier0 -contains $Sid) { return $true }
  $ctx = Get-AclContext
  if ($Sid.StartsWith($ctx.DomainSid + '-')) {
    $rid = 0
    if ([int]::TryParse($Sid.Substring($ctx.DomainSid.Length + 1), [ref]$rid) -and ($script:PrivRids -contains $rid)) { return $true }
  }
  # Enterprise Admins (519) and Schema Admins (518) live in the forest root domain, so in a child
  # domain their SID does not carry the local domain prefix.
  if ($Sid -match '^S-1-5-21-\d+-\d+-\d+-(518|519)$') { return $true }
  return $false
}

function Get-TargetSecurity([string]$Dn) {
  if ($script:TargetOverride -and $script:TargetOverride.ContainsKey($Dn)) { return $script:TargetOverride[$Dn] }
  try {
    $e = New-Object System.DirectoryServices.DirectoryEntry('LDAP://' + $Dn.Replace('/', '\/'))
    $e.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]'Dacl,Owner'
    $e.RefreshCache()
    $cls = [string]($e.Properties['objectClass'] | Select-Object -Last 1)
    $cg = [guid]::Empty
    $g = Get-SchemaGuid $cls 'classSchema'
    if ($g) { $cg = $g }
    return [pscustomobject]@{ Ok=$true; Class=$cls; ClassGuid=$cg; Security=$e.ObjectSecurity }
  } catch {
    return [pscustomobject]@{ Ok=$false; Class=''; ClassGuid=[guid]::Empty; Security=$null }
  }
}

function ConvertTo-AceRecord($Ace) {
  [pscustomobject]@{
    Trustee   = [string]$Ace.IdentityReference.Value
    Type      = [string]$Ace.AccessControlType
    Rights    = $Ace.ActiveDirectoryRights
    ObjectType = [guid]$Ace.ObjectType
    InheritedObjectType = [guid]$Ace.InheritedObjectType
    IsInherited = [bool]$Ace.IsInherited
    InheritOnly = (([int]$Ace.PropagationFlags -band 2) -ne 0)
    Propagates = (([int]$Ace.InheritanceFlags -band 1) -ne 0)
  }
}

function Test-AceApplies($Rec, [guid]$TargetClassGuid) {
  if ($Rec.InheritOnly) { return $false }
  if ($Rec.InheritedObjectType -ne [guid]::Empty -and $TargetClassGuid -ne [guid]::Empty -and $Rec.InheritedObjectType -ne $TargetClassGuid) { return $false }
  return $true
}

function Resolve-CapGuids($Cap) {
  $list = @()
  if ($Cap.Guids) { foreach ($n in $Cap.Guids) { $list += $script:G[$n] } }
  $missing = @()
  if ($Cap.Attrs) {
    foreach ($a in $Cap.Attrs) {
      $g = Get-SchemaGuid $a
      if ($g) { $list += $g } else { $missing += $a }
    }
  }
  return [pscustomobject]@{ Guids = $list; Missing = $missing }
}

function Test-AceGrants($Rec, $Cap, $Resolved) {
  $r = $Rec.Rights
  if (($r -band $AdR::GenericAll) -eq $AdR::GenericAll) { return $true }
  if ($Cap.Full) { return $false }
  if (($r -band $Cap.Rights) -eq 0) { return $false }
  if ($Cap.AllOnly) { return ($Rec.ObjectType -eq [guid]::Empty) }
  $hasObjSpec = ($Cap.Guids -or $Cap.Attrs)
  if (-not $hasObjSpec) { return $true }
  if ($Rec.ObjectType -eq [guid]::Empty) { return $true }
  return ($Resolved.Guids -contains $Rec.ObjectType)
}

function Resolve-Trustee([string]$Sid) {
  if ($script:TrusteeNameOverride -and $script:TrusteeNameOverride.ContainsKey($Sid)) { return [pscustomobject]@{ Name=$script:TrusteeNameOverride[$Sid]; Resolved=$true } }
  if ($script:Offline) { return [pscustomobject]@{ Name='(unresolved)'; Resolved=$false } }
  try {
    $n = (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value
    return [pscustomobject]@{ Name=$n; Resolved=$true }
  } catch { return [pscustomobject]@{ Name='(unresolved)'; Resolved=$false } }
}

function Get-DnFromSid([string]$Sid) {
  if ($script:SidToDnOverride -and $script:SidToDnOverride.ContainsKey($Sid)) { return $script:SidToDnOverride[$Sid] }
  if ($script:Offline) { return $null }
  try { return [string]([ADSI]"LDAP://<SID=$Sid>").distinguishedName } catch { return $null }
}

# Returns @{ IsGroup; Members(string[] of leaf and nested SIDs); Truncated }
function Get-EffectiveMembers([string]$Sid) {
  if ($script:MembersOverride -and $script:MembersOverride.ContainsKey($Sid)) {
    return [pscustomobject]@{ IsGroup=$true; Members=@($script:MembersOverride[$Sid]); Truncated=$false }
  }
  if ($script:Offline) { return [pscustomobject]@{ IsGroup=$false; Members=@(); Truncated=$false } }
  if ($script:MemberCache.ContainsKey($Sid)) { return $script:MemberCache[$Sid] }
  $res = [pscustomobject]@{ IsGroup=$false; Members=@(); Truncated=$false }
  try {
    $dn = Get-DnFromSid $Sid
    if ($dn) {
      $e = [ADSI]"LDAP://$($dn.Replace('/', '\/'))"
      $cls = @($e.objectClass)
      if ($cls -contains 'group') {
        $res.IsGroup = $true
        $seen = @{}; $queue = New-Object System.Collections.Queue; $queue.Enqueue($dn); $out = @()
        while ($queue.Count -gt 0) {
          $cur = $queue.Dequeue()
          if ($seen.ContainsKey($cur)) { continue }
          $seen[$cur] = $true
          if ($seen.Count -gt 2000) { $res.Truncated = $true; break }
          $ce = [ADSI]"LDAP://$($cur.Replace('/', '\/'))"
          if (@($ce.member).Count -ge 1500) { $res.Truncated = $true }
        foreach ($m in @($ce.member)) {
            $me = [ADSI]"LDAP://$($m.Replace('/', '\/'))"
            $ms = (New-Object System.Security.Principal.SecurityIdentifier([byte[]]$me.objectSid[0], 0)).Value
            $out += $ms
            if (@($me.objectClass) -contains 'group') { $queue.Enqueue($m) }
          }
        }
        $res.Members = $out
      }
    }
  } catch { }
  $script:MemberCache[$Sid] = $res
  return $res
}

function Get-TrusteeKind([string]$Sid, $Members) {
  if ($Members.IsGroup) { return 'group' }
  return 'principal'
}

# Core: who holds capability X on these targets? Findings only for non-expected trustees.
function Find-CapabilityExposure {
  param([string[]]$TargetDns, [string[]]$CapNames, [switch]$InheritedOnly)
  $found = @(); $dedupe = @{}
  foreach ($dn in $TargetDns) {
    $t = Get-TargetSecurity $dn
    if (-not $t.Ok) { $script:AclReadErrors += $dn; continue }
    $script:Examined = [int]$script:Examined + 1
    $rules = $t.Security.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    $recs = @(); foreach ($a in $rules) { $recs += ConvertTo-AceRecord $a }
    $allows = @($recs | Where-Object { $_.Type -eq 'Allow' -and (Test-AceApplies $_ $t.ClassGuid) })
    $denies = @($recs | Where-Object { $_.Type -eq 'Deny' -and (Test-AceApplies $_ $t.ClassGuid) })
    foreach ($cn in $CapNames) {
      $cap = $script:Caps[$cn]
      if (-not $cap) { throw "unknown capability $cn" }
      $res = Resolve-CapGuids $cap
      if ($cap.Attrs -and $res.Guids.Count -eq 0 -and $res.Missing.Count -gt 0) {
        $script:NotDeployed += "$cn ($($res.Missing -join ','))"
        continue
      }
      foreach ($a in $allows) {
        if ($InheritedOnly -and -not $a.IsInherited) { continue }
        if (-not (Test-AceGrants $a $cap $res)) { continue }
        $sid = $a.Trustee
        if (Test-ExpectedPrincipal $sid) { continue }
        if ($cap.Companion -and ($a.Rights -band $AdR::GenericAll) -ne $AdR::GenericAll) {
          # confidential attributes (LAPS) need ReadProperty AND control access; plain read-all is the default
          $comp = @($allows | Where-Object { $_.Trustee -eq $sid -and (($_.Rights -band $AdR::ExtendedRight) -ne 0) -and $_.ObjectType -eq [guid]::Empty })
          if ($comp.Count -eq 0) { continue }
        }
        $key = "$dn|$sid|$cn"
        if ($dedupe.ContainsKey($key)) { continue }
        $mem = Get-EffectiveMembers $sid
        $via = ''
        if ($mem.IsGroup) {
          $nonExp = @($mem.Members | Where-Object { -not (Test-ExpectedPrincipal $_) })
          if ($mem.Members.Count -gt 0 -and $nonExp.Count -eq 0 -and -not $mem.Truncated) { continue }
          if ($nonExp.Count -gt 0) { $via = 'members: ' + (($nonExp | Select-Object -First 5) -join ',') } else { $via = 'empty group' }
        }
        $tr = Resolve-Trustee $sid
        $conf = 'HIGH'
        if (-not $tr.Resolved) { $conf = 'LOW' }
        elseif ($mem.IsGroup -and ($mem.Truncated -or $mem.Members.Count -eq 0)) { $conf = 'MEDIUM' }
        $note = ''
        $denied = @($denies | Where-Object { ($_.Trustee -eq $sid -or $script:Broad -contains $_.Trustee) -and (Test-AceGrants $_ $cap $res) })
        if ($denied.Count -gt 0) { $conf = 'MEDIUM'; $note = 'explicit Deny present for this right; effective access needs live confirmation' }
        $ot = 'all'; if ($a.ObjectType -ne [guid]::Empty) { $ot = [string]$a.ObjectType }
        $dedupe[$key] = $true
        $found += [pscustomobject]@{ Target=$dn; TargetClass=$t.Class; Trustee=$sid; TrusteeName=$tr.Name; Cap=$cn; Rights=[string]$a.Rights; ObjectType=$ot; Inherited=$a.IsInherited; Confidence=$conf; Via=$via; Note=$note }
      }
    }
  }
  return $found
}

function Find-OwnerExposure {
  param([string[]]$TargetDns)
  $found = @()
  foreach ($dn in $TargetDns) {
    $t = Get-TargetSecurity $dn
    if (-not $t.Ok) { $script:AclReadErrors += $dn; continue }
    $script:Examined = [int]$script:Examined + 1
    $o = $t.Security.GetOwner([System.Security.Principal.SecurityIdentifier])
    if (-not $o) { $script:AclReadErrors += $dn; continue }
    $sid = [string]$o.Value
    if (Test-ExpectedPrincipal $sid) { continue }
    $mem = Get-EffectiveMembers $sid
    if ($mem.IsGroup -and $mem.Members.Count -gt 0 -and @($mem.Members | Where-Object { -not (Test-ExpectedPrincipal $_) }).Count -eq 0) { continue }
    $tr = Resolve-Trustee $sid
    $conf = 'HIGH'; if (-not $tr.Resolved) { $conf = 'LOW' }
    $found += [pscustomobject]@{ Target=$dn; TargetClass=$t.Class; Trustee=$sid; TrusteeName=$tr.Name; Cap='Owner'; Rights='Owner (implicit WriteDacl)'; ObjectType='n/a'; Inherited=$false; Confidence=$conf; Via=''; Note='owner can rewrite the DACL' }
  }
  return $found
}

function Search-Ldap([string]$Base, [string]$Filter, [string]$Prop, [int]$Max = 2000) {
  if ($script:SearchOverride -and $script:SearchOverride.ContainsKey($Filter)) { return @($script:SearchOverride[$Filter]) }
  if ($script:Offline) { return @() }
  $out = @()
  try {
    $s = New-Object System.DirectoryServices.DirectorySearcher((New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Base")))
    $s.Filter = $Filter; $s.PageSize = 500; $s.SizeLimit = 0
    [void]$s.PropertiesToLoad.Add($Prop)
    foreach ($r in $s.FindAll()) {
      if ($out.Count -ge $Max) { $script:Truncated += "$Filter capped at $Max"; break }
      $out += [string]$r.Properties[$Prop.ToLower()][0]
    }
  } catch { $script:AclReadErrors += "search:$Filter" }
  return $out
}

function Get-PrivGroupDns {
  $ctx = Get-AclContext; $d = @()
  foreach ($rid in $script:PrivGroupRids) { $x = Get-DnFromSid "$($ctx.DomainSid)-$rid"; if ($x) { $d += $x } }
  foreach ($s in $script:PrivGroupSids) { $x = Get-DnFromSid $s; if ($x) { $d += $x } }
  return $d
}

function Get-Tier0ObjectDns {
  $ctx = Get-AclContext
  $d = @($ctx.DomainDN, "CN=AdminSDHolder,CN=System,$($ctx.DomainDN)") + @(Get-PrivGroupDns)
  foreach ($s in @("$($ctx.DomainSid)-500", "$($ctx.DomainSid)-502")) { $x = Get-DnFromSid $s; if ($x) { $d += $x } }
  foreach ($gs in @("$($ctx.DomainSid)-512","$($ctx.DomainSid)-519","$($ctx.DomainSid)-518","S-1-5-32-544")) {
    $m = Get-EffectiveMembers $gs
    foreach ($ms in $m.Members) { $x = Get-DnFromSid $ms; if ($x) { $d += $x } }
  }
  $d += Search-Ldap $ctx.DomainDN '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' 'distinguishedName' 200
  return @($d | Select-Object -Unique)
}

function Get-ParentDn([string]$Dn) {
  $i = 0; $esc = $false
  for ($i = 0; $i -lt $Dn.Length; $i++) { $c = $Dn[$i]; if ($esc) { $esc = $false; continue }; if ($c -eq '\') { $esc = $true; continue }; if ($c -eq ',') { return $Dn.Substring($i + 1) } }
  return $null
}

function Resolve-Scope([string]$Scope) {
  if ($Scope.StartsWith('dn:')) { return @($Scope.Substring(3)) }
  return @(& "Scope-$Scope")
}
function Scope-domain-head { return @((Get-AclContext).DomainDN) }
function Scope-adminsdholder { return @("CN=AdminSDHolder,CN=System,$((Get-AclContext).DomainDN)") }
function Scope-privileged-groups { return @(Get-PrivGroupDns | Select-Object -Unique) }
function Scope-tier0-objects { return @(Get-Tier0ObjectDns) }
function Scope-tier0-parents { return @(Get-ParentDnsOfTier0) }
function Scope-partition-heads { $c = Get-AclContext; return @($c.DomainDN, $c.ConfigDN, $c.SchemaDN) }
function Scope-computer-parents { $c = Get-AclContext; return @($c.DomainDN) + @(Search-Ldap $c.DomainDN '(objectClass=organizationalUnit)' 'distinguishedName' 2000) }
function Scope-gpo-objects { $c = Get-AclContext; $b = "CN=Policies,CN=System,$($c.DomainDN)"; return @($b) + @(Search-Ldap $b '(objectClass=groupPolicyContainer)' 'distinguishedName' 2000) }
function Scope-gpo-link-points { $c = Get-AclContext; return @($c.DomainDN, "OU=Domain Controllers,$($c.DomainDN)") + @(Get-ParentDnsOfTier0) }
function Scope-gmsa-objects { $c = Get-AclContext; return @(Search-Ldap $c.DomainDN '(objectClass=msDS-GroupManagedServiceAccount)' 'distinguishedName' 2000) }
function Get-ParentDnsOfTier0 { $dd = (Get-AclContext).DomainDN; $p = @(); foreach ($x in @(Get-Tier0ObjectDns)) { $q = Get-ParentDn $x; if ($q -and ($q -eq $dd -or $q.EndsWith(',' + $dd))) { $p += $q } }; return @($p | Select-Object -Unique) }

function Format-Finding($F) {
  $s = "  TARGET=$($F.Target) | TRUSTEE=$($F.Trustee) ($($F.TrusteeName)) | CAP=$($F.Cap) | RIGHTS=$($F.Rights) | OBJECTTYPE=$($F.ObjectType) | INHERITED=$($F.Inherited) | CONFIDENCE=$($F.Confidence)"
  if ($F.Via) { $s += " | VIA=$($F.Via)" }
  if ($F.Note) { $s += " | NOTE=$($F.Note)" }
  return $s
}

# Runs a plan (list of @{Scope;Caps;Mode;InheritedOnly}) and prints the verdict.
function Invoke-AclStage {
  param([string]$Id, [object[]]$Plan, [string]$PassText, [switch]$PassThru)
  $script:AclReadErrors = @(); $script:Examined = 0; $script:Truncated = @(); $script:NotDeployed = @()
  $findings = @()
  try {
    foreach ($p in $Plan) {
      $dns = @(Resolve-Scope $p.Scope)
      if ($p.Mode -eq 'owner') { $findings += @(Find-OwnerExposure -TargetDns $dns) }
      elseif ($p.InheritedOnly) { $findings += @(Find-CapabilityExposure -TargetDns $dns -CapNames $p.Caps -InheritedOnly) }
      else { $findings += @(Find-CapabilityExposure -TargetDns $dns -CapNames $p.Caps) }
    }
  } catch { $script:AclReadErrors += "fatal:$($_.Exception.Message)" }
  $notes = @(); if ($script:NotDeployed.Count -gt 0) { $notes += ('not deployed: ' + (($script:NotDeployed | Select-Object -Unique) -join '; ')) }
  if ($script:Truncated.Count -gt 0) { $notes += ('scope truncated: ' + (($script:Truncated | Select-Object -Unique) -join '; ')) }
  $errs = @($script:AclReadErrors | Select-Object -Unique)
  $verdict = 'PASS'
  if ($findings.Count -gt 0) { $verdict = 'FAIL' }
  elseif ($errs.Count -gt 0 -and $script:Examined -eq 0) { $verdict = 'SKIP' }
  elseif ($errs.Count -gt 0 -or $script:Truncated.Count -gt 0) { $verdict = 'SKIP' }
  $ntext = $notes -join ' '
  if ($verdict -eq 'PASS') { Write-Output "PASS: $PassText [ACL-$Id]" }
  elseif ($verdict -eq 'SKIP') { Write-Output "SKIP: could not fully evaluate ($($errs.Count) unreadable, examined $($script:Examined)); no exposure proven either way. [ACL-$Id]" }
  else { Write-Output "FAIL: $($findings.Count) exposure(s) across $(@($findings | Select-Object -ExpandProperty Target -Unique).Count) object(s). [ACL-$Id]" }
  Write-Output "  SCOPE: examined=$($script:Examined) unreadable=$($errs.Count) $ntext"
  foreach ($f in $findings) { Write-Output (Format-Finding $f) }
  foreach ($e in ($errs | Select-Object -First 5)) { Write-Output "  UNREADABLE: $e" }
  if ($PassThru) { return [pscustomobject]@{ Verdict=$verdict; Findings=$findings; Notes=$ntext; Errors=$errs } }
}

# Backward search from tier-0 targets: who controls the controllers? Depth-limited, cycle-safe.
function Find-AttackPaths {
  param([string[]]$Tier0Dns, [int]$MaxDepth = 3)
  $ControlCaps = @('GenericAll','WriteDacl','WriteOwner','WriteAllProperties','AddMember','ForceChangePassword','ShadowCredentials','SpnWrite','RbcdWrite')
  $paths = @(); $visited = @{}
  $frontier = @(); foreach ($d in $Tier0Dns) { $frontier += [pscustomobject]@{ Dn=$d; Chain=@(); Conf='HIGH' } }
  for ($depth = 1; $depth -le $MaxDepth; $depth++) {
    $next = @()
    foreach ($node in $frontier) {
      $fs = @(Find-CapabilityExposure -TargetDns @($node.Dn) -CapNames $ControlCaps)
      $fs += @(Find-OwnerExposure -TargetDns @($node.Dn))
      $byKey = @{}
      foreach ($f in $fs) {
        $k = "$($f.Trustee)|$($node.Dn)"
        if (-not $byKey.ContainsKey($k)) { $byKey[$k] = @() }
        $byKey[$k] += $f
      }
      foreach ($k in $byKey.Keys) {
        $grp = $byKey[$k]; $f = $grp[0]
        $caps = (($grp | ForEach-Object { $_.Cap } | Select-Object -Unique) -join '+')
        $conf = $node.Conf; if ($f.Confidence -eq 'LOW' -or ($f.Confidence -eq 'MEDIUM' -and $conf -eq 'HIGH')) { $conf = $f.Confidence }
        $chain = @("$($f.Trustee)--$caps-->$($node.Dn)") + $node.Chain
        $broad = ($script:Broad -contains $f.Trustee)
        $paths += [pscustomobject]@{ Start=$f.Trustee; StartName=$f.TrusteeName; Hops=$depth; Chain=$chain; Confidence=$conf; Broad=$broad }
        if ($visited.ContainsKey($f.Trustee)) { continue }
        $visited[$f.Trustee] = $true
        $dn = Get-DnFromSid $f.Trustee
        if ($dn) { $next += [pscustomobject]@{ Dn=$dn; Chain=$chain; Conf=$conf } }
      }
    }
    $frontier = $next
    if ($frontier.Count -eq 0) { break }
  }
  return $paths
}

function Invoke-PathStage {
  param([string]$Id, [int]$MaxDepth = 3)
  $script:AclReadErrors = @(); $script:Examined = 0; $script:Truncated = @(); $script:NotDeployed = @()
  $paths = @()
  try { $paths = @(Find-AttackPaths -Tier0Dns @(Get-Tier0ObjectDns) -MaxDepth $MaxDepth) } catch { $script:AclReadErrors += "fatal:$($_.Exception.Message)" }
  if ($paths.Count -gt 0) {
    Write-Output "FAIL: $($paths.Count) permission path(s) from non-tier-0 principals to tier-0 objects. [ACL-$Id]"
    foreach ($p in ($paths | Sort-Object Hops | Select-Object -First 200)) { Write-Output "  PATH=$($p.Chain -join ' ; ') | START=$($p.Start) ($($p.StartName)) | HOPS=$($p.Hops) | BROAD=$($p.Broad) | CONFIDENCE=$($p.Confidence)" }
  } elseif ($script:Examined -eq 0 -or @($script:AclReadErrors | Select-Object -Unique).Count -gt 0 -or $script:Truncated.Count -gt 0) {
    Write-Output "SKIP: path analysis incomplete (examined $($script:Examined) object ACLs, $(@($script:AclReadErrors | Select-Object -Unique).Count) unreadable); no path proven absent. [ACL-$Id]"
  }
  else { Write-Output "PASS: no permission path from a non-tier-0 principal to a tier-0 object within $MaxDepth hop(s) ($($script:Examined) object ACLs examined). [ACL-$Id]" }
}
function Get-PrivilegedClosureDns {
  $ctx = Get-AclContext; $set = @{}
  $sids = @(); foreach ($r in $script:PrivGroupRids) { $sids += "$($ctx.DomainSid)-$r" }; $sids += $script:PrivGroupSids
  foreach ($gs in $sids) {
    $g = Get-DnFromSid $gs; if ($g) { $set[$g] = $true }
    $m = Get-EffectiveMembers $gs
    foreach ($ms in $m.Members) { $x = Get-DnFromSid $ms; if ($x) { $set[$x] = $true } }
  }
  foreach ($s in @("$($ctx.DomainSid)-500", "$($ctx.DomainSid)-502")) { $x = Get-DnFromSid $s; if ($x) { $set[$x] = $true } }
  foreach ($dc in (Search-Ldap $ctx.DomainDN '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' 'distinguishedName' 500)) { $set[$dc] = $true }
  return @($set.Keys)
}

# Stage 3: stale protection (adminCount=1 but no longer privileged) is reported separately
# from effective exposure on every adminCount=1 object.
function Invoke-StaleAdminCountStage {
  param([string]$Id, [switch]$PassThru)
  $script:AclReadErrors = @(); $script:Examined = 0; $script:Truncated = @(); $script:NotDeployed = @()
  try { $ctx = Get-AclContext } catch { Write-Output "SKIP: no reachable domain context; no exposure proven either way. [ACL-$Id]"; return }
  $protected = @(Search-Ldap $ctx.DomainDN '(adminCount=1)' 'distinguishedName' 2000)
  $current = @{}; foreach ($d in (Get-PrivilegedClosureDns)) { $current[$d] = $true }
  $stale = @($protected | Where-Object { -not $current.ContainsKey($_) })
  $findings = @()
  if ($protected.Count -gt 0) {
    $findings = @(Find-CapabilityExposure -TargetDns $protected -CapNames @('GenericAll','WriteDacl','WriteOwner','AddMember','ForceChangePassword','ShadowCredentials','WriteAllProperties'))
  }
  $errs = @($script:AclReadErrors | Select-Object -Unique)
  $verdict = 'PASS'
  if ($findings.Count -gt 0) { $verdict = 'FAIL' } elseif ($protected.Count -eq 0 -or $errs.Count -gt 0 -or $script:Truncated.Count -gt 0) { $verdict = 'SKIP' }
  if ($verdict -eq 'PASS') { Write-Output "PASS: no non-tier-0 control over any adminCount=1 object ($($protected.Count) protected, $($stale.Count) stale). [ACL-$Id]" }
  elseif ($verdict -eq 'SKIP') { Write-Output "SKIP: adminCount=1 sweep incomplete (protected=$($protected.Count) unreadable=$($errs.Count)); no exposure proven either way. [ACL-$Id]" }
  else { Write-Output "FAIL: $($findings.Count) effective exposure(s) on adminCount=1 objects; $($stale.Count) object(s) carry stale protection. [ACL-$Id]" }
  Write-Output "  SCOPE: protected=$($protected.Count) stale=$($stale.Count) examined=$($script:Examined) unreadable=$($errs.Count)"
  foreach ($f in $findings) { Write-Output (Format-Finding $f) }
  foreach ($d in ($stale | Select-Object -First 100)) { Write-Output "  STALE=$d (adminCount=1 but not in a privileged group closure; ACL inheritance stays disabled until cleared)" }
  if ($PassThru) { return [pscustomobject]@{ Verdict=$verdict; Findings=$findings; Stale=$stale } }
}

# Stage 16: who can read msDS-ManagedPassword. Readers come from msDS-GroupMSAMembership plus ACEs.
function Get-GmsaReaderSids([string]$Dn) {
  if ($script:GmsaDescOverride -and $script:GmsaDescOverride.ContainsKey($Dn)) { return @($script:GmsaDescOverride[$Dn]) }
  $out = @()
  try {
    # DirectorySearcher returns the security descriptor as byte[]; DirectoryEntry.Properties would hand back a COM object.
    $s = New-Object System.DirectoryServices.DirectorySearcher((New-Object System.DirectoryServices.DirectoryEntry('LDAP://' + $Dn.Replace('/', '\/'))))
    $s.SearchScope = 'Base'; $s.Filter = '(objectClass=*)'
    [void]$s.PropertiesToLoad.Add('msds-groupmsamembership')
    $r = $s.FindOne()
    if ($r -and $r.Properties['msds-groupmsamembership'].Count -gt 0) {
      $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor([byte[]]$r.Properties['msds-groupmsamembership'][0], 0)
      foreach ($a in $sd.DiscretionaryAcl) { if ($a.AceType -eq 'AccessAllowed') { $out += [string]$a.SecurityIdentifier.Value } }
    }
  } catch { $script:AclReadErrors += $Dn }
  return $out
}
# computer / group / user / unknown, from the object's own class
function Get-SidKind([string]$Sid) {
  if ($script:KindOverride -and $script:KindOverride.ContainsKey($Sid)) { return $script:KindOverride[$Sid] }
  $cdn = Get-DnFromSid $Sid
  if (-not $cdn) { return 'unknown' }
  try {
    $oc = @(([ADSI]"LDAP://$($cdn.Replace('/', '\/'))").objectClass)
    if ($oc -contains 'computer') { return 'computer' }
    if ($oc -contains 'group') { return 'group' }
    if ($oc -contains 'user') { return 'user' }
  } catch { }
  return 'unknown'
}
function Invoke-GmsaStage {
  param([string]$Id, [switch]$PassThru)
  $script:AclReadErrors = @(); $script:Examined = 0; $script:Truncated = @(); $script:NotDeployed = @()
  try { $ctx = Get-AclContext } catch { Write-Output "SKIP: no reachable domain context; no exposure proven either way. [ACL-$Id]"; return }
  $gmsas = @(Resolve-Scope 'gmsa-objects')
  $findings = @()
  foreach ($dn in $gmsas) {
    $script:Examined = [int]$script:Examined + 1
    foreach ($sid in (Get-GmsaReaderSids $dn)) {
      $broad = ($script:Broad -contains $sid) -or ($sid.StartsWith($ctx.DomainSid + '-') -and ($sid.EndsWith('-513') -or $sid.EndsWith('-515')))
      $kind = Get-SidKind $sid
      $bad = @(); $why = ''
      if ($broad) { $bad = @($sid); $why = 'broad principal may retrieve the gMSA password' }
      elseif ($kind -eq 'user') { $bad = @($sid); $why = 'user account may retrieve the gMSA password' }
      elseif ($kind -eq 'group') {
        # a group of computers is the normal design: report only if it contains non-computer principals
        $mem = Get-EffectiveMembers $sid
        $bad = @($mem.Members | Where-Object { (Get-SidKind $_) -eq 'user' } | Select-Object -First 5)
        $why = 'group with non-computer members may retrieve the gMSA password'
        if ($mem.Truncated) { $script:Truncated += "gMSA reader group $sid member list truncated" }
      }
      if ($bad.Count -gt 0) {
        $tr = Resolve-Trustee $sid
        $findings += [pscustomobject]@{ Target=$dn; TargetClass='msDS-GroupManagedServiceAccount'; Trustee=$sid; TrusteeName=$tr.Name; Cap='GmsaReader'; Rights='msDS-GroupMSAMembership'; ObjectType='msDS-ManagedPassword'; Inherited=$false; Confidence='HIGH'; Via=($bad -join ','); Note=$why }
      }
    }
  }
  # Who can change the reader list (and so add themselves) is the ACL-level exposure.
  $findings += @(Find-CapabilityExposure -TargetDns $gmsas -CapNames @('GmsaMembershipWrite','GenericAll','WriteDacl','WriteOwner'))
  $errs = @($script:AclReadErrors | Select-Object -Unique)
  $verdict = 'PASS'
  if ($findings.Count -gt 0) { $verdict = 'FAIL' } elseif ($errs.Count -gt 0 -or $script:Truncated.Count -gt 0) { $verdict = 'SKIP' }
  if ($gmsas.Count -eq 0 -and $verdict -eq 'PASS') { Write-Output "PASS: no gMSA objects in the domain (not deployed). [ACL-$Id]" }
  elseif ($verdict -eq 'PASS') { Write-Output "PASS: only computer principals can read msDS-ManagedPassword on $($gmsas.Count) gMSA(s). [ACL-$Id]" }
  elseif ($verdict -eq 'SKIP') { Write-Output "SKIP: gMSA readers could not be fully read ($($errs.Count) unreadable); no exposure proven either way. [ACL-$Id]" }
  else { Write-Output "FAIL: $($findings.Count) gMSA password-read exposure(s). [ACL-$Id]" }
  Write-Output "  SCOPE: gmsa=$($gmsas.Count) unreadable=$($errs.Count)"
  foreach ($f in $findings) { Write-Output (Format-Finding $f) }
  if ($PassThru) { return [pscustomobject]@{ Verdict=$verdict; Findings=$findings } }
}

# ---- end library ----
