<#
 LAB ONLY. NOT RUN. This script WRITES to Active Directory; the audit scenario never does.
 Seeds a known set of risky ACEs so each stage of acl-privilege-exposure-audit can be shown
 to catch what it should, and removes them again. Run only in a disposable lab domain.
   $env:BAS_CONFIRM_LAB_AD = 'true'
   .\acl-canary.ps1 -Mode Seed      # create objects + ACEs
   .\acl-canary.ps1 -Mode Remove    # delete everything this script created
 Needs the ActiveDirectory module and Domain Admin in the lab.
 Note: stand-in tier-0 objects are protected (AdminSDHolder); SDProp resets their ACLs within ~60 min,
 so run the scenario right after Seed, or trigger SDProp manually and re-seed.

 Expected result after Seed (run the scenario as an ordinary domain user):
   Stage 6  GenericAll        FAIL  trustee BAS-Canary-Low on BAS-Canary-T0
   Stage 8  AddMember         FAIL  trustee BAS-Canary-Low on BAS-Canary-T0-Group
   Stage 9  Ownership         FAIL  owner BAS-Canary-Low on BAS-Canary-T0-Group
   Stage 12 ShadowCreds       FAIL  trustee BAS-Canary-Low on BAS-Canary-T0
   Stage 13 SPN               FAIL  trustee BAS-Canary-Low on BAS-Canary-T0
   Stage 22 Correlation       FAIL  path BAS-Canary-Low -> BAS-Canary-Mid -> BAS-Canary-T0-Group (2 hops)
 Negative controls (must NOT appear): BAS-Canary-Benign has only ReadProperty on BAS-Canary-T0.
#>
param([ValidateSet('Seed','Remove')][string]$Mode = 'Seed')
if ($env:BAS_CONFIRM_LAB_AD -ne 'true') { throw 'Refusing to run: set BAS_CONFIRM_LAB_AD=true in a lab domain.' }
Import-Module ActiveDirectory
$dn = (Get-ADDomain).DistinguishedName
$ou = "OU=BAS-ACL-Canary,$dn"
function Add-Ace($Target, $Trustee, $Rights, $ObjectType) {
  $acl = Get-Acl "AD:$Target"
  $sid = (Get-ADObject -Identity $Trustee -Properties objectSid).objectSid
  if ($ObjectType) { $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, $Rights, 'Allow', [guid]$ObjectType) }
  else { $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, $Rights, 'Allow') }
  $acl.AddAccessRule($rule); Set-Acl "AD:$Target" $acl
}
if ($Mode -eq 'Seed') {
  New-ADOrganizationalUnit -Name 'BAS-ACL-Canary' -Path $dn -ProtectedFromAccidentalDeletion $false
  $pw = ConvertTo-SecureString ([guid]::NewGuid().ToString() + 'aA1!') -AsPlainText -Force
  foreach ($n in 'BAS-Canary-Low','BAS-Canary-Benign','BAS-Canary-T0') { New-ADUser -Name $n -Path $ou -AccountPassword $pw -Enabled $true }
  New-ADGroup -Name 'BAS-Canary-Mid' -GroupScope Global -Path $ou
  New-ADGroup -Name 'BAS-Canary-T0-Group' -GroupScope Global -Path $ou
  # Stand-in tier-0: membership of a lab-only privileged group makes the audit treat these as tier-0.
  Add-ADGroupMember -Identity 'Account Operators' -Members 'BAS-Canary-T0','BAS-Canary-T0-Group'
  $t0 = "CN=BAS-Canary-T0,$ou"; $t0g = "CN=BAS-Canary-T0-Group,$ou"
  $low = "CN=BAS-Canary-Low,$ou"; $mid = "CN=BAS-Canary-Mid,$ou"; $ben = "CN=BAS-Canary-Benign,$ou"
  Add-Ace $t0 $low 'GenericAll' $null
  Add-Ace $t0 $ben 'ReadProperty' $null
  Add-Ace $t0g $low 'WriteProperty' 'bf9679c0-0de6-11d0-a285-00aa003049e2'
  Add-Ace $t0g $mid 'GenericAll' $null
  Add-ADGroupMember -Identity $mid -Members $low
  Write-Output 'Seeded. Run the scenario now, then -Mode Remove.'
} else {
  Remove-ADGroupMember -Identity 'Account Operators' -Members 'BAS-Canary-T0','BAS-Canary-T0-Group' -Confirm:$false
  Remove-ADOrganizationalUnit -Identity $ou -Recursive -Confirm:$false
  Write-Output 'Removed.'
}
