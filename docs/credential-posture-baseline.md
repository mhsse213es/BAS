# Windows credential posture baseline

The scenario `scenarios/windows-credential-protection-posture.yaml` reads an organizational
baseline from:

    C:\ProgramData\Audspect\posture-baseline.json

The scenario never creates this file. Without it, the checks that need a decision report
NOT_ASSESSED (SKIP). They never report PASS on enumeration alone.

## File format

A single JSON object. Unknown keys are an error, so a misspelled key cannot silently disable
a check.

```json
{
  "admin_allowlist": ["S-1-5-21-1111111111-2222222222-3333333333-500"],
  "min_password_length": 14,
  "max_lockout_threshold": 10,
  "max_password_age_days": 90
}
```

Every key is optional. A missing key makes only its own check NOT_ASSESSED.

| Key | Type | Valid values | Meaning | Used by |
|---|---|---|---|---|
| `admin_allowlist` | array of strings | one or more SIDs, each matching `S-1-...` | The only principals allowed as direct members of the local Administrators group. Matched by SID, never by display name. | Local Administrators check |
| `min_password_length` | integer | 1 to 128 | The minimum acceptable `MinimumPasswordLength`. The observed value must be greater than or equal to this. | Minimum password length check |
| `max_lockout_threshold` | integer | 1 to 999 | The highest acceptable `LockoutBadCount`. The observed value must be 1 up to this number. A value of 0 means accounts never lock, so it FAILs. | Lockout threshold check |
| `max_password_age_days` | integer | 1 to 999 | The longest acceptable `MaximumPasswordAge`. The observed value must be 1 up to this number. A value of 0 means passwords never expire, so it FAILs. A negative observed value is reported as unexpected and FAILs. | Maximum password age check |

Use SIDs for `admin_allowlist`. Find a SID with:

    Get-LocalUser -Name Administrator | Select-Object Name, SID
    Get-LocalGroupMember -Group Administrators | Select-Object Name, SID

## How the file is validated

| State | Result of the baseline checks |
|---|---|
| File absent | SKIP (NOT_ASSESSED). The reason names the missing file. |
| File present, key absent | SKIP (NOT_ASSESSED) for that key's check only. |
| File present, invalid | ERROR for every baseline check. Nothing falls back to a default. |

A file is invalid when any of these is true:

- It is not valid JSON, or its root is not an object.
- It contains a key outside the four above.
- `admin_allowlist` is not a non-empty array, or an entry is not a SID.
- A threshold is not an integer, is null, or is outside its range.
- The file, or the folder `C:\ProgramData\Audspect`, grants write, append, delete, permission change or take-ownership to Everyone (S-1-1-0), Authenticated Users (S-1-5-11) or Users (S-1-5-32-545).

## Protecting the file

The scenario reads the file. It does not check that only administrators wrote it, so the
scenario enforces this by refusing a file or folder writable by broad principals. Set the
ACL on the folder and the file to Administrators and SYSTEM:

    $dir = 'C:\ProgramData\Audspect'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    icacls $dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'
    icacls "$dir\posture-baseline.json" /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F'

Run this from an elevated PowerShell session. Changing the file later requires the same
elevation.

## Audit subcategory checks

The audit checks read the numeric setting value of each subcategory by its GUID, using
`auditpol /backup`. The GUID and the value do not depend on the Windows display language.

| Subcategory | GUID | Passes when |
|---|---|---|
| Special Logon | {0CCE921B-69AE-11D9-BED3-505054503030} | success is audited (value has bit 1) |
| User Account Management | {0CCE9235-69AE-11D9-BED3-505054503030} | success is audited (value has bit 1) |
| Credential Validation | {0CCE923F-69AE-11D9-BED3-505054503030} | success or failure is audited (value has bit 1 or 2) |

`auditpol /backup` needs an elevated session. Without it, the check reports SKIP.

## Limits

- Nested group membership is not expanded. The administrator check does not prove complete
  administrator membership. Expansion is a future enhancement, and it must report unreachable
  domain controllers and unresolved groups as ERROR or SKIP, never as compliant.
- Credential-theft checks belong to Endpoint Mastery 04 and are not repeated here.
