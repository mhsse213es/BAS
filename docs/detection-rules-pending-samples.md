# Detection rules awaiting schema samples

72 of 2104 rules have neither a field-mapped nor a keyword translation. They are left generic on purpose: a guessed field name produces a query that looks right and never matches. Each row says why it is blocked and what one redacted sample would settle. Remove usernames, IP addresses, tenant IDs and tokens before sharing.

A mapping built from a sample is checked with a positive and a negative event before its `verification` becomes `validated`.

| Group | Rules | Why blocked | What to send |
|---|---:|---|---|
| `github/audit` | 8 | No Sentinel table, Splunk sourcetype or Elastic dataset for GitHub audit events could be confirmed from vendor documentation. | Which collector ships GitHub audit logs to your SIEM, and one redacted audit event (the `action` and `actor` keys). |
| `windows/file_access` | 7 | Needs the audit event the rule was written against (4663 object access) and its enabled auditing. | Confirm Object Access auditing is on, and one redacted 4663 event. |
| `azure/pim` | 7 | PIM alert incidents (`invalidLicenseAlertIncident` ...) are not in `AuditLogs` or `AADUserRiskEvents`. | The table or export where your tenant records PIM alerts, and one redacted alert. |
| `rpc_firewall/application` | 6 | RPC Firewall's events carry `EventLog` / `InterfaceUuid`; no collector mapping confirmed. | One redacted RPC Firewall event as it appears in your SIEM. |
| `azure/signinlogs` | 6 | Remaining rules use nested or ambiguous fields (`properties.message`, `DeviceDetail.trusttype`, `ActivityDetails`, `Count`). | One redacted successful and one failed Entra sign-in event as stored in `SigninLogs`, plus how the table is ingested. |
| `azure/auditlogs` | 5 | Rules use nested `TargetResources.modifiedProperties` and fields the `AuditLogs` table does not have. | One redacted `AuditLogs` row for a certificate or consent change, including the TargetResources column. |
| `m365/threat_management` | 5 | The rules use `eventSource` / `eventName` / `status`, which no confirmed Microsoft 365 table carries. | Where these events are stored in your tenant and one redacted event. |
| `linux/file_event` | 4 | Needs the Sysmon for Linux collector's field names. | Which collector ships Sysmon for Linux and one redacted file-create event. |
| `azure/activitylogs` | 4 | Rules use `properties.message` or other products' field names (`eventSource`, `Operation`). | One redacted `AzureActivity` row for an application or MFA-policy change. |
| `fortigate/event` | 4 | Splunk's FortiGate add-on maps a raw `action` field that collides with the CIM `action` (documented in the add-on's community threads), so a mapping here could silently match the wrong events. `cfgpath` is unconfirmed. | One redacted FortiGate event log line (type=event) and the SIEM sourcetype or dataset it lands in. |
| `windows/iis-configuration` | 4 | The stock Windows pipelines do not know the IIS-Configuration channel. | Confirm that channel is collected and which sourcetype / dataset carries it. |
| `m365/audit` | 2 | `RequestType` and `Directionality` are not `OfficeActivity` columns. | One redacted event of each kind from `OfficeActivity` (or the Splunk `o365:management:activity` event). |
| `linux/network_connection` | 2 | Needs the Sysmon for Linux collector's field names. | One redacted Sysmon for Linux network-connect event. |
| `windows` | 1 | A one-off source with fields or an event shape not confirmed from vendor documentation. | One redacted event from the source and the collector / sourcetype / table it lands in. |
| `windows/ldap` | 1 | A one-off source with fields or an event shape not confirmed from vendor documentation. | One redacted event from the source and the collector / sourcetype / table it lands in. |
| `zeek/kerberos` | 1 | A one-off source with fields or an event shape not confirmed from vendor documentation. | One redacted event from the source and the collector / sourcetype / table it lands in. |
| `gcp/gcp.audit` | 1 | A one-off source with fields or an event shape not confirmed from vendor documentation. | One redacted event from the source and the collector / sourcetype / table it lands in. |
| `windows/smbserver-connectivity` | 1 | A one-off source with fields or an event shape not confirmed from vendor documentation. | One redacted event from the source and the collector / sourcetype / table it lands in. |
| `windows/file_rename` | 1 | A one-off source with fields or an event shape not confirmed from vendor documentation. | One redacted event from the source and the collector / sourcetype / table it lands in. |
| `gcp/google_workspace.login` | 1 | A one-off source with fields or an event shape not confirmed from vendor documentation. | One redacted event from the source and the collector / sourcetype / table it lands in. |
| `proxy` | 1 | A one-off source with fields or an event shape not confirmed from vendor documentation. | One redacted event from the source and the collector / sourcetype / table it lands in. |

## Rules by group

### `github/audit` (8)

- GitHub Repository Pages Site Changed to Public
- Github Fork Private Repositories Setting Enabled/Cleared
- Github High Risk Configuration Disabled
- Github Push Protection Bypass Detected
- Github Push Protection Disabled
- Github Repository/Organization Transferred
- Github Secret Scanning Feature Disabled
- Github Self Hosted Runner Changes Detected

### `windows/file_access` (7)

- Access To Crypto Currency Wallets By Uncommon Applications
- Access To Potentially Sensitive Sysvol Files By Uncommon Applications
- Access To Windows Credential History File By Uncommon Applications
- Access To Windows DPAPI Master Keys By Uncommon Applications
- Credential Manager Access By Uncommon Applications
- Microsoft Teams Sensitive File Access By Uncommon Applications
- Suspicious File Access to Browser Credential Storage

### `azure/pim` (7)

- Invalid PIM License
- Roles Activated Too Frequently
- Roles Activation Doesn't Require MFA
- Roles Are Not Being Used
- Roles Assigned Outside PIM
- Stale Accounts In A Privileged Role
- Too Many Global Admins

### `rpc_firewall/application` (6)

- Remote DCOM/WMI Lateral Movement
- Remote Schedule Task Lateral Movement via ATSvc
- Remote Schedule Task Lateral Movement via ITaskSchedulerService
- Remote Schedule Task Lateral Movement via SASec
- Remote Server Service Abuse for Lateral Movement
- SharpHound Recon Account Discovery

### `azure/signinlogs` (6)

- Application Using Device Code Authentication Flow
- Applications That Are Using ROPC Authentication Flow
- Increased Failed Authentications Of Any Type
- Measurable Increase Of Successful Authentications
- Suspicious SignIns From A Non Registered Device
- Use of Legacy Authentication Protocols

### `azure/auditlogs` (5)

- Account Created And Deleted Within A Close Time Frame
- Certificate-Based Authentication Enabled
- End User Consent
- End User Consent Blocked
- New Root Certificate Authority Added

### `m365/threat_management` (5)

- Logon from a Risky IP Address
- Microsoft 365 - Impossible Travel Activity
- Microsoft 365 - Potential Ransomware Activity
- Microsoft 365 - Unusual Volume of File Deletion
- Suspicious Inbox Forwarding

### `linux/file_event` (4)

- Linux Doas Conf File Creation
- Persistence Via Sudoers.d Files
- Suspicious Filename with Embedded Base64 Commands
- Wget Creating Files in Tmp Directory

### `azure/activitylogs` (4)

- Azure Application Deleted
- Azure Device or Configuration Modified or Deleted
- Disabled MFA to Bypass Authentication Mechanisms
- User Added to an Administrator's Azure AD Role

### `fortigate/event` (4)

- FortiGate - Firewall Address Object Added
- FortiGate - New Administrator Account Created
- FortiGate - New Firewall Policy Added
- FortiGate - New Local User Created

### `windows/iis-configuration` (4)

- ETW Logging/Processing Option Disabled On IIS Server
- HTTP Logging Disabled On IIS Server
- New Module Module Added To IIS Server
- Previously Installed IIS Module Was Removed

### `m365/audit` (2)

- Azure Login Bypassing Conditional Access Policies
- Suspicious Email Delivered In Microsoft 365

### `linux/network_connection` (2)

- Communication To LocaltoNet Tunneling Service Initiated - Linux
- Communication To Ngrok Tunneling Service - Linux

### `windows` (1)

- Mimikatz Use

### `windows/ldap` (1)

- Potential Active Directory Reconnaissance/Enumeration Via LDAP

### `zeek/kerberos` (1)

- Kerberos Network Traffic RC4 Ticket Encryption

### `gcp/gcp.audit` (1)

- GCP Break-glass Container Workload Deployed

### `windows/smbserver-connectivity` (1)

- Unsigned or Unencrypted SMB Connection to Share Established

### `windows/file_rename` (1)

- Suspicious Appended Extension

### `gcp/google_workspace.login` (1)

- Google Workspace Government Attack Warning

### `proxy` (1)

- HackTool - CobaltStrike Malleable Profile Patterns - Proxy
