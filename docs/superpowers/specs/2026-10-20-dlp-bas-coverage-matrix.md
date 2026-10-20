# DLP BAS — Coverage Matrix (proposed, for review)

Status: **proposal.** It records what the repository covers today, what
is missing, and what each gap needs. It does not claim any control is
verified. Nothing here is a measured product result.

## 1. Verdict vocabulary

Each test reports one of five outcomes. The record keeps the B1 decision
class alongside (see `docs/superpowers/plans/2026-10-20-dlp-record-schema-change-plan.md`):

| Reported outcome | Meaning | Maps to decision class |
|---|---|---|
| Verified | Enforcement confirmed by destination or product evidence | TN (allowed case) / TP (blocked case, needs an authoritative block event) |
| Failed | Policy should have acted, and independent evidence shows it did not | FN / FP |
| Inconclusive | Evidence exists but does not decide the outcome | Inconclusive |
| Unsupported | No verified path or control exists in this environment | Unsupported |
| Not tested | Step did not run, was skipped, or lacked a precondition | Untested |

A simulated transfer by itself is never "Verified". It proves only that
the path was attempted. Enforcement needs evidence that the content reached
or was stopped at the policy point.

## 2. Evidence levels (what each scenario can prove today)

- **L0 — attempt only.** The step ran. Nothing confirms the content moved.
- **L1 — local self-report.** `DLP_OBSERVATION` line from the same host. Not
  independent. Maps to Inconclusive.
- **L2 — destination receipt.** A sink received the payload (sink token
  matched). Proves the data left. Does not prove a product should have blocked it.
- **L3 — authoritative enforcement event.** A DLP or SIEM product event with
  `action = block/allow` correlated to the step. Not yet collected: no
  adapter is verified against a live tenant.

Today nothing reaches L3. Every "verified" claim is gated on item 9 in the QA log.

## 3. Four test families

### 3.1 Endpoint & Device Control

| Area | Covered today | Evidence level | Gap |
|---|---|---|---|
| Printer (incl. print-to-PDF, virtual printers, print-server routing) | `validation`, `multichannel`: default printer via `Out-Printer` | L1 | No print-to-PDF or virtual-printer variant; no print-server routing; no L2/L3 |
| USB / removable media | `validation`, `multichannel`: copy to removable drive | L1 | Needs removable media to run at all (item 7); no read-only or device-exception variants |
| Plug and Play (PnP) | none | — | Device enumeration, new-device authorization. Needs a PnP enumeration step and an enforcement event |
| Device control (allow/deny lists, classes, user/group exceptions, read-only vs blocked) | none | — | Needs a dedicated scenario per device class; needs an agent or product policy to test against |
| Bluetooth (paired devices, storage peripherals) | none | — | Needs a paired device or emulator; the scenario can only attempt, not confirm |
| Clipboard (copy sensitive content, paste into restricted app) | `validation`, `multichannel`: `Set-Clipboard` | L1 | Only copy, no paste into a restricted application |
| Copy/paste (cross-app, browser-to-app, remote session, virtual desktop) | clipboard only | L1 | Remote-session and virtual-desktop transfers not covered |
| Application file access (unauthorized app opens, reads, stages or transmits a file) | none | — | Needs a second application and a restricted-file policy |

### 3.2 Email & Collaboration

| Area | Covered today | Evidence level | Gap |
|---|---|---|---|
| Email: external recipients, personal email, attachments, sensitive content | `smtp`: `Send-MailMessage` to an internal sink address | L2 (sink) | No external-recipient or personal-mail variant; no attachment-vs-body split |
| Email: encryption and exceptions | none | — | Needs an encrypted-mail variant and an exception list to test against |
| Collaboration apps and sync clients (Slack/Teams-compatible, OneDrive-compatible) | `webhook`, `db-export`, `cloud-storage` (sink-compatible) | L2 | Compatible shapes only; no real client |
| Developer tools (CI/CD artifacts, package publish) | `devtools` (added 4c03d378) | L2 | HTTPS imitation only; no git, npm, pip or docker |

### 3.3 Web & Cloud Exfiltration

| Area | Covered today | Evidence level | Gap |
|---|---|---|---|
| Cloud storage (personal drive, unmanaged account, unsanctioned storage) | `cloud-storage`: S3, Azure Blob, Graph, Drive, Dropbox, GCS, Box shapes | L2 | Sink-compatible endpoints only; no unmanaged-account or sanctioned-vs-unsanctioned distinction |
| Web upload (browsers, web forms, webmail, file-sharing sites) | `sink-https` (generic POST), `ai-prompt` (AI-service shape) | L2 | No browser-driven form upload; no webmail or file-sharing shape |
| Application/API channels (SaaS APIs, sync clients) | `webhook`, `coderepo`, `db-export` | L2 | Sink-compatible only |
| Mobile / MTP (phone connections, media transfer, device restrictions) | none. DLP-MOB was not built: no mobile agent (QA item 3) | — | Needs a mobile agent or MDM integration; not buildable here |

### 3.4 Network transfer (includes Network shares and Network communication, added per the 2026-10-20 request)

| Area | Covered today | Evidence level | Gap |
|---|---|---|---|
| Network shares: copy to SMB/CIFS, NFS, mapped drives, NAS | `validation`: copy to a local "shared path" only, not a real share | L1 | No real SMB or NFS destination; no read/write-restriction or share-exception variant |
| Network shares: unauthorized share access | none | — | Needs a share with a restricted ACL |
| Network communication: HTTP/S | `sink-https`, `webhook`, `cloud-storage` | L2 | Covered for the sink; no proxy or TLS-inspection path |
| Network communication: DNS | `dns-tunnel` (4 steps) | L2 | Covered for the sink |
| Network communication: FTP/SFTP | `sftp`, `db-export` | L2 | Covered for the sink; no plain FTP |
| Network communication: SMTP | `smtp` | L2 | As in email |
| Network communication: raw TCP, WebSockets, other protocols | `telnet` (raw TCP-like session over HTTPS) | L2 | No raw TCP sink, no WebSocket |
| Lateral data movement (endpoint to endpoint, internal server, shared storage) | none | — | Needs a second internal host; this is the largest gap in the matrix |
| Network discovery and destination access | none | — | Access control, not DLP content inspection. Keep it out of DLP verdicts; put it in a separate network-access scope |

### 3.5 Cross-cutting: Archives and file transformations

| Area | Covered today | Evidence level | Gap |
|---|---|---|---|
| ZIP / nested archives, renamed extensions, encrypted files, OCR | `validation`, `multichannel`: ZIP creation only, no outbound transfer | L1 (local) | Transfer of the archive is not tested. No nested, renamed, encrypted or OCR variant |

## 4. The distinction the matrix enforces

- **Simulating a transfer path is not testing the product.** A step that
  POSTs to a sink proves the path is open from this host. It does not prove a
  DLP product should have stopped it, or that it did.
- **A file copy alone is not a DLP failure.** A failure needs evidence that
  sensitive content moved and that the applicable policy should have blocked,
  warned or audited the action.
- **Network-access control is not DLP.** Discovery and destination reachability
  belong in a separate scope so they are not scored as content-inspection results.

## 5. Gap summary

- **Most of the matrix stays at L1 or L2.** Only sink-backed rows reach L2.
  Nothing reaches L3 until an adapter is verified against a live tenant.
- **Largest missing areas:** lateral data movement, real network shares,
  device control and PnP, Bluetooth, application file access, MTP.
- **Needs hardware or a product, not just a scenario:** removable media (item 7),
  Bluetooth peripherals, mobile/MTP (no agent), device-control policies, and any
  endpoint DLP agent to enforce against.

## 6. Proposed build order (for approval)

1. **Network shares** (dedicated scenario): copy to a real SMB share on a lab
   host, then a read-only share variant. L1 first, L2 if the share writes to a
   sink-backed collector. Reuses the existing sink conventions.
2. **Lateral data movement** (dedicated scenario): endpoint to second-host copy
   over the share, recording which host originated and which received. Needs a
   second lab host.
3. **Email variants**: external recipient and personal-address variants of
   `smtp`, with an encrypted-mail case. Sink-backed, so buildable now.
4. **Archive transfer**: archive then transfer the ZIP over the existing
   channels, plus a renamed-extension variant. Sink-backed, so buildable now.
5. **Web upload**: browser-form shape of the HTTPS sink. Buildable, but
   simulates the form rather than driving a browser.
6. **Device control, PnP, Bluetooth, MTP, application file access**: each
   needs a device, a policy or a host that the lab does not have. Record as
   Unsupported in this environment until one exists.

Items 3 and 4 are buildable without new infrastructure. Items 1 and 2 need
a lab SMB share and a second host, so they wait on those.

## 7. Status update, 2026-10-20 (supersedes the gap cells above where they conflict)

Sections 3.1 to 3.5 are the proposal as it was written. The rows below record what is now built, and what is still open and why. A built scenario is coded and signed, but has not been run. Its QA item is in `docs/dlp-mastery-qa-log.md`.

### 7.1 Built since the proposal

| Row | Scenario | Evidence | Operator input |
|---|---|---|---|
| PnP | `dlp-exfiltration-pnp` | L1 | `BAS_DLP_PNP_DRIVE_LETTER` |
| Bluetooth (storage only) | `dlp-exfiltration-bluetooth` | L1 | `BAS_DLP_BT_STORAGE_PATH` |
| Device control | `dlp-exfiltration-device-control` | L1 | `BAS_DLP_DEVICE_CLASS_GUID` (read only) |
| MTP | `dlp-exfiltration-mtp` | L1 (no block possible) | `BAS_DLP_MTP_DEVICE_NAME` |
| Application file access | `dlp-exfiltration-app-file-access` | L1 | `BAS_DLP_RESTRICTED_DIR` |
| Network shares (writable and read-only) | `dlp-exfiltration-network-share` | L1 | `BAS_DLP_SMB_SHARE`, `BAS_DLP_SMB_RO_SHARE` |
| Lateral data movement | `dlp-exfiltration-lateral-movement` | L1 | `BAS_DLP_LATERAL_SERVER_SHARE`, `BAS_DLP_LATERAL_PEER_SHARE` |
| Web upload and form (request shape) | `dlp-exfiltration-web-upload` | L2 | none (sink) |
| Email external and personal recipients | `dlp-exfiltration-email-recipients` | L2 | none (sink) |
| Archive: encrypted blob | `dlp-exfiltration-archive-encrypted` | L2 | none (sink) |

Section 3.1 "Application file access" and 3.4 "Network shares" are now covered at L1 by the operator-gated scenarios above. Section 3.4 "Lateral data movement" is no longer the largest gap, because a scenario exists. It is still unrun.

### 7.2 Still open, and why each is not built

| Row | Why it is not built here |
|---|---|
| Print-to-PDF | Microsoft Print to PDF opens a Save As dialog. That blocks a non-interactive agent. It needs a headless PDF printer, or a GUI run that is outside this repository. |
| Virtual printers and print-server routing | Needs a print server. None is provisioned. |
| Remote session and virtual desktop copy | Needs an RDP or VDI session. Not provisioned. |
| Raw TCP and WebSocket | The HTTPS sink decodes JSON only. A raw TCP or WebSocket receiver is a listener change and a product decision. |
| Browser-driven forms, multipart or urlencoded | Same sink limit as the web-upload row. Recorded as QA item 19. |
| Email attachments, encrypted mail, multiple recipients | The SMTP listener rejects multipart and multi-recipient messages. A receipt cannot be produced for these. |
| Password-protected ZIP | PowerShell cannot create one. It needs 7-Zip, which the repository does not provision. |
| OCR | Needs an image rendering path that the scenarios do not have. |
| Restricted-ACL share, real NFS or NAS | Needs lab shares. The operator-gated scenarios cover the path once those are set. |
| Device exceptions, user and group variants | Need a device policy and several accounts. |
| Mobile agent (DLP-MOB) | No mobile agent exists (QA item 3). |
| Network discovery | Out of DLP scope by section 4. Keep it in a separate access-control scope. |

### 7.3 Remaining real work, once the lab is available

Run each QA item from the open list. The scenarios cannot be verified until they run against the lab sink or lab hardware.
