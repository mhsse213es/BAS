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
