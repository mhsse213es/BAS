# Cymulate comparison: what is still missing (2026-10-28)

This re-scores Audspect against four Cymulate CSV exports kept in `reports/`, using the code and QA logs as they are on `main`
today. It replaces the earlier gap list, which was only referenced ("priority 2", "priority 3") in `docs/waf-mastery-qa-log.md`
and `docs/emailgw-mastery-qa-log.md` and was never saved as a document.

## What this covers, and what it does not

- **Covered:** the four areas the exports contain: web application firewall, email gateway, web gateway, data exfiltration (DLP).
- **Not covered:** anything else Cymulate sells that is not in these four files (endpoint security, lateral movement, phishing
  awareness, immediate-threats feeds, cloud, and so on). Nothing here speaks for those areas.
- **What the exports are:** the results of a test run against someone's own environment. Only the catalog shape is used here
  (which attack types, containers, channels and data types were tested, and how many). The pass and block rates describe that
  environment's controls and say nothing about Cymulate's quality or about Audspect, so they are not used as scores.
- **Method:** the exports were aggregated by column. Nothing from them (URLs, addresses, payloads) is copied here.
  Audspect's side comes from the code: `wafcatalog` (counted by running it), `dlpfixture` (counted by running it), the
  scenario files in `scenarios/`, the console catalog in `web/src/features/email.js`, and the QA logs.
- **Not done:** no live run of any Audspect scenario, and no check against Cymulate's current product. Counts are the exports'.
- **Positioning:** `docs/threat-content-factory/README.md` already says not to claim parity with Cymulate or similar tools in
  customer material until measured numbers exist. This document does not change that.

Row counts are not the goal. Cymulate sends tens of thousands of requests and files; Audspect deliberately sends a small set of
safe, reviewed test content (EICAR or benign placeholders only, reserved test domains only, lab-gated CVE checks). A gap below
means a missing kind of test, not a missing number of rows.

## 1. Web application firewall

| | Cymulate export | Audspect now |
|---|---|---|
| Size | 11,103 requests, 8 attack types, 48 sub-categories | 62 vectors in 17 families (`internal/wafcatalog`) |
| Attack types | XSS 7,806; path traversal 1,604; file inclusion 618; command injection 574; SQL injection 294; SSRF 119; NoSQL 53; XML 35 | All eight present, plus LDAP and XPath injection, file upload, HTTP parser discrepancy, API and auth abuse, rate limit, cache, policy misconfiguration |
| Methods | POST 8,941; GET 2,162 | not tracked per vector |
| Platform tag | OS agnostic, Linux, Windows | not tracked per vector |

**Still missing**
1. **Payload depth inside each family.** The families exist, but Cymulate varies the payload a lot: Unix and Windows path
   traversal with encoded payloads (about 990 requests), Unix and Windows command injection, SQL injection by type (error-based,
   blind, passive, Oracle, MSSQL, WAF-bypass), and XSS in polyglot, event-handler, URI and hex-encoded forms. Audspect has 6 XSS
   vectors, 3 SQL injection and 2 path traversal.
2. **Per-request method and platform.** Audspect does not record whether a vector is GET or POST, or Windows or Unix specific.
3. **CVE-specific simulations.** One CVE (Log4Shell) exists in `internal/cvecatalog`, and its live prober is deliberately not
   built (no lab to test it against). This belongs to the earlier "priority 2".

**Closed 2026-10-28 (gap 1, in part):** 25 more vectors for SQL injection (now 10), XSS (12), path traversal (8) and command injection (8), each with a benign twin and a safety deny-list test; see `docs/waf-mastery-qa-log.md` item 12. They are catalog entries graded against fixtures: no request is sent to a real WAF, and they are not yet in a scoring scenario.

**Already closed since the first comparison:** the six missing families (command injection, file inclusion, XXE, NoSQL, LDAP, XPath)
and three XSS variants (commit `8b70131a`); the CVE catalog, verdict contract and lab-execution gate (`fa1756ce`).

## 2. Email gateway

| | Cymulate export | Audspect now |
|---|---|---|
| Size | 14,683 messages, 9 attack types, 2,925 distinct attachment paths | 20 scenarios, EG-001 to EG-020 (console catalog) |
| Attack types | malware 5,380; dummy 3,108; ransomware 1,719; payload 1,717; worm 1,690; true-type 675; links 167; policy 136; exploit 91 | spoofing, impersonation, credential phishing, malicious attachment, payment diversion, outbound DLP, auto-forwarding, post-delivery response, auth exceptions, detection-to-response, QR lure, PDF and Office links, internal spoof, reply-chain hijack, relay bypass, plus four attachment cases (EG-017 to EG-020) |
| Attachment shapes | first file type across 40+ kinds (documents with macros, scripts, executables, databases, slides); chains up to 5 levels deep, such as a document inside a zip inside a zip | four: a script, a double extension, a mismatched file type and a blocked extension, one container level |

**Still missing**
1. **Nested and archive containers.** Zip, Rar, Tar, Cab, Arj, mail-message and calendar attachments, and files nested several levels
   deep, are the largest part of the export (about 13,000 of 14,683 messages have two or more levels). Audspect sends none.
2. **Other script and executable extensions.** The export covers `.bat`, `.scr`, `.pif`, `.wsf`, `.jse`, `.vbe`, `.com`, `.cmd` and
   more. Audspect covers `.js`, `.vbs` and `.exe`.
3. **Office files with macros and other document formats** (macro-enabled Word, Excel and PowerPoint, databases, slide files).
4. **Password-protected archives** in the email path.
5. **Exploit-bearing documents** (CVE-style PDFs). These depend on the same lab-gated CVE work as the WAF item above.
6. **Links and policy cases** as separate batches (the export has 167 and 136 of them).

**Safety constraint:** everything Audspect sends is the EICAR string or benign placeholder text. Adding containers is allowed
under that rule; adding real malware samples is not.

**Already closed:** the attachment-type matrix EG-017 to EG-020 (`b13a4e0c`) and its console entries (`a764bd67`).

**Closed 2026-10-28 (gap 1, 2 and part of 3 above):** EG-021 to EG-025 -- ZIP, three-level nested ZIP, tar.gz, an attached email, and eight more script and executable extensions (`bat`, `scr`, `pif`, `wsf`, `jse`, `vbe`, `com`, `cmd`). Still missing from this list: RAR, 7z, CAB and ARJ containers, password-protected archives, macro-enabled Office files, exploit documents, and links and policy batches. See `docs/emailgw-mastery-qa-log.md` item 22.

## 3. Web gateway

| | Cymulate export | Audspect now |
|---|---|---|
| Size | 28,979 results | 43 categorized destinations (`internal/webgwefficacy`) |
| Types | phishing 22,826; policy 4,036; files 1,345; command-and-control 598; file policy 174 | phishing 3; command-and-control 3; URL filtering 2; safe file download 2 |
| Categories | 154 threat and category labels (adult, sports, social, shopping, news, and so on) | 2 URL-filtering destinations |
| File vectors | about 450 file kinds delivered by download | 2 (`eicar.com`, `sample.txt`) |

**Closed 2026-10-28 (gaps 2 and 3, in part):** 14 more URL-filtering categories and 20 more file downloads (blocked file types, ordinary allowed types, the three EICAR names), 43 destinations in all; see `docs/webgw-mastery-qa-log.md`. Still fixture-only: nothing is sent through a real gateway.

**Still missing**
1. **Endpoint-executed scenario.** The ten destinations are checked only against fixtures; no request is sent from an endpoint
   through a gateway. This needs a lab gateway and is a staging task.
2. **Category breadth.** URL-filtering policy is two destinations against 154 categories in the export.
3. **File-type download matrix**, the web equivalent of the email attachment matrix.
4. **A live or frequently refreshed phishing and command-and-control feed.** Audspect's destinations are fixed reserved test
   domains, so they cannot say whether a gateway blocks *current* threats. This is a deliberate safety choice, and it is also a
   product limit.
5. Known limitation, unchanged: detection is scored Pass whenever any gateway evidence exists, so it is not scored independently.

## 4. Data exfiltration (DLP)

**Channels.** The export has 23 channels; Audspect has scenarios for most of them.

| Cymulate channel | Audspect |
|---|---|
| HTTPS | yes (sink-verified) |
| HTTP | not confirmed as a separate scenario |
| DNS, DNS tunneling | yes |
| E-mail, SFTP, Telnet | yes |
| AWS S3, Azure Blob, Google Storage, OneDrive, Google Drive, Dropbox | yes (cloud-storage, plus Box) |
| GitHub, GitLab | yes |
| Slack, MS Teams | yes (webhooks) |
| Removable device | yes (USB in the multichannel scenario) |
| ICMP tunneling | **no** (deferred earlier) |
| Open ports | **no** |
| Browser HTTP and HTTPS (a browser uploading) | **no** |
| Gmail with append | **no** |

Audspect also has channels the export lacks: AI prompts, database export, clipboard, print and archive staging.

**Data types.** The export has 38 phrase titles in 5 classes (source code, PII, financial, confidential, medical).
`dlpfixture` has 29 fixtures. Not found in Audspect, by searching the fixtures, scenarios and detectors: **JavaScript and
C++ source code, MySQL source code, IPv6 addresses, MAC addresses, "names, addresses and mails" as a PII record, a medical
progress note, and a screenshot or OCR carrier.** Python source code is covered (a step in the HTTPS scenario). Audspect has
other types the export lacks, such as India-specific customer records.

**File carriers.** The export carries data in Word, Excel, PowerPoint, PDF, zip, password-protected zip, OCR images and plain text,
plus 20-odd HTTP content types. Audspect's `dlp-exfiltration-file-carriers` has DOCX, XLSX, PDF, PNG and a password-protected
archive (which reports "operation unknown" without 7-Zip). **Missing: PowerPoint, a plain zip, an OCR text-in-image carrier, and the
range of HTTP content types.**

**Closed 2026-10-28 (gap 2, in part):** `dlp-exfiltration-data-types` adds JavaScript, C++ and MySQL source code, IPv6 addresses, MAC addresses, a names/addresses/e-mail record and a medical progress note; the carriers scenario now also has a PowerPoint and a plain ZIP. Local file operations only, nothing proves a product detects them; see `docs/dlp-mastery-qa-log.md`. Still missing: an OCR text-in-image carrier and the HTTP content types.

**Still missing**
1. The four channels above (ICMP, open ports, browser upload, Gmail append).
2. The nine data types above and the PowerPoint, zip, OCR and content-type carriers.
3. **A live run with DLP enabled.** Everything is verified only as local file operations; no product detection has been shown.
   This is the staging validation, and it is yours to run.

## Ranking

By value to a customer and how safe each is to build here:

1. **Email: nested and archive containers, other script extensions, macro documents** (EICAR or placeholder only). Largest
   gap, fully buildable and testable in this repo. *Done 2026-10-28 for ZIP, nested ZIP, tar.gz, attached email and eight more
   script extensions; RAR/7z/CAB/ARJ, password-protected archives and macro documents remain.*
2. **WAF: payload depth** in SQL injection, path traversal, command injection and XSS, using the existing vector contract. *Done 2026-10-28 (25 vectors); live WAF traffic and scoring-scenario use remain.*
3. **DLP: the nine missing data types and the PowerPoint, zip and OCR carriers.** Small, same pattern as the fixtures already there.
4. **Web gateway: category breadth and a file-type download matrix**, still fixture-only until a lab gateway exists.
5. **DLP: ICMP, browser-upload, open-ports and Gmail-append channels.**
6. **Needs a lab or staging, so not buildable or provable here:** the endpoint web gateway scenario, the live CVE prober, exploit
   documents, and the live DLP and WAF validation run.

## What is not a gap

Several things Audspect has that none of the four exports show: AI-prompt and database-export DLP channels, India-specific data
types, relay-path and reply-chain email cases, and detection-to-response and evidence-completeness checks. Those are Audspect's
own directions and are not part of this comparison.
