# RBI 2026 directions: mapping review

Reviewed 2026-11-16. Covers `orchestrator/internal/compliance/mappings/rbi_csf.yaml`.

## What was reviewed, and from what

The instrument is the Reserve Bank of India (Commercial Banks – Cybersecurity, Technology: Risk, Resilience and Assurance
Framework) Directions, 2026: RBI/DoS/2026-27/410, DoS.CO.CSITEG.4/31.01.015/2026-27, dated 31 July 2026. RBI's page shows
a version "updated as on 1 October 2026".

- **Source of the text:** a copy at `lexsite.com/eDocs/RBI-DoS-410.pdf` (56 pages, text layer present). The PDF on
  `rbidocs.rbi.org.in` is behind a CAPTCHA, which was not bypassed.
- **Why the copy is trusted:** its title, reference number and date match RBI's notification page, and every paragraph
  that page reproduces (1 to 52) and every paragraph number it cites agrees with the copy (para 49 data dictionary, 120
  DMARC, 151 VA/PT cadence, 165 half-yearly DR drills, 182 six-hour reporting, 230 repeal).
- **Not done:** a page-by-page comparison of the copy against the RBI-hosted PDF. Someone with a browser can download
  that PDF and spot-check the paragraphs cited below.

## What the Directions say about their own scope

- Commercial banks only. Small finance banks, payments banks and local area banks are excluded (paras 3–4). Foreign bank
  branches follow a comply-or-explain approach for some paragraphs (para 4).
- Effective on issuance, 31 July 2026. No phase-in for the technical controls appears in the text (para 231 is a saving
  clause only).
- Para 230 repeals "the existing Directions, instructions, and guidelines relating to Cybersecurity Framework and IT
  Governance as applicable to Commercial Banks … as communicated vide circular no. DoS.CO.PPG.66/11.01.005/2026-27 dated
  July 31, 2026". The 2016 "Cyber Security Framework in Banks" circular (RBI/2015-16/418) is **not named** in the
  Directions. Its repeal rests on that other circular, which was not read.
- No dedicated cloud-security section exists. An earlier note claimed the Directions add one; the text does not support it.

## Result: what was wrong and what changed

The control statements were checked one by one. Thirteen of the 25 named a number, algorithm, product or mechanism the
Directions do not state. They now say what the Directions say, and each cites its paragraph.

| Control | Before | The Directions say | Now cites |
|---|---|---|---|
| EPT-02 | critical patches in 30 days, zero-days in 7 | patches applied "expeditiously" / "in a timely manner", risk-based; no day counts | ¶58, ¶98–100 |
| MON-03 | logs retained 180 days | scope, frequency and storage of log collection set with stakeholders; no retention period | ¶93–97 |
| DAT-01 | encrypted at rest (AES-256) | strong, non-deprecated algorithms and standards; encryption "if supported" | ¶50, ¶106, ¶140 |
| DAT-02 | TLS 1.2+ | VPN or other secure protocols; strong, non-deprecated ciphers | ¶106, ¶140 |
| APP-01 | SAST/DAST, code review for critical apps | secure coding, threat modelling, security testing; source code audit is "may consider" | ¶79–86, ¶91 |
| APP-02 | WAF before all internet-facing apps | no WAF requirement; application security assessment and VA/PT of internet-facing apps | ¶84–86, ¶150 |
| NET-01 | network segmentation | authorised access and devices only, unauthorised connections blocked; segmentation is not named | ¶68, ¶73–74, ¶103 |
| NET-03 | VPN with MFA, session recording | secure access (VPN or other secure protocols); MFA for teleworking access to critical systems; elevated access logged | ¶106, ¶114 |
| IAM-02 | MFA for all privileged and remote access | risk-based; mandatory MFA for privileged users of critical systems | ¶110, ¶114 |
| IAM-04 | secure storage and rotation | protect credentials and tokens against leakage and attack; rotation not stated | ¶107 |
| EPT-04 | only authorised software may run | inventory of authorised software; whitelisting "may" be implemented | ¶56–57 |
| BCP-01 | immutable offline backups | back up, restore periodically to test usability, preserve integrity, meet RTO/RPO | ¶169–171 |
| INC-02 | IR plan tested annually | policy, drills, crisis plan; six-hour reporting on DAKSH is stated | ¶175, ¶182, ¶188–193 |

Supported as written, now with references: IAM-01 (¶105, ¶111), IAM-03 (¶104–105, ¶108–109), NET-02 (¶77), NET-04
(¶75, ¶77), EPT-01 (¶144–145), EPT-03 (¶117–119, ¶144), DAT-03 (¶51–52), DAT-04 (¶48), MON-01 (¶143, ¶215), MON-02
(¶77), INC-01 (¶75, ¶215), BCP-02 (¶165–167).

## What this review does not establish

- **The ATT&CK technique links are Audspect's own judgement.** RBI publishes no such mapping, so none can be "verified
  against" it. A control resisting the techniques executed is evidence about that control, not that the bank meets a
  paragraph.
- **Coverage of the Directions is partial.** These areas have no control yet: third-party arrangements (¶126–139),
  customer authentication (¶115–116), removable media (¶121–125), secure configuration (¶66–67), vendor source code and
  certification (¶90–92), straight-through processing (¶141–142), anti-phishing services (¶148), VA/PT governance
  (¶149–161), and the governance, CSOC and information-systems-audit chapters (II–IV, VI, VII).
- **The text is a copy.** See above.
- **The 1 October 2026 amendment** (a footnote shows a provision substituted by the Governance Amendment Directions)
  appears to affect para 8 only; the other amended paragraphs, if any, were not identified.

The product keeps a note on RBI results saying this, in place of the earlier "not verified" warning.
