# Cymulate comparison: every known gap in Audspect

Companion to `docs/cymulate-comparison-gap-analysis.md` (stale rows corrected 2026-11-11). This file lists only what we lack. Counts and reasoning are in the doc.

Status of each item as of 2026-11-11: **buildable here** = can be done in this repo with fixtures; **needs lab/staging** = needs a live gateway, WAF, or DLP product to prove.

## 1. Web application firewall

| # | Gap | Status |
|---|---|---|
| W1 | Command injection payload depth. Cymulate's failures concentrate here (517 of 574 got through, 90%). Highest-value WAF gap. | buildable here |
| W2 | Path traversal with encoded payloads, Unix and Windows variants | buildable here |
| W3 | SQL injection by type: error-based, blind, passive, Oracle, MSSQL, WAF-bypass forms (only a few exist) | buildable here |
| W4 | XSS forms: polyglot, event-handler, URI, hex-encoded (only a few exist) | buildable here |
| W5 | No Log4Shell / JNDI vectors at all in `wafcatalog` (Cymulate sent 16) | buildable here (payload); live prober needs lab |
| W6 | CVE-specific live prober (`internal/cvecatalog`) deliberately not built, no lab to test against | needs lab/staging |
| W7 | Request method (GET/POST) and platform (Windows/Unix) not recorded per vector | buildable here |
| W8 | Vectors are catalog entries graded against fixtures; none sent to a real WAF | needs lab/staging |
| W9 | Vectors not yet used in a scoring scenario | buildable here |

## 2. Email gateway

| # | Gap | Status |
|---|---|---|
| E1 | Container nesting: deepest is three levels; Cymulate goes to about five | buildable here |
| E2 | RAR and ARJ containers missing (no free writer available) | blocked on tooling |
| E3 | Exploit-bearing documents (CVE-style PDFs / Office files) | needs lab (lab-gated CVE work) |
| E4 | Links batch: all link tests use reserved `.test` lab hosts, not real malicious URLs | deliberate safety choice; needs a feed decision |
| E5 | Policy batch as its own set (Cymulate's 136 policy cases) | buildable here |
| E6 | Attachment-type breadth: Cymulate uses 40+ kinds and about 270 final file types; we cover a few dozen types | buildable here (EICAR/placeholder only) |
| E7 | Macro-enabled Office files are type-policy only; no macro content is sent (deliberate) | deliberate; cannot test macro execution |
| E8 | Real malware-family behaviour not represented (placeholders only, deliberate) | deliberate |
| E9 | No live run of the email scenarios against a real gateway | needs lab/staging |

## 3. Web gateway

| # | Gap | Status |
|---|---|---|
| G1 | Endpoint-executed scenario: requests are not sent from an endpoint through a gateway | needs lab/staging |
| G2 | URL-filter category breadth: Cymulate uses about 154 labels; we have 43 destinations in total, few of them category-specific | buildable here |
| G3 | File-type download matrix: Cymulate has about 450 file kinds; we have about 22 | buildable here |
| G4 | No live or refreshed phishing / C2 feed. Destinations are fixed reserved test domains, so we cannot say whether a gateway blocks current threats. Product limit, not just a test gap | design decision (feed) |
| G5 | Scoring limitation: detection scores Pass whenever any gateway evidence exists, so it is not scored independently | buildable here (scoring change) |
| G6 | Nothing is sent through a real gateway | needs lab/staging |

## 4. Data exfiltration (DLP)

**Channels**

| # | Gap | Status |
|---|---|---|
| D1 | ICMP tunnelling (needs raw sockets; deferred) | needs design (raw sockets) |
| D2 | Open-port egress test (needs new listeners) | needs design (new listeners) |
| D3 | Gmail-append channel (needs new listener) | needs design (new listener) |

**Data types and carriers**

| # | Gap | Status |
|---|---|---|
| D4 | OCR / text-in-image carrier | buildable here |
| D5 | Screenshot (PrintScreen) carrier | buildable here |
| D6 | HTTP content-type matrix (Cymulate uses 20+ types). Results are keyed by technique, so several sink steps cannot be reported separately | buildable here after a schema change |

Data types previously listed as missing (JavaScript and C++ source, MySQL source, IPv6 and MAC addresses, names/addresses record, medical progress note, PowerPoint, plain ZIP) are now covered by `dlp-exfiltration-data-types` and `dlp-exfiltration-file-carriers`. Those are local file operations only.

**Proof**

| # | Gap | Status |
|---|---|---|
| D7 | No live run with DLP enabled. No product detection has been shown; everything is verified only as local file operations | needs lab/staging (the user runs this) |

## 5. Cross-cutting

| # | Gap | Status |
|---|---|---|
| X1 | No live run of any scenario in any of the four areas against a real product | needs lab/staging |
| X2 | The four Cymulate exports are customer-specific and dated 2022 to 2023 (WAF benchmark 2026). They describe one environment, not current products | known limit of the input |
| X3 | Cymulate PDF headline ratios do not reconcile with the CSV counts (WAF: PDF 63% vs about 17% penetrated in CSV). Use CSV counts; do not quote PDF ratios as scores | known limit of the input |
| X4 | The email export was stopped by the user, so its totals are incomplete | known limit of the input |
| X5 | Areas outside these four exports (endpoint, lateral movement, cloud, phishing awareness, immediate threats) are not compared | out of scope of this comparison |

## Summary

- **Buildable here with fixtures:** W1, W2, W3, W4, W5 (payload), W7, W9, E1, E5, E6, G2, G3, G5, D4, D5, D6
- **Needs a design decision first:** E4 and G4 (feed policy), D1, D2, D3 (raw sockets and new listeners), E2 (RAR tooling)
- **Needs lab or staging, not provable here:** W6, W8, E3, E9, G1, G6, D7, X1
- **Known limits of the inputs, not Audspect gaps:** X2, X3, X4, X5
