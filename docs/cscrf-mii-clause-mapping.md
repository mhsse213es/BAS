# CSCRF-MII internal references mapped to circular clauses (provisional)

**Source used:** SEBI circular SEBI/HO/ITD-1/ITD_CSC_EXT/P/CIR/2024/113 (20 August 2024), the Cybersecurity and Cyber Resilience Framework. The copy read was a third-party mirror (APMI, 205 pages), not sebi.gov.in. Every mapping below must be checked against the official SEBI copy before it is treated as final.

**Rule:** a mapping is a pointer to the clause that covers the same control, not a claim that BAS establishes compliance. BAS validates technical controls only.

| Internal reference | Control | Framework identifier | Clause text in the circular (short quote) | Status |
|---|---|---|---|---|
| CSCRF-BDR-01 | Backup present | RC.RP.S4 | "A backup and recovery plan shall be formulated..." and backup of data and server images | Mapped |
| CSCRF-BDR-02 | Recovery point age | RC.RP.S4 | "RTO and RPO, as prescribed by SEBI from time to time..." | Mapped; the numeric RPO is not in the circular and must come from SEBI |
| CSCRF-BDR-03 | Restore integrity | RC.RP.S2 | "REs shall periodically conduct backup testing and restore back-up data..." | Mapped |
| CSCRF-BDR-04 | Restore time | RC.RP.S2 | RTO of two hours is cited as a recommendation in the text | Mapped; file-level test only |
| CSCRF-BDR-05 | DR site connectivity | none confirmed | DR plans are required (line 3434); no identifier was found for the clause | Unmapped |
| CSCRF-IR-01 | Malware detection | PR.AA.S9 (malware controls); PR.AA.S15 (EPP/EDR/anti-malware) | "Adequate controls shall be deployed to address virus/ malware/ ransomware attacks" | Mapped |
| CSCRF-IR-03 | Block known-bad addresses | PR.AA.S9 | "configured to scan for known bad domains, sources, and addresses, block these" | Mapped |
| CSCRF-IR-04 | Account disablement | PR.AA.S9 (end-of-life user deactivation) | "'end of life' mechanisms shall be adopted for user management to deactivate..." | Partial |
| CSCRF-IR-06 | Evidence export | RS.AN.S3 | "...system logs, network traffic, and forensic images of affected systems" | Partial |
| CSCRF-DP-01 | Encryption at rest | PR.DS.S3 | "Data shall be encrypted in motion, at rest and in-use by using strong encryption" | Mapped |
| CSCRF-DP-02 | Data path ACL | PR.AA.S9 (access rights) | access rights and privileged users | Partial |
| CSCRF-DP-03 | SMB encryption (in motion) | PR.DS.S3 | as above (in motion) | Mapped |
| CSCRF-DP-04 | DLP agent | PR.DS.S3 | "REs shall deploy Data Loss Prevention (DLP) solutions/ processes." | Mapped |
| CSCRF-ID-01 / ID-02 | Privileged group and admin account changes | PR.AA.S5 (review of privileged users); PR.AA.S9 (privileged users) | "Review of privileged users" | Mapped |
| CSCRF-ID-06 | Password policy | PR.AA.S6 | "minimum password length and history" | Mapped |
| CSCRF-ID-07 | MFA | PR.AA.S9; PR.AA.S12 | "All critical systems accessible over the internet shall have multi-factor security"; remote access "must employ MFA" | Mapped |
| CSCRF-EA-01 | Patch currency | PR.MA.S3 | "patch management procedures" | Mapped |
| CSCRF-EA-02 | Supported OS | PR.MA.S3; GV.RM.S2 | end-of-support and end-of-life software | Mapped |
| CSCRF-EA-03 | Endpoint protection | PR.AA.S15 | "Solutions like EPP, EDR, XDR, anti-malware software etc. shall be implemented" | Mapped |
| CSCRF-EA-08 | Application control | PR.IP.S1 | "REs shall use application directory whitelisting on all assets" | Mapped |
| CSCRF-NET-01..08 | Network segmentation, ingress/egress, DNS | PR.AA.S9 | segmentation; "whitelist approach of IPs"; "DNS filtering services" | Partial (grouped; not one-to-one) |
| CSCRF-SIEM-02 | Event forwarding | PR.IP.S1 | "Send the associated logs to a centralized log repository" | Mapped |
| CSCRF-SIEM-03 | Ingestion check | PR.IP.S1 | as above | Partial |
| CSCRF-SIEM-04 | Log retention | PR.AA.S8 | "Strong log retention policy shall be implemented" | Mapped |
| CSCRF-SIEM-01 | Time source | not found | "NTP" appears only in a server list (line 9335) | Unmapped |
| CSCRF-MII-01..04 | MII trade logs, settlement files, services, reconciliation | not found | no MII-specific clause identified | Unmapped |
| CSCRF-GOV-01..03, CSCRF-REG-01 | Governance and regulatory items | not applicable | outside BAS scope | Not validatable |

**Open items before this table is final:** check every "Mapped" row against the official SEBI copy; find identifiers for CSCRF-BDR-05 and CSCRF-SIEM-01; confirm whether the circular's clause for DR connectivity exists in an annexure.
