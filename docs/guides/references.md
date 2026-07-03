# Audspect BAS — References

**Platform Version:** v1.7.3

---

## Standards and Frameworks

| Standard | Title | Relevance |
|---|---|---|
| MITRE ATT&CK v14 | Adversary Tactics, Techniques, and Common Knowledge | Primary taxonomy for all scenario step mapping |
| NIST SP 800-132 | Recommendation for Password-Based Key Derivation | PBKDF2-HMAC-SHA256 iteration count guidance |
| NIST SP 800-53 Rev 5 | Security and Privacy Controls for Federal Information Systems | Compliance mapping framework |
| NIST SP 800-115 | Technical Guide to Information Security Testing | BAS methodology foundations |
| CISA KEV Catalog | Known Exploited Vulnerabilities Catalog | Technique enrichment data source |
| FIRST EPSS | Exploit Prediction Scoring System | CVE exploit probability enrichment |
| ISO/IEC 27001:2022 | Information Security Management Systems | Compliance mapping framework |
| CIS Benchmarks v8 | Center for Internet Security Controls and Benchmarks | Posture check framework |
| RFC 7519 | JSON Web Token (JWT) | Session authentication standard |
| RFC 2898 | PKCS #5: Password-Based Cryptography Specification | PBKDF2 standard |
| RFC 4880 | OpenPGP Message Format | Scenario signing (GPG/OpenPGP) |
| STIX 2.1 | Structured Threat Information Expression | ATT&CK data format; OpenCTI connector format |
| OWASP Top 10 | Top Web Application Security Risks | Platform security guidance |

---

## Regulatory Frameworks

| Framework | Issuer | Coverage in Audspect BAS |
|---|---|---|
| RBI Cyber Security Framework | Reserve Bank of India | Dedicated scenario + compliance report |
| SEBI Cybersecurity Circular for MII | Securities and Exchange Board of India | Dedicated scenario + compliance report |
| RBI Cloud Framework | Reserve Bank of India | Referenced in architecture guidance |

---

## Open Source Components

| Component | License | Usage |
|---|---|---|
| Atomic Red Team (ART) | MIT | ART atomic test library |
| Caldera | Apache 2.0 | Adversary emulation platform (optional) |
| CTID Adversary Emulation Library | Apache 2.0 | Caldera abilities library |
| BloodHound / SharpHound | Apache 2.0 | AD attack path data collection |
| PostgreSQL | PostgreSQL License | Database |
| Docker | Apache 2.0 | Container runtime |
| Chi (Go router) | MIT | HTTP routing |
| gorilla/websocket | BSD | WebSocket implementation |
| golang.org/x/crypto | BSD | PBKDF2 implementation |
| golang.org/x/crypto/bcrypt | BSD | Legacy bcrypt verification |
| garble | BSD | Go binary obfuscation |

---

## Audspect Documentation Set

### Customer Guides (`docs/guides/`)

| Document | Description |
|---|---|
| [Quick Start](quick-start.md) | First deployment and first simulation in 30 minutes |
| [Installation Guide](installation.md) | Complete deployment: web wizard, TLS, systemd, sizing |
| [Upgrade Guide](upgrade-guide.md) | Upgrading from v1.6.x or v1.7.x |
| [Backup and Restore](backup-restore.md) | Database backup, restore, disaster recovery procedures |
| [Agent Management](agent-management.md) | Agent deployment, lifecycle states, binary trust |
| [Scenarios Guide](scenarios.md) | Scenario library, YAML format, builder, hybrid modes |
| [Scoring Methodology](scoring-methodology.md) | Score formulas, weights, risk bands, trend |
| [Reporting Guide](reporting.md) | All report types, scheduling, integrity, formats |
| [Findings and Remediation](findings-remediation.md) | Finding lifecycle, re-validate, ticket integration |
| [Attack Path Guide](attack-path.md) | Collection, job lifecycle, SharpHound, graph analysis |
| [Posture Checks](posture-checks.md) | Posture catalog, OS checks, custom posture steps |
| [User Management](user-management.md) | RBAC, user creation, password policy |
| [API Reference](api-reference.md) | Complete REST API documentation |
| [Configuration Guide](configuration.md) | All environment variables and config options |
| [Security Hardening](security-hardening.md) | TLS, secrets, Docker hardening, audit logging |
| [Compliance Mapping](compliance-mapping.md) | Framework-to-technique mapping tables |
| [Architecture Deep Dive](architecture-deep-dive.md) | Service boundaries, request lifecycle, database tables |
| [Troubleshooting](troubleshooting.md) | 70+ symptom/cause/fix entries |
| [FAQ](faq.md) | Frequently asked questions |
| [Glossary](glossary.md) | 60+ term definitions |
| [Release Notes](release-notes.md) | Version history and changelog |
| [References](references.md) | This document |

### Internal Documentation (`docs/internal/`)

| Document | Description |
|---|---|
| [Build Guide](../internal/build-guide.md) | Windows build pipeline, garble, Docker build steps |
| [Signing Infrastructure](../internal/signing-infrastructure.md) | GPG key management, scenario signing, rotation |
| [Developer Guide](../internal/developer-guide.md) | Dev environment, repo layout, architectural decisions |
| [Scenario SDK](../internal/scenario-sdk.md) | Complete YAML schema reference for scenario authoring |
| [Monitoring and Logging](../internal/monitoring-logging.md) | Log format, health metrics, SIEM export |
| [Performance Tuning](../internal/performance-tuning.md) | PostgreSQL tuning, Chromium scaling, disk management |
| [Disaster Recovery](../internal/disaster-recovery.md) | Recovery procedures for all failure scenarios |

---

## Support Contacts

| Type | Contact |
|---|---|
| Customer support | support@audspect.com |
| Security issues | security@audspect.com |
| License inquiries | support@audspect.com |
| Engineering (internal) | engineering@audspect.com |

---

*© Audspect — Confidential — Customer Distribution*
