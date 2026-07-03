# Audspect BAS — Glossary

**Platform Version:** v1.7.3

---

| Term | Definition |
|---|---|
| **Agent** | Lightweight Go binary deployed on a target endpoint that receives and executes simulation commands from the orchestrator. Agents are intentionally "dumb" — all intelligence lives on the server. |
| **Agent Secret** | Shared passphrase used for HMAC-SHA256 authentication of agent-submitted results. Required on both the server (`AGENT_SECRET` env var) and the agent configuration. |
| **Amplifier** | See Kill Chain Amplifier. |
| **Anomaly Detection** | EDR/SIEM capability that detects deviations from baseline behavior. BAS simulation provides ground-truth events for validating anomaly detection effectiveness. |
| **ART** | Atomic Red Team — an open-source library of ATT&CK-mapped attack simulation test cases maintained by Red Canary. Audspect bundles the ART YAML library in the orchestrator image. |
| **Asset Score** | Risk measure (0–100, higher = worse) for individual hosts based on how many attack paths pass through them and their criticality tier tag. |
| **ATT&CK** | MITRE ATT&CK — a globally accessible knowledge base of adversary tactics, techniques, and procedures based on real-world observations. The primary taxonomy used in Audspect BAS. |
| **ATT&CK Navigator** | MITRE's open-source visualization tool for ATT&CK matrices. Audspect exports Attack Flow reports as Navigator-compatible JSON. |
| **Atomic Test** | A single, reproducible simulation of one MITRE ATT&CK technique, defined in ART YAML. Each atomic has a unique ID, executor, command, prerequisites, and cleanup. |
| **Audit Log** | Immutable record of all security-relevant platform events (auth, user management, agent state changes, integrity failures). Visible in the dashboard Audit Logs section. |
| **Audit Pack** | ZIP archive containing HTML report, PDF report, CSV data, raw JSON, and a SHA-256 manifest for one agent's complete assessment period. |
| **Baseline** | The Prevention Score from the first completed run of a scenario on an agent. All subsequent runs are compared against this baseline. |
| **BAS** | Breach and Attack Simulation — methodology for continuously emulating adversary techniques against an organization's own infrastructure to validate security control effectiveness. |
| **BFSI** | Banking, Financial Services, and Insurance — the primary target industry for Audspect BAS. |
| **Blast Radius** | The set of hosts reachable from a collection source in the attack path graph within a given hop count. Higher blast radius = greater lateral movement potential. |
| **BloodHound** | Open-source Active Directory attack path analysis tool. Audspect integrates BloodHound's data collector (SharpHound) for domain-joined attack path collection. |
| **Caldera** | MITRE's open-source adversary emulation platform. Audspect uses a custom `bas-caldera` image baking the CTID adversary emulation library (~2,213 abilities). |
| **Campaign** | A grouped execution of multiple scenarios across multiple agents, run simultaneously, producing a unified campaign report and a single campaign-level score. |
| **Capability** | A MITRE Caldera ability's specific action type (execute command, upload file, run shellcode, etc.). |
| **CBOM** | Cryptography Bill of Materials — an inventory of cryptographic algorithms, keys, and protocols in use within the platform. See `docs/SBOM-CBOM-v1.7.3.md`. |
| **CEF** | Common Event Format — a standard log format used in SIEM systems. BAS simulation logs can be exported in CEF for SIEM ingestion. |
| **Choke Point** | A host in the attack path graph that appears in the highest number of paths. Hardening a choke point reduces the blast radius more than hardening any other single host. |
| **CIS Benchmarks** | Center for Internet Security hardening guidelines. Audspect includes a CIS Ubuntu L1 scenario for automated benchmark validation. |
| **Command and Control (C2)** | MITRE ATT&CK tactic: technique for adversary communication with compromised hosts. T1071, T1095, T1571, etc. |
| **Compliance Score** | Percentage of framework controls where the platform's security measures are verified as effective through BAS simulation. |
| **Coverage Score** | Percentage of tested MITRE ATT&CK tactics where every step passed. A tactic is "fully covered" only when no step in it failed. |
| **Crown Jewel** | An asset tagged with the highest criticality tier. Attack paths terminating at crown jewel assets are treated as Critical severity findings. |
| **CTID** | Center for Threat-Informed Defense — a MITRE-affiliated research center. Produces the Adversary Emulation Library used in Audspect's Caldera integration. |
| **CVE** | Common Vulnerabilities and Exposures. Audspect does not scan for CVEs but optionally enriches findings with KEV-mapped CVE data. |
| **Delivery ZIP** | The self-contained installation package provided by Audspect containing Docker image tarballs, scenarios, and setup scripts. Suitable for air-gapped environments. |
| **Detection** | A security control's response to a simulated technique (EDR alert, SIEM event, AV block). Audspect provides ground-truth stimulus; detection validation requires cross-referencing with SIEM telemetry. |
| **Docker Compose** | The container orchestration tool used for Audspect BAS deployment. All platform components run as Docker containers defined in `docker-compose.yml`. |
| **Edge** | A relationship between two nodes in the attack path graph. Edge types: tcp_reachable, local_admin, active_session, ad_group_member, ad_gpo. |
| **EDR** | Endpoint Detection and Response. The primary security control tested by BAS simulation steps on endpoint agents. |
| **EPSS** | Exploit Prediction Scoring System (FIRST). Probability scores for CVE exploitation. Optionally used for enrichment if the EPSS file is configured. |
| **ERROR** | BAS step verdict meaning the simulation platform could not execute the step. Not a control result — excluded from scoring. |
| **Evidence** | Raw output (stdout/stderr), artifacts, or screenshots captured during a simulation step. Stored per-run and displayed in findings for comparison. |
| **Exercise** | A structured Purple Team engagement: a defined plan with multiple steps, blue team detection evidence capture, step-by-step approval, and a formal report with evidence chain. |
| **Exposure Score** | A BAS metric (0–100, higher = worse) measuring how far an attacker can progress through the kill chain, amplified by consecutive failures across phases. |
| **FAIL** | BAS step verdict meaning the technique succeeded (the attacker wins). A failed technique is the primary source of Findings. |
| **Finding** | A structured record created when a technique produces a FAIL verdict, tracking the control gap through a lifecycle from Created to Resolved. |
| **Garble** | A Go source code obfuscation tool used in the Audspect orchestrator build pipeline. Obfuscates symbol names and string literals. |
| **Graph** | The data structure built from attack path collection: nodes (hosts/users) and edges (relationships). Used for blast radius and path analysis. |
| **HMAC** | Hash-based Message Authentication Code. Used to authenticate agent-submitted results: HMAC-SHA256 over the full result payload using `AGENT_SECRET`. |
| **Integrity System** | Audspect's platform-level tamper detection: RSA-4096 scenario signing, agent binary trust, result HMAC, report hashing, and 15-second filesystem watch. |
| **JWT** | JSON Web Token (RFC 7519). Used for browser session authentication. Issued on login, stored as an HttpOnly cookie, expires after 24 hours. |
| **KEV** | CISA Known Exploited Vulnerabilities catalog. Audspect bundles this for technique enrichment. Only curated mappings are used — never auto-generated. |
| **Kill Chain** | An ordered sequence of MITRE ATT&CK tactics representing the phases of an attack: Reconnaissance → Resource Development → Initial Access → Execution → Persistence → Privilege Escalation → Defense Evasion → Credential Access → Discovery → Lateral Movement → Collection → C2 → Exfiltration → Impact. |
| **Kill Chain Amplifier** | A multiplier (1.0×–2.5×) applied to the Exposure Score when an attacker achieves consecutive FAIL results across advancing kill-chain phases. |
| **Lab Mode** | An execution mode that enables payload-bearing simulation steps. Disabled by default; requires explicit enable in both scenario YAML and agent enrollment config. |
| **License** | Node-locked, time-limited license file (`.lic`) required for full platform functionality. Path configured via `BAS_LICENSE_PATH`. |
| **LOLBin** | Living-Off-the-Land Binary — a legitimate OS binary (e.g., `certutil.exe`, `mshta.exe`, `wmic.exe`) abused by attackers to execute malicious actions while evading detection. |
| **Manifest** | `BINARIES.sha256` — a file listing SHA-256 hashes of all known-good agent binaries, used for binary trust verification on each heartbeat. |
| **MISP** | Malware Information Sharing Platform. One of two threat intelligence connectors supported by Audspect BAS. |
| **MITRE ATT&CK** | See ATT&CK. |
| **Node** | A host or user identity in the attack path graph. Host nodes include IP, hostname, OS, and criticality tier. |
| **Orchestrator** | The central BAS server: Go binary handling scenario engine, scoring, REST API, WebSocket hub, and static file serving for the dashboard. |
| **PASS** | BAS step verdict meaning the control blocked or detected the technique. Contributes positively to the Prevention Score. |
| **PBKDF2** | Password-Based Key Derivation Function 2 (RFC 2898). The platform's password hashing algorithm: PBKDF2-HMAC-SHA256, 310,000 iterations, 256-bit output. |
| **Posture** | The security configuration and control effectiveness state of an endpoint, as measured by the platform's simulation results. |
| **Posture Catalog** | The per-agent inventory of available posture checks, harvested at enrollment and stored in `agents.posture_catalog`. |
| **Prevention Score** | A BAS metric (0–100, higher = better) measuring the severity-weighted proportion of techniques that were blocked by security controls. |
| **Purple Team** | A collaborative security testing methodology where red team attack actions are observed and documented by the blue team for detection gap analysis. Audspect's Exercise module supports structured purple team exercises. |
| **RBAC** | Role-Based Access Control. Audspect uses three roles: Viewer, Analyst, Admin. |
| **Re-validate** | A targeted single-technique re-run dispatched to a specific agent to verify that a remediated control now blocks the technique. |
| **Remediation** | The Audspect view that groups Findings by technique across all agents, showing aggregate impact and recommended fixes. |
| **Risk Classification** | The risk band derived from a Prevention Score: Protected (90–100), Low (75–89), Medium (50–74), High (25–49), Critical (0–24). |
| **RSA-4096** | The asymmetric cryptography used for scenario YAML signing. 4096-bit keys provide strong long-term signing security. |
| **Run** | A single execution of a scenario on a specific agent at a specific time. The fundamental unit of BAS simulation history. |
| **SBOM** | Software Bill of Materials — inventory of software components. See `docs/SBOM-CBOM-v1.7.3.md`. |
| **Scenario** | A named, versioned, signed YAML file defining a collection of simulation steps, metadata, and scoring configuration. |
| **SEBI** | Securities and Exchange Board of India. Issues cybersecurity circulars for Market Infrastructure Institutions (MII) that Audspect maps to test scenarios. |
| **SharpHound** | BloodHound's Active Directory data collector. Used in Audspect BAS Attack Path Validation for domain-joined host graph enrichment. |
| **SIEM** | Security Information and Event Management. Audspect generates ground-truth simulation events that a properly configured SIEM should detect and alert on. |
| **SKIPPED** | BAS step verdict meaning the step was not applicable to this OS or configuration. Excluded from scoring. |
| **STIX** | Structured Threat Information Expression. MITRE publishes ATT&CK data as STIX 2.1 bundles. Audspect bundles ATT&CK STIX for authoritative technique-to-tactic mapping and enrichment. |
| **Tactic** | A MITRE ATT&CK kill-chain phase (e.g., credential-access, lateral-movement). Techniques are categorized under one or more tactics. |
| **Technique** | A specific MITRE ATT&CK method (e.g., T1003.001 — LSASS Memory). The fundamental unit of adversary behavior in the framework. |
| **Telemetry** | Real security events (EDR alerts, SIEM events) generated when a live simulation step executes on an endpoint. BAS provides the known input; telemetry validation verifies the expected output. |
| **Trend** | The direction of Prevention Score change: Improving, Degrading, Stable, or Baseline (first run). Threshold: >3 points change to register Improving or Degrading. |
| **TTP** | Tactics, Techniques, and Procedures — the vocabulary of adversary behavior. Audspect BAS tests TTPs continuously. |
| **Variant** | A family of similar techniques or payloads tested together to validate that controls block the technique across its known variants, not just one specific implementation. |
| **Verdict** | The outcome of a single simulation step: PASS, FAIL, ERROR, or SKIPPED. |
| **WebSocket** | Persistent bidirectional communication channel between the browser and orchestrator. Powers live run output, AP job progress, and real-time agent status updates. |

---

*© Audspect — Confidential — Customer Distribution*
