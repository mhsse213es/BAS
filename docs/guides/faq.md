# Audspect BAS — Frequently Asked Questions

**Platform Version:** v1.7.3

---

## General

**Q: Does Audspect BAS require internet access?**

No. The platform is fully air-gapped after initial delivery. All content (ART library, ATT&CK STIX data, KEV catalog, Caldera abilities, scenarios) is bundled in the Docker images. No data is sent to Audspect or any external service.

---

**Q: Does Audspect BAS send any data outside our network?**

No. All data — agent results, run history, findings, reports, user accounts, attack path graphs — is stored exclusively in the on-premises PostgreSQL instance. The platform makes no outbound connections at runtime.

---

**Q: Will BAS simulation trigger our EDR or SIEM alerts?**

Yes — and that's intentional. BAS simulation is real-technique execution; it is designed to trigger your controls. If your EDR blocks a technique, the step records PASS. If the technique executes without interference, it records FAIL. Coordinate with your SOC before running large-scale scenarios to avoid alert fatigue. The **Safe Simulation** scenario is a read-only scenario that does not trigger EDR responses, useful for initial connectivity testing.

---

**Q: Is the agent safe to run in production?**

Yes, with these caveats:
- The agent executes the commands the orchestrator dispatches. If you dispatch an ART all-windows scan, it will attempt real attack techniques.
- Use the **Safe Simulation** scenario for the first run to verify connectivity without impact.
- ART/Caldera steps include cleanup commands that restore system state after execution.
- The agent runs as a Windows service or Linux systemd unit with configurable service account permissions.
- Do not enable **Lab Mode** in production environments. Lab mode enables payload-bearing steps.

---

**Q: What's the difference between a FAIL verdict and an ERROR verdict?**

| Verdict | Who is responsible | Scoring impact |
|---|---|---|
| FAIL | Your security controls | Included in scoring; lowers Prevention Score |
| ERROR | The BAS platform (execution problem) | Excluded from scoring |

FAIL means the attacker succeeded — your EDR, AV, or other control allowed the technique. ERROR means the BAS infrastructure couldn't run the step at all (e.g., missing prerequisite, PowerShell policy, agent offline mid-run). ERROR steps are not your security team's problem.

---

**Q: How long does a full scenario run take?**

| Scenario | Approximate Duration |
|---|---|
| Safe Simulation | 1–2 minutes |
| Selective ART Test (40–80 techniques) | 10–20 minutes |
| Full ART Windows (300+ techniques) | 60–90 minutes |
| CIS Ubuntu L1 | 5–10 minutes |
| Attack Path Collection | 5–30 minutes (depends on network size and SharpHound) |

---

**Q: Can I run BAS simulations against servers, not just workstations?**

Yes. Deploy the agent on any target endpoint: workstations, servers, domain controllers, application servers. The agent binary is the same; it detects the OS and adapts execution accordingly. Consult with your IT team before deploying agents on critical production servers and schedule runs during low-activity windows.

---

## Agents

**Q: How many agents can the platform support?**

The platform has been tested at:
- Up to 50 agents: standard 4 vCPU / 8 GB RAM server
- 50–200 agents: 8 vCPU / 16 GB RAM recommended
- 200+ agents: contact Audspect for sizing guidance

---

**Q: What happens if the server goes offline while agents are running?**

Agents buffer results locally and retry submission. When the server comes back online, agents re-establish WebSocket connections and submit buffered results. The orchestrator's run staleness monitor marks runs as Partial if no result is received for 90 seconds — but buffered results submitted after reconnect heal the partial run to Completed.

---

**Q: Can I run multiple scenarios on the same agent simultaneously?**

No. The platform queues scenarios for each agent. If you dispatch two scenarios to the same agent, the second is queued and starts when the first completes. Multiple agents can run scenarios simultaneously without limit.

---

**Q: How do I update agent binaries across a large fleet?**

1. Download the new binary from the dashboard (Agents → Download Agent)
2. Deploy via your standard method: SCCM, Ansible, Group Policy, manual
3. On Windows, the agent service restarts automatically on binary replacement
4. On Linux, restart the service: `sudo systemctl restart bas-agent`

The dashboard shows a binary trust warning for agents running an outdated binary (yellow shield icon).

---

## Scoring

**Q: My Prevention Score went from 80 to 60 between two runs. Why?**

Several factors can cause score drops:
1. **AV/EDR update removed an exclusion** that was previously blocking a technique
2. **New techniques added to the scenario** in a version update (more tested steps with failures increases the denominator)
3. **Agent environment changed** (patch removed, policy changed, new software installed)
4. **Different run scope** — some steps that were SKIPPED before are now running (e.g., new tool installed satisfying a prerequisite)

Check the Trend badge: if it shows Degrading, compare the step-by-step results of this run vs. the previous one to identify which specific steps changed from PASS to FAIL.

---

**Q: How does the Kill Chain Amplifier work?**

The Kill Chain Amplifier multiplies your Exposure Score when an attacker achieves failures (technique successes) in consecutive kill-chain phases. An attacker who can execute in multiple consecutive phases represents a more serious threat than one who can execute in isolated phases. The amplifier models this reality:

- 1 failed phase: 1.0× (no amplification)
- 2 consecutive failed phases: 1.2×
- 5+ consecutive failed phases: 2.5×

---

**Q: Why is Coverage Score lower than Prevention Score?**

Coverage Score is binary per tactic — one failed step in a tactic marks the whole tactic as exposed. Prevention Score is a weighted average. A tactic with 10 steps, 9 passing and 1 failing, scores 90% in Prevention but 0% in Coverage.

This is intentional: Coverage Score identifies kill-chain phases where attackers have any foothold. Prevention Score shows your overall block rate. Both together give the complete picture.

---

## Findings and Remediation

**Q: A finding appeared but the technique is intentionally allowed in our environment. What do I do?**

Set the finding status to **False Positive**. This removes it from the remediation queue and from scoring impact without deleting the historical record. False positives are excluded from Prevention Score calculations.

---

**Q: How do I close a finding?**

After fixing the control gap, use **Re-validate** to dispatch a targeted re-run on the affected agent. When the re-run passes, the finding automatically moves to **Validated** status. Move it to **Resolved** once you confirm the fix is stable.

Alternatively, set the status manually to **Resolved** if you applied the fix and cannot immediately re-validate (e.g., a patch is deployed but requires a maintenance window for re-run).

---

## Reports

**Q: Why does the PDF report have blank pages?**

The Chromium sidecar container is not running or is out of memory. Check:
```bash
docker compose ps | grep chromium
docker compose logs chromium --tail=20
```

Restart the sidecar: `docker compose up -d chromium`

---

**Q: Can I customize the report template?**

Report templates are compiled into the orchestrator binary (Go `html/template` package). Custom branding (logo, colors) is available by contacting Audspect for a customized build. Template-level customization is not available in the standard release.

---

## Security

**Q: What password algorithm does Audspect BAS use?**

PBKDF2-HMAC-SHA256, 310,000 iterations (NIST SP 800-132 minimum), 256-bit derived key, 256-bit random salt. The iteration count is configurable higher via `BAS_PBKDF2_ITERATIONS`. A cryptographic self-test runs at every startup.

---

**Q: Does the platform have any telemetry or phone-home behavior?**

No. The platform makes no network connections outside of what you explicitly configure (Caldera URL, MISP URL, OpenCTI URL, SMTP server). All of these are optional and must be configured by the administrator.

---

**Q: How are scenario files protected from tampering?**

Every scenario YAML is paired with an RSA-4096 detached signature file (`.yaml.sig`). The orchestrator:
- Verifies signatures on startup when loading scenarios
- Re-verifies every 15 seconds via a filesystem watcher
- Re-verifies at dispatch time before sending to an agent
- Refuses to load or run any scenario that fails signature verification

---

**Q: Are my BAS simulation results usable in legal or regulatory proceedings?**

BAS simulation results are strong technical evidence of security control effectiveness at a point in time. For formal regulatory submissions (RBI, SEBI examinations), the generated compliance reports carry SHA-256 integrity hashes and generation timestamps. Consult your compliance counsel on the evidentiary standards in your jurisdiction.

---

*© Audspect — Confidential — Customer Distribution*
