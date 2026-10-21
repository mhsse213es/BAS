# Audspect BAS — Posture Checks Guide

**Platform Version:** v1.7.3

---

## Overview

Posture checks are lightweight, non-destructive configuration verification steps that run on the agent endpoint. Unlike ART or Caldera simulation steps, posture checks do not attempt to emulate attacker behavior — they verify whether OS or application configuration meets a defined security baseline.

Posture checks are the foundation of the **Custom** framework and appear in scenarios like the Safe Security Simulation (Read-Only), CIS Ubuntu L1, and the RBI/SEBI compliance drills.

---

## How Posture Checks Work

1. The orchestrator dispatches a posture check step command to the agent
2. The agent executes the command (PowerShell on Windows, Bash on Linux/macOS)
3. The command exits with a code: `0` = PASS, `1` = FAIL, `2` = ERROR, `3` = SKIPPED
4. The agent returns exit code + stdout/stderr to the orchestrator
5. The orchestrator records the verdict and generates remediation guidance on FAIL

Posture checks are read-only by design. They query configuration state; they do not write, create, or execute system-modifying actions.

---

## Posture Catalog

The posture catalog is a per-agent inventory of all available posture checks for that agent's OS. It is populated automatically at enrollment time from the agent's built-in check set.

**Viewing the catalog:**
- Dashboard: Agents → [agent] → Overview tab → Posture Checks section
- API: `GET /api/posture/catalog?agentId={agentId}&scenario={scenarioId}`

Each catalog entry has these fields:

```json
[
  {
    "id": "<check-id>",
    "phase": "<phase>",
    "techniqueId": "<ATT&CK technique ID>",
    "name": "<check name>",
    "severity": "<critical | high | medium | low>"
  }
]
```

**Important:** If the posture catalog appears empty after upgrading an agent binary, the agent must **re-enroll** to refresh the catalog. The catalog is harvested only at enrollment time:

```bash
# On Linux
sudo systemctl stop bas-agent
sudo ./bas-agent-linux-amd64 -server https://<server>:9443 -secret <secret> -install
sudo systemctl start bas-agent
```

For Windows, uninstall and reinstall the agent service:
```powershell
.\bas-agent-windows-amd64.exe -uninstall
.\bas-agent-windows-amd64.exe -server https://<server>:9443 -secret <secret> -install
```

---

## OS Support Matrix

| Check Category | Windows | Linux | macOS |
|---|---|---|---|
| AV / EDR status | ✓ | ✓ | ✓ |
| Firewall configuration | ✓ | ✓ | ✓ |
| Logging configuration | ✓ | ✓ | — |
| Patch/update status | ✓ | ✓ | — |
| Password policy | ✓ | ✓ | — |
| Disk encryption | ✓ | ✓ | ✓ |
| Boot integrity (Secure Boot) | ✓ | ✓ | — |
| PowerShell configuration | ✓ | — | — |
| SSH configuration | — | ✓ | ✓ |
| AppArmor / SELinux | — | ✓ | — |
| CIS Benchmark L1 | — | ✓ (Ubuntu) | — |

---

## Writing Custom Posture Checks

Custom posture checks are authored as scenario steps with `framework: custom`. The command is a shell script executed on the agent.

### Windows (PowerShell)

```yaml
- id: check-audit-policy
  technique: "T1562.006"
  tactic: "defense-evasion"
  name: "Audit policy: Logon Events enabled"
  severity: high
  framework: custom
  executor: powershell
  command: |
    $audit = auditpol /get /subcategory:"Logon" 2>&1
    if ($audit -match "Success and Failure") {
      exit 0    # PASS
    } else {
      exit 1    # FAIL
    }
  remediation: |
    Enable Logon audit events:
    auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

### Linux (Bash)

```yaml
- id: check-ssh-root-login
  technique: "T1021.004"
  tactic: "lateral-movement"
  name: "SSH root login disabled"
  severity: critical
  framework: custom
  executor: bash
  command: |
    if grep -qE "^PermitRootLogin\s+no" /etc/ssh/sshd_config; then
      exit 0
    else
      exit 1
    fi
  remediation: |
    Edit /etc/ssh/sshd_config:
    Set: PermitRootLogin no
    Restart: systemctl restart sshd
```

### Exit code convention

| Exit Code | Verdict | Meaning |
|---|---|---|
| `0` | PASS | Configuration is correct; control effective |
| `1` | FAIL | Configuration gap found; remediation needed |
| `2` | ERROR | Check could not be executed (missing command, permission error) |
| `3` | SKIPPED | Check not applicable to this system configuration |

---

## Built-in Posture Checks

Audspect ships a library of ready-to-use posture check steps. Browse them in the scenario builder by filtering steps with `Framework: Custom`.

**Windows categories:**
- Windows Defender: real-time protection, cloud protection, behavior monitoring
- PowerShell: script block logging, transcription, constrained language mode
- Audit Policy: logon, process creation, privilege escalation
- UAC: level, notification settings
- SMB: signing, version (SMBv1 disabled)
- Windows Firewall: domain/private/public profiles
- BitLocker: encryption status
- Credential Guard: enabled/disabled

**Linux categories:**
- SSH: root login, password auth, key-only auth, protocol version
- Firewall: iptables/ufw status and default policy
- Automatic updates: unattended-upgrades enabled
- Logging: rsyslog, auditd, syslog
- AppArmor: status, profiles enforced
- Password: PAM complexity, minimum length, lockout policy
- File integrity: aide/tripwire installed and configured

---

## Posture Check vs. Simulation Step

| Aspect | Posture Check | ART/Caldera Simulation |
|---|---|---|
| Execution | Read-only OS/config query | Active technique execution |
| Risk | Zero operational impact | Minimal (BAS-controlled) impact |
| Verdict source | Exit code (script author-controlled) | Output pattern matching |
| EDR reaction | None expected | EDR should trigger |
| SIEM event | None | Expected SIEM event |
| Use case | Configuration validation | Control effectiveness validation |

Both types appear in the same scenario and contribute to the same scores. A scenario can mix posture checks and simulation steps in any order.

---

*© Audspect — Confidential — Customer Distribution*
