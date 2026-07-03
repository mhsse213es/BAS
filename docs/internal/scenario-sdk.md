# Audspect BAS — Scenario SDK

**Classification:** Internal — Audspect Engineering / Confidential  
**Platform Version:** v1.7.3

---

## Overview

This document describes the complete YAML schema for authoring Audspect BAS scenarios. It is the authoritative reference for internal scenario authors and the basis for the customer-facing Scenario Builder documentation.

---

## Full Schema Reference

```yaml
# ──────────────────────────────────────────────────────────
# SCENARIO METADATA
# ──────────────────────────────────────────────────────────
id: string                    # Required. Unique slug. [a-z0-9-_]
name: string                  # Required. Human-readable display name
version: string               # Required. Semantic version (e.g., "1.2.0")
description: string           # Optional. Long description for dashboard card
author: string                # Optional. Author name or team
tags:                         # Optional. Freeform tags for filtering
  - string
os_support:                   # Required. List of: windows / linux / darwin / all
  - string
framework: string             # Top-level framework hint: custom / art / caldera / hybrid
tactics:                      # Optional. Top-level tactic list for dashboard display
  - string
lab_only: bool                # Optional. If true, requires lab_mode: true on agent
safe: bool                    # Optional. If true, marks as safe for production
builtin: bool                 # Internal use only. Set by build pipeline for built-in scenarios.

# ──────────────────────────────────────────────────────────
# STEPS
# ──────────────────────────────────────────────────────────
steps:
  - id: string                # Required. Unique within this scenario
    name: string              # Required. Display name
    technique: string         # Required. MITRE ATT&CK ID (e.g., "T1003.001")
    tactic: string            # Required. MITRE ATT&CK tactic slug
    severity: string          # Required. critical / high / medium / low / informational
    framework: string         # Required. custom / art / caldera

    # ── Custom framework fields ──
    executor: string          # powershell / bash / cmd
    command: string           # Shell script body (multiline OK)
    cleanup: string           # Optional. Cleanup script run after step regardless of verdict
    expected_exit_pass: int   # Default: 0
    expected_exit_fail: int   # Default: 1
    expected_exit_error: int  # Default: 2
    expected_exit_skip: int   # Default: 3

    # ── ART framework fields ──
    art_technique: string     # MITRE technique ID to look up in ART library
    art_test_index: int       # Which test within the technique (0-indexed)
    art_executor_override: string  # Override executor (powershell/bash/cmd/sh)

    # ── Caldera framework fields ──
    caldera_ability_id: string   # Caldera ability UUID
    caldera_executor: string     # psh / sh / cmd

    # ── Common optional fields ──
    os: string                # Override: this step only runs on windows/linux/darwin
    timeout_seconds: int      # Step timeout (default: 60 for ART, 30 for custom)
    remediation: string       # Remediation guidance displayed in findings
    expected_telemetry: string  # Documentation: what SIEM/EDR event should be generated
    references:               # Optional. CVEs, ATT&CK URLs
      - string
    deferred: bool            # If true, execution is deferred (see posture-checks.md)
    defer_until: string       # Time in HH:MM format (agent local time)
    defer_window_minutes: int # Execution window after defer_until
    lab_only: bool            # If true, step only runs in lab mode
    prerequisites:            # Custom prerequisite checks (before executing the step)
      - id: string
        executor: string
        command: string       # If exits non-zero, step is SKIPPED
```

---

## Verdict Logic

### Custom steps

| Exit Code | Verdict |
|---|---|
| `expected_exit_pass` (default: 0) | PASS |
| `expected_exit_fail` (default: 1) | FAIL |
| `expected_exit_error` (default: 2) | ERROR |
| `expected_exit_skip` (default: 3) | SKIPPED |
| Any other code | ERROR |

### ART steps

The orchestrator:
1. Executes the ART atomic's `command` on the agent
2. Collects stdout + stderr
3. Runs the ART atomic's expected-pass and expected-fail patterns (from the atomic YAML) against the output
4. If expected-pass pattern matches: PASS
5. If expected-fail pattern matches: FAIL
6. If neither: falls back to exit code

### Caldera steps

Caldera ability success/failure is determined by the ability's `success` condition defined in Caldera. The orchestrator translates Caldera's result to PASS/FAIL/ERROR.

---

## OS Targeting

```yaml
os_support:
  - windows       # Entire scenario only runs on Windows agents
```

```yaml
steps:
  - id: step-001
    os: windows   # Only this step runs on Windows; skipped on other OS
```

If `os_support` is `all`, the scenario can run on any OS. Steps with an `os` filter are SKIPPED on non-matching agents.

---

## Example: Hybrid Scenario

```yaml
id: hybrid-endpoint-check
name: "Hybrid Endpoint Security Assessment"
version: "1.0.0"
description: "Combines posture checks with live ART simulation."
tags: [windows, hybrid, endpoint]
os_support: [windows]
framework: hybrid

steps:
  # Posture check — read-only configuration query
  - id: step-001
    technique: "T1562.001"
    tactic: "defense-evasion"
    name: "Windows Defender: Real-time protection enabled"
    severity: high
    framework: custom
    executor: powershell
    command: |
      $status = (Get-MpComputerStatus).AntivirusEnabled
      if ($status) { exit 0 } else { exit 1 }
    remediation: |
      Enable Windows Defender real-time protection:
      Set-MpPreference -DisableRealtimeMonitoring $false

  # ART simulation — live technique execution
  - id: step-002
    technique: "T1003.001"
    tactic: "credential-access"
    name: "LSASS Memory Dump Attempt"
    severity: critical
    framework: art
    art_technique: "T1003.001"
    art_test_index: 0
    expected_telemetry: |
      EDR should block or alert on lsass.exe memory access.
      SIEM rule: process_access where target=lsass.exe and caller NOT in (known_good_processes)
    remediation: |
      1. Enable Credential Guard: gpedit.msc → Credential Guard
      2. Configure EDR to block lsass.exe memory access
      3. Audit EDR exclusions for lsass.exe references
```

---

## Prerequisites System

Prerequisites run before a step and determine whether the step runs at all:

```yaml
steps:
  - id: step-003
    technique: "T1027"
    ...
    prerequisites:
      - id: check-mimikatz-present
        executor: powershell
        command: |
          if (Test-Path "C:\temp\mimikatz.exe") { exit 0 } else { exit 1 }
```

If any prerequisite exits non-zero, the step is SKIPPED with a note identifying which prerequisite failed. This is the mechanism ART uses for its native prerequisites; custom prerequisites follow the same convention.

---

## Cleanup

```yaml
- id: step-004
  framework: custom
  executor: powershell
  command: |
    New-Item -Path C:\Windows\Temp\bas-test-artifact.txt -ItemType File -Force | Out-Null
    # Check if creation was blocked (EDR/hardening)
    if (Test-Path C:\Windows\Temp\bas-test-artifact.txt) { exit 1 } else { exit 0 }
  cleanup: |
    Remove-Item -Path C:\Windows\Temp\bas-test-artifact.txt -ErrorAction SilentlyContinue
```

Cleanup runs after the step regardless of verdict (PASS, FAIL, ERROR). Cleanup failures are logged but do not change the step verdict.

---

## Signing Custom Scenarios

Custom scenarios uploaded via the dashboard are signed automatically by the orchestrator at upload time. The orchestrator's signing key (loaded from the embedded public key) is used.

Scenarios created on the filesystem (bypassing the dashboard) must be signed manually using the signing tool before placement in `SCENARIOS_DIR`. See [Signing Infrastructure](signing-infrastructure.md).

---

*© Audspect Engineering — Internal / Confidential*
