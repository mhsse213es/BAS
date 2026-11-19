# Scenario inspection: mechanical pass (findings)

Status: **mechanical pass only**. This checks the fields the enterprise plan defines and the cleanup contract. It does **not** judge whether each step really exercises its technique, which needs a per-scenario read. No scenario was edited.

Generated 2026-11-11 from `scenarios/**/*.yaml` on `step-contract-ratchet` (`00202cdb`). Expansion-based files (`art_techniques`, `art_all_platform`, `caldera_*`) get their steps at runtime, so their steps are not inspected here.

## Corrections to the first pass

- The "18 destructive steps not lab-gated" figure is not confirmed. Most of these steps have no `action_key`. The catalog classifies an unknown pair as destructive (fail-closed), so these steps may not be destructive. Each needs a per-step read.
- "No MITRE mapping" applies to the 29 detection profiles only. No scenario file lacks a mapping. The plan's "18 files" figure is out of date.

## Totals

| Check | Files |
|---|---:|
| Files inspected | 156 |
| No MITRE mapping (with steps) | 0 |
| Thin (1-2 steps) | 34 |
| With cleanup gap steps | 6 |
| No detection declared (with steps) | 40 |
| No telemetry declared (with steps) | 39 |
| Destructive steps not lab-gated | 18 |
| Expansion-based (not inspected from YAML) | 16 |
| Zero steps with no expansion (local check) | 1 |

## Detection profiles (29, no steps by design)  (29 files)

| File | Steps | Cleanup % | Detection % | Telemetry % | Flags |
|---|---:|---:|---:|---:|---|
| `detection-profiles/windows_ad_discovery.yaml` | 0 | 0 | 0 | 0 | none |
| `detection-profiles/windows_archive_staging.yaml` | 0 | 0 | 0 | 0 | none |
| `detection-profiles/windows_asrep_roast.yaml` | 0 | 0 | 0 | 0 | none |
| `detection-profiles/windows_backup_service_stop.yaml` | 0 | 0 | 0 | 0 | none |
| `detection-profiles/windows_cloud_egress.yaml` | 0 | 0 | 0 | 0 | none |
| `detection-profiles/windows_credential_access.yaml` | 0 | 0 | 0 | 0 | none |
| `detection-profiles/windows_data_destruction.yaml` | 0 | 0 | 0 | 0 | none |
| `detection-profiles/windows_defender_tampering.yaml` | 0 | 0 | 0 | 0 | none |
| `detection-profiles/windows_dlp_exfiltration.yaml` | 0 | 0 | 0 | 0 | none |
| `detection-profiles/windows_dns_c2.yaml` | 0 | 0 | 0 | 0 | none |
| `detection-profiles/windows_encoded_powershell.yaml` | 0 | 0 | 0 | 0 | none |
| `detection-profiles/windows_file_discovery.yaml` | 0 | 0 | 0 | 0 | none |
| `detection-profiles/windows_kerberoast.yaml` | 0 | 0 | 0 | 0 | none |
| `detection-profiles/windows_log_manipulation.yaml` | 0 | 0 | 0 | 0 | none |
| `detection-profiles/windows_lolbin_download_cradle.yaml` | 0 | 0 | 0 | 0 | none |
| `detection-profiles/windows_malicious_service.yaml` | 0 | 0 | 0 | 0 | none |
| `detection-profiles/windows_netsh_portproxy.yaml` | 0 | 0 | 0 | 0 | none |
| `detection-profiles/windows_network_share_discovery.yaml` | 0 | 0 | 0 | 0 | none |
| `detection-profiles/windows_ransomware_encryption.yaml` | 0 | 0 | 0 | 0 | none |
| `detection-profiles/windows_rdp_nla_posture.yaml` | 0 | 0 | 0 | 0 | none |
| `detection-profiles/windows_runkey_persistence.yaml` | 0 | 0 | 0 | 0 | none |
| `detection-profiles/windows_sam_theft.yaml` | 0 | 0 | 0 | 0 | none |
| `detection-profiles/windows_schtask_persistence.yaml` | 0 | 0 | 0 | 0 | none |
| `detection-profiles/windows_security_process_termination.yaml` | 0 | 0 | 0 | 0 | none |
| `detection-profiles/windows_security_software_discovery.yaml` | 0 | 0 | 0 | 0 | none |
| `detection-profiles/windows_smb_lateral_probe.yaml` | 0 | 0 | 0 | 0 | none |
| `detection-profiles/windows_vss_inhibition.yaml` | 0 | 0 | 0 | 0 | none |
| `detection-profiles/windows_vulnerable_driver_load.yaml` | 0 | 0 | 0 | 0 | none |
| `detection-profiles/windows_webmail_egress.yaml` | 0 | 0 | 0 | 0 | none |

## ad  (10 files)

| File | Steps | Cleanup % | Detection % | Telemetry % | Flags |
|---|---:|---:|---:|---:|---|
| `acl-privilege-exposure-audit.yaml` | 6 | 83 | 83 | 83 | none |
| `adcs-esc-template-exposure-audit.yaml` | 1 | 100 | 100 | 100 | thin (1-2 steps) |
| `dcsync-replication-rights-audit.yaml` | 1 | 100 | 100 | 100 | thin (1-2 steps); 1 destructive step(s) not lab-gated |
| `dcsync-replication-rights-live-verification.yaml` | 2 | 100 | 100 | 100 | thin (1-2 steps) |
| `gpo-writable-linked-exposure-audit.yaml` | 1 | 100 | 100 | 100 | thin (1-2 steps); 1 destructive step(s) not lab-gated |
| `kerberoasting-ad-drill.yaml` | 8 | 100 | 100 | 100 | none |
| `kerberos-delegation-exposure-audit.yaml` | 1 | 100 | 100 | 100 | thin (1-2 steps) |
| `purplesharp-ad-drill.yaml` | 6 | 100 | 100 | 100 | none |
| `rbcd-configure-exposure-audit.yaml` | 1 | 100 | 100 | 100 | thin (1-2 steps) |
| `trust-sid-history-exposure-audit.yaml` | 1 | 100 | 100 | 100 | thin (1-2 steps); 1 destructive step(s) not lab-gated |

## av  (30 files)

| File | Steps | Cleanup % | Detection % | Telemetry % | Flags |
|---|---:|---:|---:|---:|---|
| `appcontrol-efficacy.yaml` | 6 | 100 | 100 | 100 | none |
| `av-ngav-assessment.yaml` | 16 | 100 | 0 | 0 | no detection declared; no telemetry declared; 4 destructive step(s) not lab-gated |
| `credential-access.yaml` | 5 | 100 | 100 | 100 | none |
| `dll-hijack-execution.yaml` | 6 | 17 | 17 | 17 | 3 cleanup gap step(s); 3 destructive step(s) not lab-gated |
| `endpoint-mastery/em-01-control-validation.yaml` | 7 | 100 | 100 | 100 | none |
| `endpoint-mastery/em-02-attack-behavioral-depth.yaml` | 6 | 100 | 100 | 100 | none |
| `endpoint-mastery/em-03-memory-attacks.yaml` | 4 | 75 | 75 | 75 | none |
| `endpoint-mastery/em-04-credential-theft.yaml` | 3 | 100 | 67 | 100 | none |
| `endpoint-mastery/em-05-persistence-validation.yaml` | 2 | 100 | 50 | 100 | thin (1-2 steps) |
| `endpoint-mastery/em-06-defense-evasion.yaml` | 2 | 100 | 50 | 50 | thin (1-2 steps) |
| `endpoint-mastery/em-08-exploit-mitigation.yaml` | 2 | 50 | 0 | 0 | thin (1-2 steps); no detection declared; no telemetry declared |
| `endpoint-mastery/em-09-browser-attack.yaml` | 2 | 50 | 0 | 50 | thin (1-2 steps); no detection declared |
| `evasion-testing.yaml` | 5 | 100 | 100 | 100 | none |
| `exposure-validation.yaml` | 5 | 100 | 100 | 100 | none |
| `linux-credential-access.yaml` | 0 | 0 | 0 | 0 | expansion-based (not inspected from YAML) |
| `linux-defense-evasion.yaml` | 0 | 0 | 0 | 0 | expansion-based (not inspected from YAML) |
| `linux-discovery.yaml` | 0 | 0 | 0 | 0 | expansion-based (not inspected from YAML) |
| `linux-persistence.yaml` | 0 | 0 | 0 | 0 | expansion-based (not inspected from YAML) |
| `linux-privilege-escalation.yaml` | 0 | 0 | 0 | 0 | expansion-based (not inspected from YAML) |
| `lolbin-execution-coverage.yaml` | 21 | 100 | 100 | 100 | 1 destructive step(s) not lab-gated |
| `lolbin-execution.yaml` | 5 | 100 | 100 | 100 | none |
| `lolbin-extended.yaml` | 5 | 100 | 100 | 100 | none |
| `macos-credential-access.yaml` | 0 | 0 | 0 | 0 | expansion-based (not inspected from YAML) |
| `macos-persistence.yaml` | 0 | 0 | 0 | 0 | expansion-based (not inspected from YAML) |
| `windows-credential-protection-posture.yaml` | 4 | 0 | 0 | 0 | non-executable; no detection declared; no telemetry declared |
| `windows-detection-prerequisites-posture.yaml` | 4 | 0 | 0 | 0 | non-executable; no detection declared; no telemetry declared |
| `windows-discovery-validation.yaml` | 3 | 100 | 100 | 100 | none |
| `windows-discovery.yaml` | 0 | 0 | 0 | 0 | expansion-based (not inspected from YAML) |
| `windows-execution-control-posture.yaml` | 3 | 0 | 0 | 0 | non-executable; no detection declared; no telemetry declared |
| `windows-persistence-posture.yaml` | 4 | 0 | 0 | 0 | non-executable; no detection declared; no telemetry declared |

## cloud  (2 files)

| File | Steps | Cleanup % | Detection % | Telemetry % | Flags |
|---|---:|---:|---:|---:|---|
| `cloud-vm-attack.yaml` | 5 | 100 | 100 | 100 | none |
| `entra-hybrid-identity-attack.yaml` | 6 | 67 | 67 | 67 | none |

## common  (25 files)

| File | Steps | Cleanup % | Detection % | Telemetry % | Flags |
|---|---:|---:|---:|---:|---|
| `art-full-darwin.yaml` | 0 | 0 | 0 | 0 | expansion-based (not inspected from YAML) |
| `art-full-linux.yaml` | 0 | 0 | 0 | 0 | expansion-based (not inspected from YAML) |
| `art-full-windows.yaml` | 0 | 0 | 0 | 0 | expansion-based (not inspected from YAML) |
| `art-selective-darwin.yaml` | 0 | 0 | 0 | 0 | expansion-based (not inspected from YAML) |
| `art-selective-linux.yaml` | 0 | 0 | 0 | 0 | expansion-based (not inspected from YAML) |
| `art-selective-windows.yaml` | 0 | 0 | 0 | 0 | expansion-based (not inspected from YAML) |
| `caldera-full-windows.yaml` | 0 | 0 | 0 | 0 | expansion-based (not inspected from YAML) |
| `caldera-lateral-movement.yaml` | 5 | 0 | 0 | 0 | no detection declared; no telemetry declared |
| `cis-ubuntu-l1.yaml` | 38 | 0 | 0 | 0 | non-executable; no detection declared; no telemetry declared |
| `cscrf-mii-drill.yaml` | 9 | 100 | 100 | 100 | none |
| `endpoint-mastery/em-11-hardening-validation.yaml` | 2 | 50 | 0 | 0 | thin (1-2 steps); no detection declared; no telemetry declared |
| `endpoint-mastery/em-13-product-validation.yaml` | 1 | 100 | 0 | 0 | thin (1-2 steps); no detection declared; no telemetry declared |
| `endpoint-mastery/em-14-continuous-validation.yaml` | 1 | 100 | 0 | 0 | thin (1-2 steps); no detection declared; no telemetry declared |
| `full-scan.yaml` | 25 | 0 | 0 | 0 | non-executable; no detection declared; no telemetry declared |
| `linux-account-privilege-posture.yaml` | 3 | 0 | 0 | 0 | non-executable; no detection declared; no telemetry declared |
| `linux-audit-logging-posture.yaml` | 2 | 0 | 0 | 0 | non-executable; thin (1-2 steps); no detection declared; no telemetry declared |
| `linux-installed-software.yaml` | 1 | 0 | 0 | 0 | non-executable; thin (1-2 steps); no detection declared; no telemetry declared |
| `linux-patch-posture.yaml` | 2 | 0 | 0 | 0 | non-executable; thin (1-2 steps); no detection declared; no telemetry declared |
| `linux-ssh-hardening-posture.yaml` | 4 | 0 | 0 | 0 | non-executable; no detection declared; no telemetry declared |
| `rbi-cscf-drill.yaml` | 9 | 0 | 0 | 0 | non-executable; no detection declared; no telemetry declared |
| `safe-simulation.yaml` | 0 | 0 | 0 | 0 | local check (`local_check: true`), no YAML steps; behaviour is in agent code, not inspected here |
| `ubuntu-hardening-validation.yaml` | 28 | 29 | 29 | 29 | 17 cleanup gap step(s); 17 destructive step(s) not lab-gated |
| `windows-installed-software.yaml` | 1 | 0 | 0 | 0 | non-executable; thin (1-2 steps); no detection declared; no telemetry declared |
| `windows-patch-posture.yaml` | 1 | 0 | 0 | 0 | non-executable; thin (1-2 steps); no detection declared; no telemetry declared |
| `windows-security-config.yaml` | 10 | 0 | 0 | 0 | non-executable; no detection declared; no telemetry declared |

## dbsim  (11 files)

| File | Steps | Cleanup % | Detection % | Telemetry % | Flags |
|---|---:|---:|---:|---:|---|
| `dbsim-db01-auth-policy.yaml` | 2 | 100 | 0 | 0 | thin (1-2 steps); no detection declared; no telemetry declared |
| `dbsim-db02-excessive-grants.yaml` | 2 | 100 | 0 | 0 | thin (1-2 steps); no detection declared; no telemetry declared |
| `dbsim-db03-unauthorized-access.yaml` | 1 | 100 | 0 | 0 | thin (1-2 steps); no detection declared; no telemetry declared; 1 destructive step(s) not lab-gated |
| `dbsim-db04-audit-coverage.yaml` | 2 | 100 | 0 | 0 | thin (1-2 steps); no detection declared; no telemetry declared |
| `dbsim-db05-suspicious-read.yaml` | 1 | 100 | 0 | 0 | thin (1-2 steps); no detection declared; no telemetry declared; 1 destructive step(s) not lab-gated |
| `dbsim-db06-account-revocation.yaml` | 1 | 100 | 0 | 0 | thin (1-2 steps); no detection declared; no telemetry declared |
| `dbsim-db07-sensitive-classification.yaml` | 1 | 100 | 0 | 0 | thin (1-2 steps); no detection declared; no telemetry declared; 1 destructive step(s) not lab-gated |
| `dbsim-db08-audit-tamper-resistance.yaml` | 1 | 100 | 0 | 0 | thin (1-2 steps); no detection declared; no telemetry declared |
| `dbsim-db09-bounded-bulk-read.yaml` | 1 | 100 | 0 | 0 | thin (1-2 steps); no detection declared; no telemetry declared; 1 destructive step(s) not lab-gated |
| `dbsim-db10-write-delete-prevention.yaml` | 1 | 100 | 0 | 0 | thin (1-2 steps); no detection declared; no telemetry declared |
| `dbsim-db11-backup-export-permissions.yaml` | 1 | 100 | 0 | 0 | thin (1-2 steps); no detection declared; no telemetry declared; 1 destructive step(s) not lab-gated |

## dlp  (17 files)

| File | Steps | Cleanup % | Detection % | Telemetry % | Flags |
|---|---:|---:|---:|---:|---|
| `collection-staging-exfil.yaml` | 10 | 100 | 100 | 100 | none |
| `dlp-exfiltration-ai-prompt.yaml` | 4 | 100 | 100 | 100 | none |
| `dlp-exfiltration-browser-upload.yaml` | 1 | 100 | 100 | 100 | thin (1-2 steps) |
| `dlp-exfiltration-cloud-storage.yaml` | 11 | 100 | 100 | 100 | none |
| `dlp-exfiltration-coderepo.yaml` | 6 | 100 | 100 | 100 | none |
| `dlp-exfiltration-data-types.yaml` | 7 | 100 | 100 | 100 | none |
| `dlp-exfiltration-db-export.yaml` | 4 | 100 | 100 | 100 | none |
| `dlp-exfiltration-dns-tunnel.yaml` | 4 | 100 | 100 | 100 | none |
| `dlp-exfiltration-file-carriers.yaml` | 7 | 100 | 100 | 100 | none |
| `dlp-exfiltration-multichannel.yaml` | 9 | 100 | 100 | 100 | none |
| `dlp-exfiltration-sftp.yaml` | 6 | 100 | 100 | 100 | none |
| `dlp-exfiltration-sink-https.yaml` | 6 | 100 | 100 | 100 | none |
| `dlp-exfiltration-smtp.yaml` | 6 | 100 | 100 | 100 | none |
| `dlp-exfiltration-telnet.yaml` | 4 | 100 | 100 | 100 | none |
| `dlp-exfiltration-validation.yaml` | 5 | 100 | 100 | 100 | none |
| `dlp-exfiltration-webhook.yaml` | 5 | 100 | 100 | 100 | none |
| `endpoint-mastery/em-10-endpoint-exfiltration.yaml` | 1 | 100 | 100 | 100 | thin (1-2 steps) |

## email  (1 files)

| File | Steps | Cleanup % | Detection % | Telemetry % | Flags |
|---|---:|---:|---:|---:|---|
| `outlook-rules-bec.yaml` | 5 | 0 | 0 | 0 | 5 cleanup gap step(s); no detection declared; no telemetry declared; 5 destructive step(s) not lab-gated |

## killchain  (14 files)

| File | Steps | Cleanup % | Detection % | Telemetry % | Flags |
|---|---:|---:|---:|---:|---|
| `apt29-kill-chain.yaml` | 5 | 100 | 100 | 100 | none |
| `apt36-kill-chain.yaml` | 10 | 100 | 100 | 100 | none |
| `carbanak-kill-chain.yaml` | 8 | 100 | 100 | 100 | 1 destructive step(s) not lab-gated |
| `cobalt-group-kill-chain.yaml` | 8 | 100 | 100 | 100 | none |
| `endpoint-mastery/em-12-adversary-emulation.yaml` | 1 | 100 | 100 | 100 | thin (1-2 steps) |
| `fin7-kill-chain.yaml` | 5 | 100 | 100 | 100 | none |
| `fin8-kill-chain.yaml` | 9 | 100 | 100 | 100 | 1 destructive step(s) not lab-gated |
| `insider-threat-kill-chain.yaml` | 3 | 100 | 100 | 100 | none |
| `lazarus-swift-heist.yaml` | 9 | 22 | 22 | 22 | none |
| `scattered-spider-kill-chain.yaml` | 5 | 100 | 100 | 100 | none |
| `silence-kill-chain.yaml` | 8 | 100 | 100 | 100 | none |
| `ta505-kill-chain.yaml` | 9 | 100 | 100 | 100 | none |
| `upi-fraud-killchain.yaml` | 9 | 100 | 100 | 100 | none |
| `volt-typhoon-lotl.yaml` | 10 | 100 | 100 | 100 | none |

## network  (3 files)

| File | Steps | Cleanup % | Detection % | Telemetry % | Flags |
|---|---:|---:|---:|---:|---|
| `linux-lateral-movement.yaml` | 0 | 0 | 0 | 0 | expansion-based (not inspected from YAML) |
| `linux-network-kernel-exposure-posture.yaml` | 4 | 0 | 0 | 0 | non-executable; no detection declared; no telemetry declared |
| `windows-east-west-host-firewall-posture.yaml` | 1 | 0 | 0 | 0 | non-executable; thin (1-2 steps); no detection declared; no telemetry declared |

## ransomware  (14 files)

| File | Steps | Cleanup % | Detection % | Telemetry % | Flags |
|---|---:|---:|---:|---:|---|
| `akira-kill-chain.yaml` | 16 | 94 | 100 | 100 | none |
| `black-basta-kill-chain.yaml` | 10 | 90 | 100 | 100 | none |
| `blackcat-kill-chain.yaml` | 8 | 100 | 100 | 100 | none |
| `clop-kill-chain.yaml` | 5 | 100 | 100 | 100 | none |
| `endpoint-mastery/em-07-ransomware-readiness.yaml` | 10 | 80 | 100 | 100 | none |
| `hunters-international-kill-chain.yaml` | 9 | 0 | 0 | 0 | 5 cleanup gap step(s); no detection declared; no telemetry declared; 5 destructive step(s) not lab-gated |
| `linux-ransomware-drill.yaml` | 4 | 75 | 100 | 100 | none |
| `lockbit-kill-chain.yaml` | 5 | 100 | 100 | 100 | none |
| `medusa-kill-chain.yaml` | 10 | 0 | 0 | 0 | 4 cleanup gap step(s); no detection declared; no telemetry declared; 4 destructive step(s) not lab-gated |
| `play-kill-chain.yaml` | 8 | 100 | 100 | 100 | none |
| `ransomhub-kill-chain.yaml` | 8 | 100 | 100 | 100 | none |
| `ransomware-drill.yaml` | 9 | 89 | 100 | 100 | none |
| `rhysida-kill-chain.yaml` | 11 | 0 | 0 | 0 | 3 cleanup gap step(s); no detection declared; no telemetry declared; 2 destructive step(s) not lab-gated |
| `windows-backup-posture.yaml` | 3 | 0 | 0 | 0 | non-executable; no detection declared; no telemetry declared |

## Expansion-based scenarios (measured at ART pin a0e3f9bc, read-only)

Method: the ART library was fetched at the pinned commit. For each expansion file, the test set was derived from the engine's own rules (`builder.go`: `art_all_*` and `art_selective_*` build the same full-platform sweep; `art_techniques` builds the listed techniques). Counts are approximate for the platform filter. Caldera files could not be measured offline (they need a live Caldera server).

| File | Generated | Tests | Techniques | Tests with cleanup_command at pin |
|---|---|---:|---:|---:|
| `art-full-windows.yaml` | full Windows sweep | 1331 | 282 | 758 (57%) |
| `art-selective-windows.yaml` | same full Windows sweep (the "selective" name only changes the UI picker) | ~1331 | ~282 | ~758 (57%) |
| `art-full-linux.yaml` | full Linux sweep | 435 | 122 | 259 (60%) |
| `art-selective-linux.yaml` | same full Linux sweep | ~435 | ~122 | ~259 (60%) |
| `art-full-darwin.yaml` | full macOS sweep | 267 | 108 | 141 (53%) |
| `art-selective-darwin.yaml` | same full macOS sweep | ~267 | ~108 | ~141 (53%) |
| `linux-discovery.yaml` | `art_techniques` (8 techniques) | 136 | 8 | 21 (15%) |
| `windows-discovery.yaml` | `art_techniques` (16 techniques) | 196 | 16 | 26 (13%) |
| `linux-credential-access.yaml` | `art_techniques` | 83 | 6 | 54 (65%) |
| `linux-defense-evasion.yaml` | `art_techniques` | 28 | 3 | 14 (50%) |
| `linux-lateral-movement.yaml` | `art_techniques` | 60 | 4 | 36 (60%) |
| `linux-persistence.yaml` | `art_techniques` | 29 | 5 | 26 (90%) |
| `linux-privilege-escalation.yaml` | `art_techniques` | 19 | 3 | 11 (58%) |
| `macos-credential-access.yaml` | `art_techniques` | 86 | 6 | 55 (64%) |
| `macos-persistence.yaml` | `art_techniques` | 15 | 4 | 15 (100%) |

Findings from this measurement:
- **No per-test safety filter in the sweep.** `art.go` filters only by platform, argument defaults and payloads. ART-materialised steps carry no `production_safe` or `fidelity` value (`art.go:624-665` sets neither).
- **Live gate is only an acknowledgement.** `livegates.go:27-37` requires `confirmLive=true` for telemetry and lab modes, plus `confirmLab` for lab mode. It does not check whether a step is destructive. A telemetry-mode run of `art-full-windows` (1331 tests) can therefore run any Windows atomic after one confirmation. The agent side was not read, so whether it refuses any test is unverified.
- **The "selective" files are not selective.** `art-selective-*` run the full sweep. Their name and description would mislead a buyer.
- **Cleanup coverage in the sweeps is 53–60%.** About 40–47% of generated tests have no cleanup_command at the pin. Under the contract, these are gaps, not declared undos.
- **`linux-discovery` and `windows-discovery` have the lowest cleanup (15%, 13%).** Discovery is mostly read-only, so most of these are likely non-destructive. That still needs a per-technique check.

Not measured: Caldera-expansion files (live server needed), and whether each generated test does what its name says.

## safe-simulation (verified from code)

- Posture mode (the default) does not run YAML steps. `handlers.go:2365-2390` sends a `MsgCommandSimulate` to the agent with `scenarioId=safe-simulation`. The agent runs built-in Go checks: `agent/simulate_linux.go` `safeSimChecks()`, plus the Windows and macOS equivalents (not read in this pass).
- The Linux list is about 30 read-only checks across credential access, defence evasion, execution, persistence, privilege escalation, network controls, monitoring and account security. Each check reads a config value (for example `sshConfigValue("PermitRootLogin")`) and returns `pass`, `fail` or `skipped`.
- **Scoring:** the orchestrator takes the agent's `result` as reported (`handlers.go:3262-3275`). It does not re-score it.
- **Caveat 1, unreadable state reads as "not set":** `checkSSHRootLogin` returns `fail` when the value is empty. A missing or unreadable `sshd_config` therefore reads as a failed control, not as "could not check." The check does not return `skipped` in this case.
- **Caveat 2, scope of the claim:** the check list is a "representative subset" by its own comment, not the full CIS benchmark. The description calls it "read-only security posture simulation" that "predicts whether real attacks would be blocked." It does not test whether an attack would be blocked. It reads configuration. The claim should say so.
- **Not verified:** the Windows and macOS versions, a live run on an agent, and whether any `skipped` result is ever produced and scored correctly.

## Endpoint-mastery and detection-profiles: subagent report (UNVERIFIED except where marked)

Source: read-only subagent over 42 files (25 detection profiles, 14 endpoint-mastery, 3 profiles with issues). All 42 parsed as YAML. The subagent could not write this as a file, so its report is recorded here as text. Nothing below has been edited in the repo.

**Verified by me:** `interpreter.go` `dominantVerdict` (lines 321–346) matches `PASS:`, `FAIL:` and `SKIP:` only at the start of a trimmed line. A line such as `EXEC: ... FAIL:` never counts. With no token, `interpretCustom` returns PASS on exit 0. So the subagent's first two findings are mechanically correct.

**Not verified:** every other claim below. Line numbers and wording come from the subagent. Some may refer to the em-07 file before my earlier change to steps 4A and 4B.

High severity, as reported:
1. em-07 steps 1A, 1B, 2A, 2B, 5A print `EXEC:` with no verdict token, so exit 0 scores PASS regardless of control reaction. (Verified mechanism.)
2. em-07 step 5A puts `FAIL:` mid-line, so it cannot match. A successful stop of wbengine or VSS scores PASS.
3. em-07 steps 4A, 4B, 4C, 5A are destructive when unblocked (`vssadmin delete shadows`, `wbadmin delete catalog`, `bcdedit recoveryenabled no`, `net stop`). 4A and 4B have since been replaced by read-only checks. 4C and 5A are still destructive. There is no BAS_CONFIRM gate, and no code enforces `production_safe`.
4. em-03 step index 3 is truncated after `requires_priv: admin`. It has no executor, command, cleanup or blast_radius.
5. em-04 step 2 (DPAPI) inverts the verdict. Readable master keys print PASS. Line 110 has a typo, `-Recurced`, so PASS can't be reached.
6. em-06 steps 0 and 1 print PASS when a loopback port is closed, so the verdict depends on a closed port and not on a control. FAIL cannot be reached.
7. em-10 step 0 prints PASS on any DNS exception, including normal NXDOMAIN. This is a systematic false PASS.
8. em-14 step 0: the file says FAIL at significant drift, but the code fails only at 40% or more. A 20% gap prints PASS.
9. em-12 step 0 prints PASS on a non-zero exit, so it always passes on non-domain hosts.
10. em-02 steps 0 and 5 print PASS when the process launch fails or times out.

Medium and low items, abridged:
- Detection profiles `windows_archive_staging` (`archive-dlp-sensitive`) and `windows_sam_theft` (`sam-siem-hive-write`) have entries with no finding block.
- Seven profile names cited by other scenarios have no file in `detection-profiles/`: `windows_dcsync_replication`, `windows_wmi_persistence`, `windows_recovery_inhibition`, `windows_lsass_access`, `windows_forensic_evasion`, `windows_event_log_tampering`, `windows_backup_tampering`. Needs a separate check.
- em-01: WDAC audit mode is treated as enforced.
- em-03 cleanup kills every empty-title notepad on the host.
- em-05 description claims Scheduled Task changes that no step performs.
- em-08 DEP enum comment may be wrong (1 = AlwaysOn, 2 = OptIn per Microsoft docs; to verify). SEHOP is claimed with no step.
- em-11 and em-13 descriptions claim coverage that no step has.
- All 14 endpoint-mastery files contain `[cite: N]` artefacts in descriptions, strings or blast_radius.

## DLP, database and AD group: subagent report (UNVERIFIED except where marked)

Source: read-only subagent over 37 files (4 DLP files with issues, 11 DLP and 11 DB files OK, 10 AD files with issues, plus kerberos-delegation OK). Recorded as text. Nothing was edited.

**Verified by me:** `dlp-exfiltration-validation.yaml` lines 172–186. The print-job filter is `DocumentName -match 'bas_sim_dlp_print' -or JobStatus -match 'Printing|Spooling|Normal'` with `Select-Object -First 1`. `Remove-PrintJob` then deletes that job. The step is `production_safe: true`. An ordinary user's print job can be matched and deleted on a production host. **Highest-priority fix in this group, not yet approved.** The same pattern appears in `dlp-exfiltration-multichannel.yaml` (per the report).

High severity, as reported (unverified):
1. `collection-staging-exfil.yaml` steps 5 and 6 (HTTP POST and DNS to `.invalid`): both branches print FAIL, so a blocked egress can never PASS.
2. `collection-staging-exfil.yaml` steps 7 and 8 (FTP and WebDAV to `.invalid`): the host can't resolve it, so the step prints PASS "blocked or unreachable" without the control being exercised.
3. `collection-staging-exfil.yaml` step 4 and `dlp-exfiltration-file-carriers.yaml` step 7: `& $sevenZip.Source` runs `$null` when 7-Zip is off PATH, which prints PASS.
4. `dcsync-replication-rights-live-verification.yaml`: SKIP lines print as "SKIP T1003.006:" with no colon, so they grade PASS on exit 0. The negative control prints no token and grades PASS.
5. `dcsync-replication-rights-audit.yaml` step 0: counts only replication ACEs. GenericAll, AllExtendedRights and WriteDacl holders get PASS.
6. `purplesharp-ad-drill.yaml` step 2 (LSASS read handle): success prints EXEC with no FAIL token, so exit 0 grades PASS. Inverted verdict.
7. `dlp-exfiltration-validation.yaml` and `dlp-exfiltration-multichannel.yaml` print-spool steps: verified above.
8. `adcs-esc-template-exposure-audit.yaml`: ESC10 is only a comment. ESC6 and ESC8 are out of scope, yet the PASS claims ESC1–15 coverage. ESC9 uses flag 0x400000, and the subagent believes NO_SECURITY_EXTENSION is 0x00080000 (to verify against MS-CRTD). ESC7 never tests ManageCA or ManageCertificates, and the block is inside `catch{}`.

Medium items, abridged:
- Several DLP steps credit any generic exception as OperationBlocked (`dlp-exfiltration-data-types` steps 0–6, `dlp-exfiltration-file-carriers`, multichannel, validation). Tool failure then reads as a control success.
- `rbcd-configure-exposure-audit`: an unreadable MachineAccountQuota becomes 0 and PASSes, and quota 0 suppresses FAIL even when writable computers exist.
- `trust-sid-history-exposure-audit`: the QUARANTINE bit is treated as SID-filtering control, and external (non-forest) trusts are never evaluated.
- `kerberoasting-ad-drill`: LAPS not deployed (total 0) gives PASS "local admin passwords are protected".
- `collection-staging-exfil` cleanups `Remove-Item bas_exfil_*` can delete other concurrent runs' directories.
- Stray citation markers (`[citation:N]`) in `acl-privilege-exposure-audit` and `kerberoasting-ad-drill`.
- `purplesharp-ad-drill` LSASS read step is `production_safe: true` although it opens VM_READ on lsass.

OK files (one line each): `dlp-exfiltration-ai-prompt`, `-browser-upload`, `-cloud-storage`, `-coderepo`, `-db-export`, `-dns-tunnel`, `-sftp`, `-sink-https`, `-smtp`, `-telnet`, `-webhook`, `kerberos-delegation-exposure-audit`, and the 11 `dbsim-db01`–`db11` files. Low notes include the SMTP step labelling network as Sysmon EID 1 (should be EID 3), and `Send-MailMessage` being deprecated.

## Changes applied (approved, file by file)

1. `outlook-rules-bec.yaml`: detection and telemetry added (marked expected, not verified). Stage 1 `production_safe: true`; Stages 2–5 `production_safe: false`, `fidelity: lab-only`. Safety note added. Re-signed.
2. `dlp-exfiltration-validation.yaml` print step (T1052): the job filter now matches only this run's document name (`*bas_sim_dlp_print_<runId>*`), with no status-based fallback. The step deletes nothing unless that job is found. "Not found" and "error" now SKIP and are not scored (previously both were credited as OperationBlocked). `production_safe: false`, `fidelity: lab-only`. Re-signed. NOT VERIFIED on a lab printer: whether Windows records the document name this way.

Still open in this file: the USB, clipboard and archive steps are `production_safe: true` and change host state (per the subagent report). Not yet approved for change.

## Common and cloud group: subagent report (UNVERIFIED; nothing edited)

Source: read-only subagent over 28 files. OK: `caldera-full-windows`, `linux-account-privilege-posture`, `linux-network-kernel-exposure-posture`, `linux-ssh-hardening-posture`. 24 files have issues. Recorded as text.

High severity, as reported:
1. `ubuntu-hardening-validation` step 21 (`/proc/1/mem`): `dd skip=0` reads virtual address 0, which fails with EIO whatever the permission. The PASS branch always runs, so the test cannot FAIL.
2. `cis-ubuntu-l1`: Telnet, rsh and TFTP steps end in `|| echo`, which forces exit 0 and PASS (Telnet is inverted when installed). The sudo-logging step and the /tmp noexec/nosuid/nodev steps have the same problems. The /tmp steps run an identical grep that never checks the options.
3. `cscrf-mii-drill` step 8 (audit-log tamper): when the flag is on, the step runs `wevtutil cl Security`, which clears the Security log, and scores PASS. It is declared `reversible: true`, which is false for a log clear. When the flag is off, the output claims a process was started, but `Start()` is never called.
4. `cloud-vm-attack` step 4 prints FAIL unconditionally after an AWS call, so any AWS error still scores FAIL.
5. `linux-patch-posture` step 1: with no updates it yields "0\n0", which errors and prints FAIL on a fully patched host.
6. `full-scan` steps 15–17 (Run key, Startup folder, non-system services) print PASS on every path.
7. `caldera-lateral-movement`: no PASS/FAIL tokens in any step, so everything scores by exit code. Step 2 is named "Remote service creation" but only runs `sc.exe query`. Step 1 is localhost enumeration, not lateral movement.
8. Steps with fidelity omitted run in both telemetry and lab modes (`types.go:181`). This covers `entra-hybrid` steps 3–4 (credential theft), all five `outlook-rules-bec` steps (the file was fixed earlier, but the subagent read it before my change), and some ubuntu ART steps. `cscrf-mii-drill` steps 6, 8 and 9 have no `action_key` and resolve to `enumerate`.
9. `windows-east-west-host-firewall-posture` step 1 uses an exact string match on LocalPort, so an allow-any-port rule passes.
10. `ubuntu-hardening-validation` step 23 restarts auditd in cleanup even when it was stopped on purpose. Step 26's cleanup `losetup -D` detaches all loop devices system-wide.
11. `cscrf-mii-drill` promises an eight-category posture tier that does not exist.
12. `safe-simulation` has no steps (already recorded).

Notes: the subagent reasoned about `/proc` and `cloud` semantics without running them, so items 1 and 4 are unverified. Item 8 about the Outlook file predates my change.

## AV/NGAV group: subagent report (UNVERIFIED; nothing edited)

Source: read-only subagent over 22 files. Every file has findings, so 0 of 22 are OK. The subagent used the step-contract worktree's `interpreter.go` for verdict logic, not main, so re-check against main before acting.

Engine facts the subagent relied on: `dominantVerdict` (lines 331–336) matches only exact lowercase `fail:`, `skip:` and `pass:` prefixes. `interpretCustom` (lines 269–290) scores exit 0 with no token as PASS. A non-zero exit with "blocked" or "access denied" in the output is PASS. Other non-zero exits are FAIL. So any step that prints EXEC, INFO or WARN and exits 0 scores PASS, which means many successful attacks score PASS.

High severity, as reported:
1. `exposure-validation.yaml` steps 2–5: critical findings print `FAIL (CRITICAL):`, which the engine ignores. No PASS line is printed on those paths, so critical findings score PASS.
2. `credential-access.yaml` step 5: an absent `LmCompatibilityLevel` prints WARN with no token and scores PASS. The file says absent should count as vulnerable.
3. `lolbin-extended.yaml` (all five steps): success prints EXEC with no token, so the file cannot produce FAIL. Step 2 (Regasm) leaves an HKCR COM registration behind, and its cleanup only removes temp files.
4. `windows-discovery-validation.yaml`: no step emits FAIL or SKIP. Step 2 prints "skipped" without the `SKIP:` prefix, so a non-domain host scores PASS. Step 3's gateway regex does not match standard `ipconfig` output, so the step passes without running anything.
5. `dll-hijack-execution.yaml` step 3: if csc is missing it prints PASS. The planted binary is never invoked. FAIL is printed on staging regardless of whether EDR detects anything.
6. `evasion-testing.yaml` step 5 (AMSI): it sets `amsiInitFailed` in the live session and resets it only afterwards. An exception in between leaves AMSI disabled. The file says "No disabling of AV" and marks the step `production_safe: true`. The field-not-found and exception paths print PASS.
7. `evasion-testing.yaml` step 4: any non-EXEC result, including an OS access denial, prints PASS "EDR kernel callback detected ancestry manipulation" with no evidence.
8. `av-ngav-assessment.yaml`: exit 0 equals PASS across 15 steps, and step 7 uses the inverted convention. Step 16 loops for 60 s against a 30 s timeout. Step 10 uses an undefined host, `avtest-host.local`.

Other high items: most of `lolbin-execution-coverage` (steps 6–21) prints EXEC with no token. Its step 18 fetches a remote scriptlet from `$env:BAS_C2_URI`, which the blast radius omits. Its step 20 passes a wildcard cleanup to `sc.exe`. `lolbin-execution` steps 3 and 4 always PASS, and its description claims a posture mode and a lab gate that don't exist. `windows-persistence-posture` step 1 passes on partial enumeration, against the contract's SKIP rule.

Caveats the subagent gave: the `sc.exe` and `schtasks` wildcard behaviour, the `LocalSystem` default, and Sysmon event IDs are general knowledge, not checked on a target. The ipconfig regex point comes from reading the pattern, not a live run. The AMSI marker and ASR GUID are not checked against Microsoft's documented values.

## Changes applied (approved): dlp-exfiltration-multichannel.yaml

- Description: SAFETY note added (clipboard overwrite; text-only restore; lab endpoint only).
- USB step: the copy uses `-ErrorAction Stop`. A copy error prints SKIP and is not scored. Only a clean copy with no file afterwards counts as blocked. `fidelity: lab-only`, `production_safe: false`.
- Clipboard step: an unreadable clipboard prints SKIP and restores the original text. `fidelity: lab-only`, `production_safe: false`.
- Print step: matches only this run's document name, deletes only that job, and prints SKIP when the job is missing or the submission fails. `fidelity: lab-only`, `production_safe: false`.
- Re-signed; signatures verified; contract tests run.
- NOT VERIFIED on a lab host: the printer job name, the USB block signature for a real DLP product, and the clipboard behaviour.
- Left unchanged, per approval: the archive, shared-path, HTTPS, DNS, SFTP and SMTP steps.

## Ransomware and kill-chain group: subagent report (UNVERIFIED; nothing edited)

Source: read-only subagent over 26 files. 0 OK, 26 with issues. Recorded as text.

High severity, as reported:
1. `linux-ransomware-drill` step 2 and `ransomware-drill` step 4 (rename probe): a successful `.bas_locked` rename prints EXEC with no token, so it scores PASS. Inverted.
2. `linux-ransomware-drill` step 3 and `ransomware-drill` step 5 (XOR simulation): EXEC and CLEANUP lines only, so PASS whether or not encryption happened.
3. `hunters-international`, `medusa` and `rhysida`: no step has a `command` field. `builder.go:327-329` turns each into SKIP, so these chains validate nothing.
4. `rhysida` step 8 and `medusa` step 8: destructive `vssadmin delete shadows /all` and `sc.exe stop` text in details, with no env-var gate and no executable command. `rhysida` SILENTKILL steps 4–6 use `enumerate` on defence-disabling actions.
5. `clop` step 1 (`taskkill /F /IM`): non-terminating errors leave `$spawned=$true`, so a blocked spawn prints FAIL. Inverted.
6. Unconditional FAIL with no PASS path: `apt29` 0, `fin7` 1, `blackcat` 0, `cobalt` 3 and 6, `fin8` 2, `silence` 7, `ta505` 7, `upi` 6, `volt` 1/3/6, `ransomware-drill` 6.
7. Stub steps that print a string but never run the control: `akira` 4, `black-basta` 2, `ransomhub` 3, `ransomware-drill` 1 (`Add-MpPreference` is never run). `akira` 3 prints PASS when the LSASS handle is granted.
8. `production_safe: true` on steps that copy SAM and SYSTEM hives: `akira` 2, `blackcat` 2, `ransomhub` 2, `volt` 4. Their blast radius wrongly says SAM is unusable without the bootkey.

Other notable items: EID 1102 is claimed for custom-log clears (knowledge-based; not verified). `Out-String -match` is misused in `insider`, `apt29` and `scattered-spider`. `volt-typhoon` step 7 cleanup runs `Stop-Process -Force` on every windowless `mshta` or `rundll32` on the host. Many steps lack an `action_key`, and some have the wrong one.

Cannot verify from YAML: ART-expanded steps, locale-dependent output, unknown `depends_on` IDs in `akira`, and em-dash encoding under PS 5.1.

## Changes applied (approved): ransomware-drill.yaml

Worktree branch `step-contract-ratchet`. Only the three approved steps changed (diff against the pre-change copy confirmed no other step changed).

- Rename probe (`Benign File Rename Probe`): a successful rename prints FAIL. A blocked rename (original still present, renamed copy absent) prints PASS. If the probe file can't be created, it prints SKIP. If neither file exists afterwards, it prints SKIP. Any leftover renamed copy is removed.
- XOR encryption simulation (lab-only): wrapped in try/catch. Encryption that ran prints FAIL. Access denied before any file was encrypted prints PASS. Any other exception prints SKIP. The synthetic files, the lab gate and the restoration are unchanged.
- Defender check: replaced the stub (`$cmdLine` was built but never run) with a read-only `Get-MpPreference` exclusion check. TEMP excluded prints FAIL. Not excluded prints PASS. Unreadable preferences print SKIP. The false EID 4104/4688 claims are removed. The step name and blast radius now say it checks configuration state only, and do not test whether Defender logs an exclusion change. No `Add-MpPreference` in this change.
- Test pin: `engine_test.go` line 891 now names the renamed Defender step, so the detection-profile wiring test still checks the same profile.
- Unchanged, as directed: VSS enumeration (EXEC-only PASS, held for a scoring-correction change), VSS deletion, Defender real-time protection, service probe.
- Signed (release key); `verify-all` ok=156 fail=0. All three command blocks parse as PowerShell (`Parser.ParseFile`).
- NOT VERIFIED on a lab host: all three probes.
- Same stub pattern is still present in other scenarios (akira, ransomhub, em-07); those files are not changed.

## Changes applied (approved): akira-kill-chain.yaml (3 steps)

See `docs/scenario-step-contract-qa-log.md`, section "2026-11-12: Akira kill chain". Summary: Stage 3 is lab-only, not production-safe, with corrected exposure text. Stage 3b is changed to a PROCESS_VM_READ handle check with a real verdict, lab-only. Stage 4 is a read-only Defender configuration check. Signed; the three commands parse; the contract, scenario and related API tests pass; NOT VERIFIED on a lab host. Other Akira stages not changed.
