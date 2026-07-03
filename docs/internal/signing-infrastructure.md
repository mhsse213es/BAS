# Audspect BAS — Signing Infrastructure

**Classification:** Internal — Audspect Engineering / Confidential  
**Platform Version:** v1.7.3

---

## Overview

Audspect BAS uses two layers of cryptographic signing:

1. **RSA-4096 GPG Signing** — signs scenario YAML files (detached `.sig`) and the agent binary manifest (`BINARIES.sha256`)
2. **SHA-256 Manifest** — the manifest itself is signed with GPG; orchestrator verifies signature and then verifies each binary hash

---

## Current Signing Key

| Attribute | Value |
|---|---|
| Algorithm | RSA-4096 |
| Key ID | (retrieve with `gpg --list-secret-keys`) |
| Expiry | 2029-06-04 |
| Location | Windows build host GPG keyring |
| Passphrase | Unprotected (empty passphrase) on build host |
| Backup | **CRITICAL — must be backed up off the build host** |

**Reminder:** The key expires 2029-06-04. Renew or replace before expiry. Start the renewal process 3 months before expiry.

---

## Backing Up the Signing Key

```powershell
# Export private key (contains the full signing capability)
gpg --export-secret-keys --armor <KEY-ID> > audspect-signing-key-private.asc

# Export public key (safe to distribute; used for verification)
gpg --export --armor <KEY-ID> > audspect-signing-key-public.asc
```

Store `audspect-signing-key-private.asc` in:
- An encrypted offline storage medium (hardware token or encrypted USB)
- A secure vault (HSM-backed or KMS)

**Never commit the private key to git. Never email the private key.**

---

## Signing Scenario Files (Manual)

```powershell
# Sign a single scenario
gpg --detach-sign --armor --output scenarios/my-scenario.yaml.sig scenarios/my-scenario.yaml

# Verify a signature
gpg --verify scenarios/my-scenario.yaml.sig scenarios/my-scenario.yaml
```

In the build pipeline, `windows-build.ps1` Step 0b signs all scenarios automatically.

---

## Signing the Binary Manifest

After building agent binaries:

```powershell
# Compute SHA-256 hashes
Get-FileHash agent\bas-agent.exe -Algorithm SHA256 | ForEach-Object { "$($_.Hash.ToLower())  $($_.Path)" } >> orchestrator\agents\BINARIES.sha256
# (repeat for each agent binary)

# Sign the manifest
gpg --detach-sign --armor `
    --output orchestrator\agents\BINARIES.sha256.sig `
    orchestrator\agents\BINARIES.sha256
```

The orchestrator verifies the manifest signature on startup. If the signature is invalid, binary trust verification is disabled and a startup warning is logged.

---

## How the Orchestrator Verifies Scenarios

At startup (`LoadScenarios()`):

1. For each `*.yaml` file in `SCENARIOS_DIR`:
   - Look for a corresponding `*.yaml.sig` file
   - If no `.sig` file: log warning, mark scenario as unsigned — it cannot be dispatched
   - If `.sig` file present: call `gpg --verify <sig> <yaml>` using the embedded public key
   - If verification fails: mark scenario as "signature invalid" — cannot be dispatched

2. Filesystem watcher (15-second interval):
   - Re-verify signatures for all loaded scenarios
   - If a previously-valid scenario now fails: alert in dashboard, reject dispatch

The public key is embedded in the orchestrator binary at build time. It is not loaded from the filesystem at runtime.

---

## Embedding the Public Key

The public key is embedded in `orchestrator/internal/integrity/signing_key.go`:

```go
package integrity

// signingPublicKey is the Audspect scenario signing public key (RSA-4096).
// This is baked in at compile time — not loaded from disk.
const signingPublicKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----`
```

When rotating keys:
1. Generate the new key
2. Export the new public key
3. Update `signingPublicKey` in `signing_key.go`
4. Re-sign all scenarios with the new private key
5. Re-sign `BINARIES.sha256` with the new private key
6. Build and release

---

## Key Rotation Procedure

**Trigger:** Key expiry approaching (within 3 months) or key compromise.

1. **Generate new key** (on the build host):
   ```
   gpg --full-generate-key
   # Select: RSA and RSA, 4096 bits, 3-year expiry
   ```

2. **Export and back up** (per backup procedure above)

3. **Update `signing_key.go`** with the new public key

4. **Re-sign all scenarios** with the new private key:
   - Run `windows-build.ps1` Step 0b (all scenarios re-signed)

5. **Re-sign `BINARIES.sha256`**:
   - Run `windows-build.ps1` Step 5 (binary build + manifest re-sign)

6. **Build and release** a new orchestrator version that embeds the new public key

7. **Announce rotation** to customer via release notes and upgrade guide

8. **Revoke old key** in the public keyring after the new release is deployed:
   ```
   gpg --gen-revoke <OLD-KEY-ID> > old-key-revocation.asc
   ```

---

## Emergency: Key Compromise

If the signing key is believed compromised:

1. Immediately build and release a new orchestrator version with a new embedded public key
2. All scenarios signed with the old key become unverifiable under the new key — they show "signature invalid" until re-signed
3. Re-sign and re-release all scenarios with the new key
4. Revoke the compromised key
5. Notify all customers to upgrade immediately

This is a rare emergency scenario. All scenario YAML is version-controlled in the git repo; re-signing is a build-pipeline operation and does not require YAML changes.

---

*© Audspect Engineering — Internal / Confidential*
