# Audspect BAS Platform — Delivery Verification Guide

This guide lets your security team independently verify that the bundle you
received is authentic, unmodified, and cryptographically trusted — before and
after installation. Follow the three layers in order.

Everything here is verifiable with standard tools already on your server
(`gpg`, `sha256sum`). No internet access is required.

---

## Layer 1 — Authenticate the bundle (before you unzip)

The whole `bas-install-<version>.zip` is signed with the Audspect release key
(GPG, RSA-4096). This proves the zip came from Audspect and was not altered in
transit. These three files are delivered **alongside** the zip:

- `bas-install-<version>.zip.asc` — detached signature
- `pubkey.asc` — the Audspect public signing key
- `verify-sig.sh` — the verifier

Run, from the delivery directory:

```bash
bash verify-sig.sh bas-install-<version>.zip
```

Expected result: `Signature valid`. Exit code `0`.

You can pin trust to the correct key by confirming its fingerprint:

```bash
gpg --show-keys pubkey.asc
# Expect fingerprint: D8B7 F958 1EAD 6202 6F57  A17E 7B6F 1A54 1AF7 E0F5
# Identity: Audspect BAS Platform (BAS Release Signing Key) <releases@audspect.com>
```

**If this step fails, stop.** Do not unzip or install. Contact Audspect — the
file may be corrupted or tampered with.

---

## Layer 2 — Verify file integrity (after you unzip)

Every file in the bundle is listed with its SHA-256 hash in `MANIFEST.sha256`.
The included `verify.sh` re-hashes each file and compares it to the manifest,
so you can confirm nothing was changed or dropped during extraction.

```bash
cd bas-install-<version>
bash verify.sh
```

Expected result: every file reports `[✓]` and the script exits `0`. Any
mismatch or missing file is reported and the script exits `1`.

> The manifest itself is covered by the Layer-1 GPG signature (it lives inside
> the signed zip), so a valid Layer 1 plus a clean Layer 2 gives you an
> unbroken chain from the Audspect key to every file on disk.

---

## Layer 3 — Trust enforced at runtime (verified for you by the platform)

Beyond delivery-time checks, the orchestrator continuously enforces integrity
while it runs. You do not need to run anything for these — they are built in —
but your team should know they are active:

- **Agent binary manifest** — `BINARIES.sha256` lists the SHA-256 of every
  agent binary and is itself RSA-4096 signed (`BINARIES.sha256.sig`). The
  orchestrator verifies this signature at startup and refuses a tampered
  manifest. Agent binaries are hash-checked against it at registration.

- **Signed attack scenarios** — every built-in scenario YAML ships with an
  RSA-4096 signature (`.sig`). The orchestrator verifies each scenario before
  it can be dispatched; an unsigned or altered scenario is rejected.

- **Signed license** — `bas.lic` is RSA-4096 signed and verified at startup.
  The platform will not run on a forged or edited license.

- **Signed agent results** — results returned by agents are authenticated with
  HMAC-SHA256 using a per-deployment agent secret, so results cannot be forged
  or replayed by anything that does not hold the secret.

- **Live tamper detection** — a filesystem watcher polls the critical scenario
  and manifest files every 15 seconds. Any change raises a real-time alert on
  the dashboard, records a `tamper_events` audit row, and suspends new run
  dispatch until an administrator acknowledges it.

- **Password storage** — administrator passwords are stored using
  PBKDF2-HMAC-SHA256 (≥310,000 iterations, per NIST SP 800-132), never in
  plaintext or with reversible encryption. A cryptographic self-test runs at
  every startup.

---

## What each control guarantees

| Control | Primitive | Guarantees |
|---|---|---|
| Bundle signature (Layer 1) | GPG RSA-4096 + SHA-256 | The zip is authentic and unmodified |
| File manifest (Layer 2) | SHA-256 per file | No file was added, dropped, or altered after unzip |
| Agent binary manifest | RSA-4096 + SHA-256 | Only Audspect-built agent binaries run |
| Scenario signatures | RSA-4096 + SHA-256 | Only authentic attack scenarios execute |
| License signature | RSA-4096 + SHA-256 | The license is genuine and unedited |
| Agent result MAC | HMAC-SHA256 | Results cannot be forged or replayed |
| Tamper watcher | SHA-256 size/mtime poll | Post-install changes are detected within 15s |
| Password storage | PBKDF2-HMAC-SHA256 | Credentials are non-reversible |

---

## Quick checklist

- [ ] `verify-sig.sh` reports **Signature valid** (Layer 1)
- [ ] `pubkey.asc` fingerprint matches `D8B7 F958 1EAD 6202 6F57  A17E 7B6F 1A54 1AF7 E0F5`
- [ ] `verify.sh` reports all files `[✓]`, exits `0` (Layer 2)
- [ ] Orchestrator starts cleanly (Layer-3 signature checks pass at boot)

If any step fails, do not proceed — contact Audspect support with the exact
output.
