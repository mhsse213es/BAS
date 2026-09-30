# D1 Release Signing Architecture — Design

**Status:** Approved architecture, pending Phase 0 discovery. Do not implement until Phase 0 (credential/certificate discovery) completes.

**Source finding:** Security register, Group D, `D1 — Missing OS-native signing` (🟠 HIGH, Confirmed/Open). See vault: `14 Risks/D1 - Missing OS-native signing.md`.

## Problem

The real customer-facing gap is narrower and sharper than the original finding evidence suggested. Investigation of the actual release pipeline (not just `packaging/signing/*`) found two separate build paths:

- `packaging/build.sh` (bash, dev/CI-style) — cross-compiles agent binaries, conditionally GPG-signs them per-binary via `packaging/signing/sign-binaries.sh` if a `releases@audspect.com` secret key happens to be present in the local GPG keyring.
- `packaging/windows-build.ps1` (PowerShell) — the **actual customer-delivery pipeline**. Builds `BASAgent-Setup-$Version.exe` (a custom Go-based installer), bundles it into `dist/bas-install-<version>.zip`, and does **not** call `sign-binaries.sh` at all.

`windows-build.ps1` applies two other mechanisms instead, neither of which is OS-native publisher trust:
- An RSA-4096 **content-integrity** signature (`orchestrator/scripts/signer.go` + `orchestrator/private_key.pem`) over scenario YAMLs and `BINARIES.sha256` — verified at orchestrator boot. This detects unauthorized modification of protected application artifacts; it says nothing to Windows/macOS about publisher identity.
- A **GPG detached signature over the whole delivery ZIP** (`$ZipPath.asc`) — gracefully skipped if no key is found, so signing is silently optional depending on what happens to be installed on the build machine.

**The actual executable a customer runs — `BASAgent-Setup-$Version.exe` — carries no signature of its own.** It is only protected by the outer ZIP's GPG signature, which essentially no end customer verifies before double-clicking the installer. The ZIP-level GPG signature and the RSA-4096 application-integrity signature are both useful, real controls, but neither substitutes for Authenticode/notarization: they don't produce a Windows SmartScreen/macOS Gatekeeper trust signal, and they don't survive the moment the customer extracts the ZIP and runs the installer directly.

Additionally: no CI-based release exists (`.github/workflows/test.yml` is test-only), and two unprotected private keys already live on the single Windows build workstation that runs `windows-build.ps1` (the GPG key `releases@audspect.com`, and `orchestrator/private_key.pem`) — matching the existing vault risk `Signing key loss`.

## Goals

- The actual customer-executed artifact (`BASAgent-Setup-$Version.exe`, and any future macOS distributable) carries a valid OS-native signature that Windows/macOS trust natively — not merely a container-level signature the customer must separately choose to verify.
- No production release ever depends on whether a private key happens to be present in the build workstation's local keyring/filesystem — signing must be an explicit, deterministic, gated step, never a silently-skipped conditional.
- Production signing private keys are never held on the general-purpose build workstation.
- The existing RSA-4096 content-integrity signer and GPG offline-verification mechanisms are preserved unchanged in mechanism, but the RSA signer's key custody is hardened as adjacent remediation.

## Explicit non-goals

- Do not introduce a full CI/CD platform to solve D1. The existing manual build process (`windows-build.ps1` on the Windows workstation) is retained initially; only the signing step moves to a dedicated boundary.
- Do not change the RSA content-integrity signer's mechanism (`scripts/signer.go`, RSA-4096, scenario/manifest signing) — only its key custody.
- Do not merge or create a dependency between any of the four signing mechanisms (Authenticode, Apple Developer ID/notarization, RSA content signer, GPG) — each protects a different trust boundary and must remain independently verifiable.
- Do not assume Audspect already holds a Windows code-signing certificate or an Apple Developer Program membership — Phase 0 (below) treats both as unknown and verifies before any pipeline work begins.
- Do not place certificates or private keys in Git, the repository, the delivery ZIP, or any ordinary build artifact.
- D2 (agent obfuscation) is explicitly out of scope for this spec — sequenced after D1 and B1-B4 per the register's dependency ordering.

## Architecture

### Phase 0 — Credential/certificate discovery (prerequisite, before any pipeline implementation)

This is a discovery task, not an assumption. Before any signing-pipeline engineering begins:

- **Windows:** confirm whether a currently valid Authenticode code-signing certificate exists; if so, who owns it, its expiration date, its Extended Key Usage (EKU must include code signing), and where its private key is currently held.
- **macOS:** confirm Apple Developer Program membership status, whether a Developer ID Application certificate exists, and whether notarization credentials (an App Store Connect API key, or Apple ID + app-specific password) are already set up.
- If either doesn't exist, procurement/account setup is a blocking prerequisite for that platform's signing work — it does not block the other platform, and does not block Phase 0 discovery for the platform that does have credentials.

### Target release chain

```
Windows build workstation
        │
        │ build/package (existing windows-build.ps1, unchanged)
        ▼
Unsigned release artifacts
        │
        ▼
Dedicated signing boundary
        │
        ├── Windows signing   → Authenticode (SHA-256) + RFC 3161 timestamp
        │
        └── macOS signing     → Developer ID codesign → notarize → staple
        │
        ▼
Signed release artifacts
        │
        ▼
Audspect RSA-4096 content-integrity signature (existing mechanism, unchanged)
        │
        ▼
GPG release signature + SHA-256 manifest (existing mechanism, unchanged)
        │
        ▼
Customer delivery ZIP
```

### Signing boundary

The build workstation must never possess the production signing private key. Signing becomes an explicit, controlled step at a dedicated signing environment/service — not a conditional branch inside the same script that also builds the artifacts.

**Phased rollout:**
- **Phase 1 (this spec's implementation target):** manual build (existing `windows-build.ps1`, unchanged) → controlled signing service/environment → release package. The build workstation produces unsigned artifacts and hands them to the signing boundary; it never holds the signing key.
- **Later (separate, unscoped work):** CI build → the same controlled signing boundary → release package. Because the signing boundary is already a separate, well-defined interface, connecting CI to it later requires no redesign of D1.

This is deliberately lighter than standing up a full CI/CD platform now: it gets the actual security property (build host never holds the production key; signing can't silently no-op) without the cost of also replacing the build process itself in this pass.

### Full customer release chain (what "release" now means)

1. Build artifacts (existing `windows-build.ps1`/`build.sh`, unchanged).
2. Sign Windows executable/installer (Authenticode + RFC 3161 timestamp) at the signing boundary.
3. Sign/notarize/staple macOS distributables at the signing boundary.
4. Generate/maintain the SHA-256 manifest (existing mechanism).
5. Apply the Audspect RSA-4096 content-integrity signature (existing mechanism, unchanged).
6. Verify all signatures before release (a release gate, not a log line — see below).
7. GPG-sign the final delivery package (existing mechanism, unchanged).
8. Produce a release verification record (see Auditability).
9. Deliver only the verified package. An artifact that is unsigned or fails verification at step 6 never reaches step 9.

### Key custody

- **Windows/macOS signing keys:** held at the dedicated signing boundary, never on the build workstation. Managed/HSM-backed storage is the target; the exact mechanism (cloud HSM, managed signing service, or a hardened dedicated signing host) is a Phase 1 implementation decision, made once Phase 0 confirms what credentials actually exist and what constraints the CA/Apple program impose.
- **RSA-4096 content-integrity key (`orchestrator/private_key.pem`):** mechanism unchanged, but moved out of the general-purpose build workspace into protected storage, with restricted access, a documented backup/recovery procedure, a rotation plan, and documented ownership. This directly addresses the existing vault risk `Signing key loss` for this key.
- **GPG key (`releases@audspect.com`):** unchanged mechanism; its existing custody gap is the same pre-existing vault risk (`Signing key loss`) and is addressed by the same protected-storage requirement, not a new one.
- No certificate or private key is ever placed in Git, the repository, the delivery ZIP, or an ordinary build artifact.

### Release gate

An unsigned or failed-verification artifact cannot become a customer ZIP. This replaces the current behavior in `windows-build.ps1` where GPG signing is silently skipped (with only a `Warn` log line) if no key or tool is found — that fragile, silently-optional behavior is exactly what this spec eliminates. No production release may depend on the presence of a private key in the build workstation's local GPG keyring or filesystem.

### Auditability

Each release produces a verification record capturing: version, artifact hashes (SHA-256), certificate identity (subject/thumbprint for Authenticode; Team ID for Apple), signing timestamp, signer result (success/failure per artifact), notarization result (accepted/rejected, with Apple's notarization log reference), and the overall verification result gating step 9 above.

## Testing

Per the original D1 remediation checklist, release verification tests must cover:
- Valid signature — a correctly signed artifact passes verification.
- Modified binary — a post-signing tampered binary fails verification.
- Modified installer/package — a post-signing tampered installer fails verification.
- Expired/revoked signing certificate — verification correctly rejects it.
- Timestamp (RFC 3161) validation — signature remains valid evaluation-time-independent of certificate expiry, per standard Authenticode timestamping semantics.
- Clean Windows/macOS installation from a verified, signed artifact succeeds with no SmartScreen/Gatekeeper warning.

## Acceptance criteria

- Phase 0 discovery is complete and documented (certificate/account status known for both platforms, for whichever platforms have owners/credentials).
- `BASAgent-Setup-$Version.exe` (and any macOS distributable) carries a valid Authenticode/Developer ID signature respectively, verifiable independent of the delivery ZIP.
- The build workstation's filesystem and GPG keyring contain no production signing private key at any point during or after a release build.
- A release with a missing or invalid signature cannot produce a customer-deliverable ZIP (verified by the modified-binary/modified-installer test cases above).
- The RSA-4096 content-integrity key has documented custody: storage location, access restriction, backup/recovery procedure, rotation plan, and owner.
- D1 is marked remediated in the security register only after an actual signed release artifact passes verification end-to-end (per the original register status rule) — not on pipeline code landing alone.

## Open items (not blocking this spec's approval, blocking Phase 1 implementation)

- Phase 0 discovery results are unknown as of this spec — they determine whether Phase 1 starts with pipeline engineering or with certificate/account procurement, and for which platform(s).
- The exact signing-boundary implementation (cloud HSM, managed signing service such as Azure Trusted Signing/SignPath, or a hardened dedicated host) is deferred to Phase 1 planning, once Phase 0's findings are known — different choices have different cost/lead-time/custody tradeoffs that shouldn't be pre-committed before knowing what credentials exist.
