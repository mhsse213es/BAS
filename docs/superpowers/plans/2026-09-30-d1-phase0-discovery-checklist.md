# D1 Phase 0 — Credential/Certificate Discovery Checklist

**Spec:** `docs/superpowers/specs/2026-09-30-d1-release-signing-architecture-design.md`

This is a discovery task, not an implementation plan — no code changes, no tests. It answers the questions that determine whether Phase 1 (the signing-boundary pipeline) starts with engineering or with procurement, for each platform independently. Whoever has access to Audspect's CA vendor account, Apple Developer account, and any existing secrets/password-manager entries should work through this and record the answers inline (or hand them back for the spec's Phase 1 planning to pick up).

## Windows — Authenticode

- [ ] Does Audspect (or any predecessor entity/individual) already hold a Windows code-signing certificate from any CA (DigiCert, Sectigo, GlobalSign, SSL.com, etc.)?
- [ ] If yes:
  - Certificate subject/organization name on file:
  - Owner (person/team with account access to the CA portal):
  - Expiration date:
  - Extended Key Usage — confirm it includes Code Signing (OID `1.3.6.1.5.5.7.3.3`):
  - Where the private key currently lives (USB HSM token, `.pfx` file, cloud key vault, etc.) — note: as of the CA/Browser Forum's 2023 baseline requirements, OV/EV code-signing private keys must be stored on a FIPS-140-2-validated hardware token or equivalent HSM/cloud signing service; a plain `.pfx` on disk is no longer issuable by public CAs for new certs, though an older cert might still be file-based:
- [ ] If no certificate exists: procurement is required. Two paths to weigh (record decision, don't implement yet):
  - **Traditional OV/EV certificate** from a CA — annual purchase, requires a hardware token or CA-provided cloud HSM, has a per-publisher SmartScreen reputation ramp-up period for OV.
  - **Cloud code-signing service** (e.g. Azure Trusted Signing or equivalent managed signing service) — no local hardware token, built-in HSM custody, and (for Trusted Signing specifically) immediate SmartScreen trust without the OV reputation ramp — worth evaluating given this spec's signing-boundary architecture already assumes signing happens at a dedicated service, not on the build workstation.

## macOS — Developer ID + notarization

- [ ] Does Audspect have an active Apple Developer Program membership ($99/year, requires organization verification via D-U-N-S number if enrolling as an Organization rather than an Individual)?
- [ ] If yes:
  - Team ID:
  - Who has Account Holder / Admin access:
  - Does a "Developer ID Application" certificate already exist under this account?
  - Is notarization tooling already set up — either an App Store Connect API key (for CI-less/scripted notarization via `notarytool`) or an Apple ID + app-specific password?
- [ ] If no membership exists: enrollment is required — budget 1-2 weeks for Apple's organization verification process before any certificate can be issued.

## Output

Once both sections are answered, hand the results back to resume Phase 1 planning (the signing-boundary implementation plan) per the spec — Phase 1 planning will differ depending on whether either platform needs procurement first or can start on pipeline engineering immediately.
