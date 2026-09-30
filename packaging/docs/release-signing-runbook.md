# Release Signing Runbook

This is the operational guide for D1 (release signing). See the architecture
spec at ../../docs/superpowers/specs/2026-09-30-d1-release-signing-architecture-design.md
for the *why*; this document is the *how*.

## Prerequisites (Phase 0 -- not yet complete)

Before signing a *production* release, Phase 0 discovery must be answered:
see ../../docs/superpowers/plans/2026-09-30-d1-phase0-discovery-checklist.md.
Until then, only test-certificate builds are possible.

## Running a signed build with a test certificate (available today)

1. Generate a throwaway self-signed test certificate:
   ```powershell
   $cert = New-SelfSignedCertificate -Subject "CN=BAS Local Test" -Type CodeSigningCert `
       -CertStoreLocation "Cert:\CurrentUser\My" -KeyUsage DigitalSignature -NotAfter (Get-Date).AddDays(1)
   ```
2. Run the build, pointing at the test cert's thumbprint:
   ```powershell
   .\packaging\windows-build.ps1 -Version "1.7.0-test" -WindowsCertThumbprint $cert.Thumbprint -WindowsSigningRequired $true
   ```
3. Check `dist\bas-install-<version>\release-verification.json` -- `overallResult` must be `true`.
4. Remove the test cert when done: `Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)"`.

Windows will still show "Unknown Publisher" for a self-signed-cert build --
that's expected. Only a certificate chaining to a public root (Phase 0)
produces real SmartScreen/publisher trust.

## Running a production customer release (blocked on Phase 0)

Once Phase 0 confirms a real Authenticode certificate is available:

```powershell
.\packaging\windows-build.ps1 -Version "1.7.0" -Customer "Acme Corp" -CustomerID "acme-prod-001" `
    -WindowsCertThumbprint "<real cert thumbprint>"
```

`-Customer`/`-CustomerID` being set makes this a customer build, which
defaults `WindowsSigningRequired`/`GpgSigningRequired` to `$true` --
the build aborts rather than producing an unsigned customer deliverable.

## macOS signing (not yet wired into any build -- no macOS artifact is
produced by windows-build.ps1 today)

`packaging/signing/sign-macos.sh` / `verify-macos-signature.sh` exist and
are written against Apple's documented interface, but were **not** tested
against real `codesign`/`notarytool` in the session that wrote them -- no
macOS host was available. Before relying on them for a real release:
verify them manually on an actual Mac with real Developer ID credentials,
the same way this plan's Task 1/2/4 were verified with `signtool.exe` and
a self-signed test cert on this Windows host.

## Troubleshooting

- **`signtool.exe not found`** -- install the Windows SDK (provides
  `signtool.exe` under `Windows Kits\10\Tools\bin\`).
- **Release verification fails with `HashMismatch`** -- the artifact was
  modified after signing; rebuild from a clean state.
- **Customer build fails with "Windows signing is required... but
  -WindowsCertThumbprint is not set"** -- pass a real certificate
  thumbprint; production customer builds cannot skip signing.
