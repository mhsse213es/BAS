# Release Signing Runbook

This is the operational guide for D1 (release signing). See the architecture
spec at ../../docs/superpowers/specs/2026-09-30-d1-release-signing-architecture-design.md
for the *why*; this document is the *how*.

## Prerequisites (Phase 0 -- not yet complete)

Before signing a *production* release, Phase 0 discovery must be answered:
see ../../docs/superpowers/plans/2026-09-30-d1-phase0-discovery-checklist.md.
Until then, only test-certificate builds are possible.

## Running a signed build with a test certificate (available today)

The release gate requires an RFC 3161 timestamp and checks the signer's
thumbprint against the one you passed whenever `-WindowsSigningRequired
$true` (the default for a `-Customer`/`-CustomerID` build). A self-signed
cert that isn't trusted by this machine will make `Get-AuthenticodeSignature`
report `UntrustedRoot` and the gate will correctly fail closed -- that is
the intended behavior, not a bug, but it means a self-signed test run needs
one extra step most people miss the first time: trusting the cert.

1. Generate a throwaway self-signed test certificate:
   ```powershell
   $cert = New-SelfSignedCertificate -Subject "CN=BAS Local Test" -Type CodeSigningCert `
       -CertStoreLocation "Cert:\CurrentUser\My" -KeyUsage DigitalSignature -NotAfter (Get-Date).AddDays(1)
   ```
2. Trust it as both root and publisher, or the gate will fail with
   `UntrustedRoot` even though signing itself succeeded:
   ```powershell
   foreach ($storeSpec in @(@("Root","LocalMachine"), @("TrustedPublisher","LocalMachine"))) {
       $s = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeSpec[0], $storeSpec[1])
       $s.Open("ReadWrite"); $s.Add($cert); $s.Close()
   }
   ```
3. Run the build, pointing at the test cert's thumbprint. Invoke in-session
   or with `-Command`, not `-File` -- `-WindowsSigningRequired` is a
   `[Nullable[bool]]` and `-File` passes switch-style arguments as strings,
   which won't bind to it:
   ```powershell
   .\packaging\windows-build.ps1 -Version "1.7.0-test" -WindowsCertThumbprint $cert.Thumbprint -WindowsSigningRequired $true
   ```
4. Check `dist\bas-install-<version>\release-verification.json` -- `overallResult` must be `true`.
5. Remove the test cert from **all three** stores when done -- leaving it in
   `LocalMachine\Root`/`TrustedPublisher` is a system-trust-store change
   that outlives this test run:
   ```powershell
   foreach ($storeSpec in @(@("My","CurrentUser"), @("Root","LocalMachine"), @("TrustedPublisher","LocalMachine"))) {
       $s = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeSpec[0], $storeSpec[1])
       $s.Open("ReadWrite")
       $found = $s.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
       if ($found) { $s.Remove($found) }
       $s.Close()
   }
   ```

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

**Key custody constraint (spec acceptance criterion):** the architecture
spec requires that no production release depend on a private key living in
the build workstation's own keyring or filesystem. `-WindowsCertThumbprint`
only works this way when it points at a certificate backed by a hardware
token or a cloud key-signing service (KSP) exposed as a Windows certificate
store on this machine -- `signtool /sha1` signs against whatever the store
entry resolves to, wherever the actual private key is held. It is **not**
satisfied by importing a real production `.pfx` into
`Cert:\CurrentUser\My` on this workstation. A service such as Azure Trusted
Signing uses `signtool /dlib` rather than `/sha1`, which this script does
not yet support -- moving to a service like that is a code change here, not
just a config change, and should be scoped before Phase 0 selects a
provider.

## macOS signing (not yet wired into any build -- no macOS artifact is
produced by windows-build.ps1 today)

`packaging/signing/sign-macos.sh` / `verify-macos-signature.sh` exist and
are written against Apple's documented interface, but were **not** tested
against real `codesign`/`notarytool` in the session that wrote them -- no
macOS host was available. Before relying on them for a real release:
verify them manually on an actual Mac with real Developer ID credentials,
the same way this plan's Task 1/2/4 were verified with `signtool.exe` and
a self-signed test cert on this Windows host.

**Known design gap, found in review, not yet fixed:** the only macOS
artifacts this repo currently produces are bare `darwin-amd64`/`darwin-arm64`
Mach-O binaries (built by `packaging/build.sh`, not by this script).
`notarytool submit` and `stapler staple` both require a zip, pkg, or dmg --
neither accepts a bare executable -- and `spctl --assess --type execute`
rejects a non-bundle command-line binary even once it's notarized. Go's
linker also ad-hoc-signs `darwin/arm64` output, so plain `codesign --sign`
(no `--force`) fails on that architecture. `sign-macos.sh` /
`verify-macos-signature.sh` need a rework for bare-binary inputs (zip
before submitting, skip/adjust stapling, add `--force`, verify via
`codesign --verify --strict` plus the notarization log rather than
`spctl`) before they're activated against a real artifact -- do this
before wiring D1-macOS into any build, not as part of first use.

## Troubleshooting

- **`signtool.exe not found`** -- install the Windows SDK (provides
  `signtool.exe` under `Windows Kits\10\Tools\bin\`).
- **Release verification fails with `HashMismatch`** -- the artifact was
  modified after signing; rebuild from a clean state.
- **Customer build fails with "Windows signing is required... but
  -WindowsCertThumbprint is not set"** -- pass a real certificate
  thumbprint; production customer builds cannot skip signing.
