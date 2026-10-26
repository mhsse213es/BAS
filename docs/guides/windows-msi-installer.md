# Windows agent MSI installer

The Windows agent is installed from a signed MSI (`AudspectAgent-x64.msi`) with a setup wizard and a silent
mode. It replaces the single-form `BASAgent-Setup.exe`, which stays available for one release as the
"legacy installer" and is then retired.

Design: `docs/superpowers/specs/2026-10-25-windows-agent-msi-installer-design.md`
Plan: `docs/superpowers/plans/2026-10-25-windows-agent-msi-installer.md`

## What the operator downloads

On **Deploy Agent**, *Download MSI installer* returns `AudspectAgent-x64.zip`, built for that request:

| File | What it is |
|---|---|
| `AudspectAgent-x64.msi` | The same signed MSI for every deployment. The server checks it against the signed integrity manifest before serving and refuses to serve it otherwise. |
| `deployment.json` | The server address, enrollment port and deployment CA, **signed by the server**. It contains no secret. |
| `install.cmd`, `install.ps1` | Silent install. The script shows the signing fingerprint, asks the operator to confirm it, and asks for the agent secret (hidden). |
| `README.txt` | The same instructions and the fingerprint. |

The agent secret is never in the bundle.

## Trust model: why the fingerprint matters

`deployment.json` carries its own signing certificate, so a valid signature alone proves nothing: anyone who
can replace the download can replace the file, the certificate and the signature together. The installer
therefore requires the **SHA-256 fingerprint of the signing certificate**, obtained separately, and trusts the
file only if the fingerprint matches.

* Read the fingerprint from the dashboard (**Deploy Agent**, *Deployment signing fingerprint*). That page is
  behind your login. It is the same value the installer shows.
* `install.ps1` has the fingerprint printed in it, for convenience. An attacker who replaces the ZIP can
  replace that line too. **Always compare it with the dashboard, not with the folder.**
* The installer verifies, in this order: fingerprint present and well formed, file format and version,
  certificate fingerprint, signature (RSA, at least 3072 bits, domain-separated from command signatures), and
  only then the address, port and CA. Any failure installs nothing. Nothing falls back to manual entry.
* Verification happens in the agent (`bas_agent.exe --verify-config`), so there is one implementation of the
  rules for the wizard, the silent install and `--install`.

## Interactive install

Double-click the MSI. Pages: Welcome, Licence, Deployment configuration (the file and the fingerprint, with a
**Verify** button that shows what the file points at), Agent secret (masked) and environment label, Test
connection, Ready, Progress, Finish.

*Test connection* checks that the server answers, that its certificate chains to the deployment CA, and that
the secret is accepted. It installs nothing. **Next** is disabled until it passes. Advanced users can set
`SKIPPREFLIGHT=1`.

## One-prompt install (the normal way)

Download the Windows bundle from **Agents > Deploy Agent**, extract it, and double-click `AudspectAgent-x64.msi`.
The bundle carries `deployment.json` and `deployment.fingerprint` beside the MSI, so the wizard asks for the agent secret
and nothing else (Next, secret, Install). If the server issues enrolment tokens it also asks for the token for that
computer; otherwise there is no token field. Keep the three files together. If `deployment.fingerprint` is missing or
malformed, the wizard falls back to asking for the configuration file and fingerprint, as before.

Trust: the download from your authenticated dashboard is the trust anchor, as with other endpoint agents. The
fingerprint is still verified against `deployment.json`'s signature, and you can compare it with the one shown in the dashboard.

## Silent install

From an elevated prompt, either run `install.cmd` (prompts for the confirmation and the secret), or script it:

```
set AUDSPECT_AGENT_SECRET=<secret>        (environment of the msiexec process only)
msiexec /i AudspectAgent-x64.msi /qn /l*v install.log CONFIG_FINGERPRINT=<64 hex characters>
```

| Property | Meaning |
|---|---|
| `CONFIG_FINGERPRINT` | **Required** on a first install. Missing or malformed fails the install. |
| `AUDSPECT_AGENT_SECRET` (environment) | The agent secret. Preferred for silent installs. |
| `AGENT_SECRET` | The same as a property. It works, but a command line is visible to every user on the machine, so avoid it. |
| `AUDSPECT_ENROLLMENT_TOKEN` (environment) | A single-use, per-host enrollment token, only for servers in token mode (see Deploy Agent, "Enrollment tokens"). Supply it per computer; it is never part of the package. Not as a command-line property. |
| `ENROLLMENT_TOKEN` | The same as a hidden property (the wizard fills it); avoid it on a command line. |
| `DEPLOYMENT_CONFIG` | Path to `deployment.json`. Default: the folder the MSI is in. Use a local path, not a network share. |
| `ENV_LABEL` | Environment label. Default `Production`. |
| `SKIPPREFLIGHT=1` | Skip the pre-install connection check. Only the exact value `1` counts. |

The secret reaches the agent on its standard input. It is not on any command line, not in `deployment.json`,
and the MSI log masks it (the property is hidden). Verify this on your own logs.

### Exit codes

The MSI returns standard Windows Installer codes. A failed check returns **1603**, and the reason is in the
log (search for `Audspect`). The agent's own codes, visible in `install.log` and when you run
`bas_agent.exe --preflight` or `--verify-config` yourself:

| Code | Meaning |
|---|---|
| 0 | OK |
| 20 | Invalid input |
| 21 | Server unreachable |
| 22 | Server rejected the secret |
| 23 | Server certificate not trusted by the deployment CA |
| 24 | Invalid CA |
| 25 | Deployment configuration rejected (fingerprint, signature, format) |

The design asked for a distinct 1650-range code for a failed pre-check. A custom action cannot set the
process exit code, so the MSI returns 1603 and the reason is logged. Deployment tools should read the log.

## Upgrade, repair, uninstall

* **Upgrade** (a higher MSI version): the service is stopped, files replaced, the stored integrity hash
  refreshed, and the service started. Enrollment, the stored secret and the service parameters are kept.
  No secret or fingerprint is needed. An agent installed by the legacy setup is adopted the same way.
* **Repair**: same as above.
* **Uninstall** (Apps & features, or `msiexec /x`): the agent removes its service, tray entry and shortcut,
  tells the server it was decommissioned, and the files are removed. During a major upgrade the uninstall step
  is skipped.
* **Remote *Uninstall Agent*** from the dashboard: the agent removes its service and artifacts as before and,
  when it was installed from the MSI, also starts a delayed `msiexec /x` so the Apps & features entry and the
  files go too. Both paths end in the same state.

If a first install fails after the service was registered, the rollback removes it again.

## Rotating or losing the signing key

The signing key is the server's command-signing key (`<data>/signing`). The fingerprint is derived from its
certificate, so **a different key means a different fingerprint, and installers pinned to the old one will
refuse new bundles until an administrator approves the new fingerprint.** That is intended.

**Planned rotation**

1. Announce the change and the date to whoever installs agents.
2. Start the server with `BAS_CONFIRM_NEW_SIGNING_KEY=true` and a new signing directory (this is the existing
   command-signing rotation procedure; it also affects already enrolled agents, so follow that procedure).
3. Open **Deploy Agent** and read the new fingerprint from the dashboard (your authenticated session).
4. Tell installers the new fingerprint through a channel the download itself cannot alter: a ticket, a
   signed e-mail, or in person. Do not put it only in a ZIP.
5. Download a new bundle. Old bundles keep working only for installers that still pin the old fingerprint.
   Already installed agents are not affected by a bundle fingerprint change.

**Lost or replaced signing directory** (the server starts with a new key): the server refuses to start with a
silently new key when agents already trust the old one, unless `BAS_CONFIRM_NEW_SIGNING_KEY=true` is set. After
you confirm, the fingerprint changes as above. Restore the old `signing/` directory from backup if you want the
old fingerprint back.

**Suspected compromise of the key:** treat it as a rotation, and also re-issue every deployment bundle and tell
installers to discard bundles downloaded before the rotation.

## Building and signing

```
packaging\windows-msi\build-msi.ps1 -AgentExe <signed bas_agent.exe> -Version 2.1.0 -Release -EulaRtf <approved licence.rtf> -CertThumbprint <trusted cert>
packaging\windows-build.ps1 ... -BuildMsi -MsiEulaRtf <approved licence.rtf>
```

* The WiX toolchain is pinned: `wix` 5.0.2 in `packaging/windows-msi/dotnet-tools.json` and
  `WixToolset.UI.wixext` 5.0.2. A build host needs the .NET SDK.
* `-Release` stops before building anything unless it has a trusted code-signing certificate and the owner's
  licence text, and the finished signature must verify as valid. `-DevSign` signs with a throwaway,
  clearly labelled **untrusted** certificate for lab use. Signing keys never enter the repository.
* The build runs the custom action tests, builds, runs MSI validation (ICE) and the structure checks
  (`tests/Test-MsiStructure.ps1`: navigation targets, masked secret, hidden properties, action order), then signs.
* The licence text is the owner's to supply. `eula.placeholder.rtf` is a marked placeholder that a release
  build refuses.

## Verification status

| Area | How it was verified | Where |
|---|---|---|
| Config signing and verification, fingerprint pinning, attacker-key case | Unit tests, shared golden fixture between agent and server | Build host |
| `--config`, `--verify-config`, `--preflight`, `--install` fail-closed behaviour | Unit tests and the built binary's exit codes | Build host |
| Custom action logic, secret on stdin, redaction, timeout | 33 unit tests | Build host |
| MSI builds, ICE validation, structure and secret-hiding checks | `build-msi.ps1`, `Test-MsiStructure.ps1` | Build host |
| Server bundle: verified MSI only, signed config, no secret, fail closed | Unit tests | Build host |
| Release guards (placeholder licence, missing/unknown certificate) | `Test-BuildGuards.ps1` | Build host |
| **Install, upgrade, repair, uninstall, rollback on real machines** | `tests/Test-MsiLifecycle.ps1` on a clean lab VM | **Not run yet**: needs a clean machine per OS |
| **Interactive wizard appearance and flow** | By hand | **Not run yet** |
| **Dashboard *Uninstall Agent* on an MSI-installed agent** | By hand | **Not run yet** |
| Production-trusted signature | Needs the organisation's code-signing certificate | **Not available here** |

## Known limitations

* The licence page's *Print* button is the stock one from the WiX UI extension; its print action is not wired.
* The MSI must be on a local path when installed silently; a network share is not readable by the installer
  service.
* The interactive wizard has no folder page: the install folder stays `C:\Program Files\BASAgent`.
