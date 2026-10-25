# Windows Agent Installer: Wizard MSI — Design

Status: DECISIONS CONFIRMED by the owner (section 10). Nothing in this document is built yet.

## 1. Why

Today the Windows agent is installed by `BASAgent-Setup.exe` (`installer/main.go`): a single hand-drawn
Win32 window with four fields (Server URL, Enrollment Port, Agent Secret, Environment Label) and a log box.
It grew one field at a time; nobody designed it as an installer. For an enterprise product this leaves gaps:

- No wizard flow (welcome, licence, folder, test connection, ready, progress, finish).
- No entry created by a standard installer database, so Apps & features, repair, and upgrade behave ad hoc.
- No supported silent install (`msiexec /qn`) or return-code contract for SCCM / Intune / GPO.
- The per-download personalisation patches bytes inside the already code-signed installer exe
  (`orchestrator/internal/api/agent_install_bundle.go`), so the Authenticode signature on the copy a customer
  downloads does not verify. That can trip SmartScreen, AppLocker and WDAC.

## 2. Goals, non-goals, anti-goals

Goals
- A signed MSI with a real wizard, plus a fully silent path that takes the same inputs as properties.
- The Authenticode signature on what the customer runs verifies.
- Behaviour parity with today's installer (section 5): nothing the current installer guarantees is lost.
- Standard upgrade, repair and uninstall.

Non-goals (this phase)
- Linux and macOS packaging (.deb/.rpm/.pkg are their own piece of work).
- Agent auto-update, MSIX, a web-based installer.

Anti-goals (failure even if it technically works)
- A wizard that can report success while the agent never enrolled.
- The agent secret appearing in logs, in the process list, or in a file left on disk.
- A personalised download that fails open when its config is tampered with (today's rule is fail closed; keep it).

## 3. Decisions proposed (the builder's calls; flagged where the owner should decide)

D1. Packaging: WiX Toolset v4 MSI, per-machine, x64, with a fixed UpgradeCode. (Alternative considered:
Inno Setup / NSIS. Faster, but MSI is what enterprise deployment tooling expects: transforms, repair,
inventory, `/qn`.) Owner decision.

D2. Wizard pages: Welcome, Licence, Server connection (URL, enrollment port), Agent secret and environment
label, Test connection, Install folder, Ready to install, Progress, Finish (option: open status monitor).
The Test connection page must pass before Next is enabled, with a visible "install anyway" only for advanced
users who set `SKIPPREFLIGHT=1`.

D3. Properties, usable from the wizard or from the command line:
`SERVER_URL`, `ENROLL_PORT` (default 9444), `AGENT_SECRET` (hidden: listed in `MsiHiddenProperties`,
never written to the MSI log), `ENV_LABEL` (default Production), `CA_FILE` (optional path to a CA PEM),
`INSTALLFOLDER`, `SKIPPREFLIGHT`, `REMOVE_DATA` (uninstall only).

D4. No duplicated logic: the connectivity, secret and CA checks stay in Go. Add an agent CLI mode,
`bas_agent.exe --preflight --server ... --enroll-port ... --secret-stdin [--ca-root ...]`, that exits 0 or a
documented non-zero code and prints a one-line human message. The wizard's Test page and the install
sequence both call it. The secret is passed on stdin, never on a command line.

D5. Personalised downloads without breaking the signature. The dashboard "Download Windows agent" returns a
ZIP: the single, generic, signed MSI, plus `deployment.json` (server URL, enrollment port, deployment CA root)
and a one-line `install.cmd` showing the silent form. A custom action reads `deployment.json` next to the MSI
to pre-fill the wizard. `deployment.json` carries a detached signature from the orchestrator; the custom
action verifies it against a public key compiled into the agent and fails closed if it is present but wrong.
The secret is not in the bundle; the operator types it, or supplies `AGENT_SECRET` for silent installs
(unchanged from today's "secret-only" model). Owner decision: confirm secret stays out of the bundle.

D6. Upgrade and uninstall: MajorUpgrade keeps existing registry service parameters, `%ProgramData%\BASAgent`
state and the enrolled certificate, so an upgrade does not re-enroll. Uninstall stops and removes the
"Audspect Agent" service, the tray startup entry and the Start Menu shortcut; data is kept unless
`REMOVE_DATA=1`. Open item: the dashboard's remote "Uninstall Agent" currently drives the agent's own
`--uninstall`. It must also drop the Apps & features registration (either by invoking `msiexec /x` or by
having the agent remove its ARP entry) so the two paths stay consistent.

D7. Exit codes follow Windows Installer: 0 success, 3010 reboot required, 1603 fatal. Preflight failure
returns a distinct custom code (1650 range) with a one-line reason in the log, so deployment tools can alert.

D8. Transition: keep `BASAgent-Setup.exe` available for one release as "legacy installer", then retire it.

## 4. Build and release integration

- `packaging/windows-build.ps1`: after the signed `bas_agent.exe` is produced, run `wix build`, run ICE
  validation, then sign the MSI with the existing `Invoke-AuthenticodeSigning` and the same cert thumbprint.
- Add the MSI to `BINARIES.sha256` / signature manifests so the orchestrator verifies it before serving
  (same gate the installer exe passes today), and add a dev-build path that skips only the Authenticode
  re-verify, as already done for other artifacts.
- Build host needs the WiX v4 dotnet tool; document it in the build prerequisites and fail early if missing.
- The 40 MB image size guard stays; the MSI is served by the orchestrator, not baked into the image twice.
- Replace the personalisation path in `agent_install_bundle.go` with ZIP generation plus detached signing
  of `deployment.json`; keep the slot-patching code only for the legacy installer until it is retired.

## 5. Behaviour that must be preserved (from `installer/main.go`)

1. Elevation: the MSI is per-machine and prompts for it.
2. Pre-install probe against the enrollment port (not the mTLS port), validating server URL and secret.
3. Deployment CA: use the CA from `deployment.json` or `CA_FILE` when present; otherwise fetch it from the
   server using the existing trust-on-first-use rules in `ca_fetch.go`. Never leave the agent on legacy
   transport because the CA was missing.
4. Install directory `C:\Program Files\BASAgent`; service name "Audspect Agent"; service started on finish.
5. Service installed with `--install --server --env --secret --ca-root [--enroll-port]` (the agent keeps its
   own install logic; the MSI calls it as a deferred custom action with the secret on stdin or in a hidden
   property, not on a visible command line).
6. Tray status monitor registered to start at login; Start Menu shortcut "Audspect Agent - Show Tray Icon".
7. Branding: Audspect logo and the Electric Blue header.
8. Failure rolls back: a failed enrollment probe or service install leaves nothing installed.

## 6. Security

- The secret is a hidden property and is passed to the agent over stdin; never logged, never written to
  `deployment.json` or the registry by the installer. (The agent's own handling of the stored credential is
  unchanged.)
- `deployment.json` integrity is verified before any field is trusted; invalid means abort, not fall back.
- The MSI and the agent exe are Authenticode-signed with the same certificate; nothing is modified after
  signing.
- Silent installs record only non-secret properties in the MSI log.

## 7. Testing

Automated
- Go unit tests: `--preflight` result codes, `deployment.json` signature verification (valid, missing,
  tampered, wrong key), property validation (port range, URL scheme).
- Build-time: WiX ICE validation; a check that the built MSI's signature verifies and that
  `MsiHiddenProperties` contains `AGENT_SECRET`.

Real-machine matrix (must be run on real VMs; not claimable from a build)
- Windows 10, 11, Server 2019, Server 2022.
- Interactive wizard, silent `/qn`, upgrade from the current 1.9.x installer-based install (no re-enroll),
  repair, uninstall with and without `REMOVE_DATA`, wrong secret, unreachable server, server with and
  without PKI configured, service already running.
- Confirm the signature verifies on the file as downloaded, and that SmartScreen/AppLocker do not object.

## 8. Work breakdown (each independently testable)

1. `--preflight` agent mode and its tests.
2. `deployment.json` format, signing on the orchestrator, verification in the agent, tests.
3. WiX project: files, service, shortcut, tray startup, upgrade, uninstall (no wizard UI yet, silent only).
4. Wizard UI pages and the Test connection integration.
5. Build script, signing, manifest and orchestrator serving (ZIP bundle).
6. Real-machine matrix, docs (`docs/guides/installation.md` agent section; fix the stale wizard text in
   `docs/Audspect_BAS_Product_Guide.md`), then deprecate the legacy exe.

## 9. Open questions for the owner

1. WiX MSI (recommended) or Inno Setup / NSIS?
2. Keep the secret out of the downloaded bundle (recommended), or also offer a bundle with the secret baked in
   for locked-down fleets?
3. Is a code-signing certificate available for release builds (OV or EV)? EV gives immediate SmartScreen
   reputation; dev builds stay unsigned.
4. Is installing the WiX toolchain on the Windows build host acceptable?
5. Licence/EULA text and any extra branding assets for the wizard.

## 10. Owner decisions (2026-10-25)

1. WiX MSI. Confirmed.
2. The agent secret stays out of the downloaded ZIP. It is requested at install time in a masked field, passed
   to the agent on stdin, and never logged. Confirmed.
3. Release builds use a trusted code-signing certificate. If none exists, use a clearly separated development
   signing workflow and never present development signatures as production-trusted. Signing keys stay outside
   the repository.
4. Install and pin the WiX toolchain on the Windows build host; keep the build reproducible.
5. Audspect branding only (no Trellix or InstallShield branding). The EULA must be approved before release;
   no invented legal terms.

Non-negotiable requirements
- N1. Signed deployment configuration: verify the server-signed `deployment.json` before trusting its URL,
  port or CA; reject tampering and unsupported versions or fields.
- N2. Safe upgrades and rollback: preserve enrollment and service configuration on upgrade; test rollback
  after failures at each installation stage.
- N3. Remote uninstall consistency: the dashboard's Uninstall Agent action uses a defined, authenticated
  workflow and stays consistent with Apps & features. A local MSI uninstall is not assumed to implement it.
- N4. The MSI signature and the `deployment.json` signature are verified independently. A signed MSI does not
  make the ZIP or its configuration trustworthy.

Implementation order: `--preflight` and tests; signed deployment configuration; WiX MSI; signing integration;
full lifecycle validation on real Windows machines.

### Open problem found while planning: trust anchor for `deployment.json` (blocks work item 2)

The agent has no key it can trust before it enrolls (command-signing keys are delivered after enrollment), and
the MSI is generic, so it cannot carry each customer's orchestrator key. Something outside the ZIP must vouch
for the config. Options:
- A. Pin by fingerprint: the dashboard shows the SHA-256 fingerprint of the orchestrator's config-signing
  public key and puts it in the generated `install.cmd`; the wizard shows it for the operator to confirm and
  the MSI takes it as `CONFIG_FINGERPRINT` for silent installs. Recommended.
- B. Customer-owned code-signing certificate signs the ZIP contents (requires the customer to have one).
- C. Per-customer MSI built or transformed on the server (heavy; reintroduces per-download signing problems).
Decision needed from the owner before work item 2 starts.
