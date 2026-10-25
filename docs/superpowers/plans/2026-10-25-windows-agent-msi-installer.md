# Windows Agent MSI Installer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the single-form `BASAgent-Setup.exe` with a signed WiX MSI that has a real wizard, a silent path, safe upgrade/rollback, and a signed deployment configuration.

**Architecture:** The agent gains a `--preflight` mode and a stdin secret path so all connectivity, CA and secret logic stays in Go. A signed `deployment.json` (checked independently of the MSI signature) pre-fills the wizard. The MSI orchestrates files, service, tray and upgrade, and calls the agent for the checks and the service install.

**Tech Stack:** Go (agent module `audspect/agent`, orchestrator module `github.com/audspect/bas`), WiX Toolset v4, PowerShell build script `packaging/windows-build.ps1`.

**Spec:** `docs/superpowers/specs/2026-10-25-windows-agent-msi-installer-design.md` (owner decisions in section 10).

## Status (2026-10-25)

Built and tested on the build host; live-machine verification is the only open item. Operator guide:
`docs/guides/windows-msi-installer.md` (includes the verification table and the key rotation procedure).

| Task | State | Evidence |
|---|---|---|
| 1. `agent/preflight`, `--preflight` | Done | commits e3de69e3, 067f5eaa; unit tests; built-binary exit codes |
| 2. `--secret-stdin` | Done | commit 37e470c6; unit tests |
| 3. Signed `deployment.json` (Option A, fingerprint pinned) | Done | `agent/deployconfig`, `orchestrator/internal/deployconfig`, shared golden fixture; `--config`, `--config-fingerprint`, `--verify-config`; dashboard fingerprint; key rotation in the guide |
| 4. WiX MSI (install, upgrade, repair, uninstall, rollback entry) | Built, validated | `packaging/windows-msi`; ICE validation; `Test-MsiStructure.ps1`; 33 custom action tests |
| 5. Wizard | Built, structure-checked | `Ui.wxs`; not clicked through on a desktop yet |
| 6. Build, signing, serving | Done | `build-msi.ps1` (release guards tested), `windows-build.ps1 -BuildMsi`, signed manifest entry, `windows-amd64-msi` bundle endpoint |
| 7. Lifecycle and remote uninstall | Remote uninstall done; lifecycle script written | `msi_removal*.go`; `tests/Test-MsiLifecycle.ps1` **not yet run** (needs a clean VM per OS) |

Open, by nature rather than by omission: running the lifecycle script on Windows 10, 11, Server 2019 and
2022; a visual pass over the wizard; a production-trusted signature (needs the organisation's certificate);
the owner-approved licence text.

## Global Constraints

- Release builds use a trusted code-signing certificate; development signing is a clearly separate workflow and is never presented as production-trusted. Signing keys never enter the repository.
- The agent secret is never written to a log, a file, a command line or `deployment.json`; it travels on stdin and is a hidden MSI property.
- `deployment.json` and the MSI are verified independently; an invalid or unsupported config aborts the install (fail closed), never falls back to manual entry silently.
- Upgrade preserves enrollment and service configuration; rollback is tested after failure at each install stage.
- Remote Uninstall Agent uses a defined authenticated workflow and stays consistent with Apps & features.
- Audspect branding only. The EULA text is supplied and approved by the owner; do not draft legal terms.
- Windows service name stays "Audspect Agent"; install directory stays `C:\Program Files\BASAgent`.
- The pre-install probe targets the enrollment port (default 9444).
- Agent module and installer module are separate Go modules (`installer/go.mod` cannot import `agent/`). The legacy installer keeps its own copy of the probe code until it is retired.
- Real-machine results must be reported separately from build and unit-test results.

## Review Focus

- A wrong secret, an unreachable server, a TLS certificate not signed by the supplied CA, a malformed or non-https URL, and an out-of-range port each give a distinct preflight code and message, and never print the secret.
- A port other than 9444 (remapped deployments) reaches the enrollment listener, not the mTLS port.
- A server with PKI not configured (no CA available) still preflights, using the same pre-trust behaviour the current installer has, and says so in the result message.
- Secret on stdin with trailing CR/LF, empty stdin, and very long input do not leak the secret and do not hang.
- Preflight must never persist anything or touch the service.

---

## Task 1: `agent/preflight` package and `--preflight` CLI

**Files:**
- Create: `agent/preflight/preflight.go`, `agent/preflight/preflight_test.go`
- Modify: `agent/main.go` (flags near line 27-36; dispatch before service handling)

**Interfaces:**
- Produces:
  - `package preflight`
  - `type Params struct { ServerURL, EnrollPort, Secret string; CARootPEM []byte }`
  - `type Result struct { Code int; Message string }` and `func (r Result) OK() bool`
  - `const ( CodeOK = 0; CodeInvalidInput = 20; CodeUnreachable = 21; CodeSecretRejected = 22; CodeTrustFailure = 23 )`
  - `func EnrollmentProbeURL(serverURL, enrollPort string) (string, error)` (port ported from `installer/main.go:479`; default port 9444)
  - `func Run(ctx context.Context, p Params) Result`
- Consumes: nothing from other tasks.

- [ ] **Step 1: Write the failing tests** in `agent/preflight/preflight_test.go`, using `httptest.NewTLSServer` as the orchestrator stand-in (serves `/health` 200 and `/ws/agent` checking header `X-Agent-Token`):
  - `TestRunOKWhenReachableAndSecretAccepted` expects `CodeOK`.
  - `TestRunSecretRejectedOn401` expects `CodeSecretRejected` and a message that does not contain the secret.
  - `TestRunUnreachableWhenNothingListens` expects `CodeUnreachable`.
  - `TestRunTrustFailureWhenCANotSigned` supplies a different CA PEM than the server's and expects `CodeTrustFailure` before any `/ws/agent` request is made (assert the handler never saw the token).
  - `TestRunNoCAFallsBackToPreTrustAndSaysSo`: nil `CARootPEM`, expects `CodeOK` and a message containing `"no deployment CA"`.
  - `TestRunInvalidInput` table: empty URL, `http://` scheme, `ftp://`, port `0`, port `70000`, port `abc`, empty secret, each `CodeInvalidInput`.
  - `TestEnrollmentProbeURLUsesEnrollPort`: `("https://h:9443","9444")` gives `https://h:9444`; empty port defaults to 9444.

- [ ] **Step 2: Run to verify failure.**
  Run: `cd agent && go test ./preflight -count=1`
  Expected: build failure, `undefined: Run`.

- [ ] **Step 3: Implement `preflight.go`.** Port the logic from `installer/ca_fetch.go` (`bootstrapHTTPClient`, `trustingHTTPClient`, `validateEnrollment`) and `enrollmentProbeURL`, mapping errors to the codes above. Messages are one line, never include the secret. A TLS verification error from the trusting client maps to `CodeTrustFailure`.

- [ ] **Step 4: Run tests.**
  Run: `cd agent && go test ./preflight -count=1`
  Expected: PASS.

- [ ] **Step 5: Failing CLI test** `TestPreflightCLIExitCodeAndNoSecretInOutput` in `agent/preflight_cli_test.go` (package `main`): build args for `runPreflightCLI(args []string, stdin io.Reader, stdout io.Writer) int` and assert the exit code and that stdout never contains the secret. Run it; expect `undefined: runPreflightCLI`.

- [ ] **Step 6: Implement `runPreflightCLI`** in `agent/preflight_cli.go` and call it from `agent/main.go` when `--preflight` is set, before any service or install handling. Flags: `--server`, `--enroll-port`, `--ca-root <path>`, `--secret-stdin` (required: preflight refuses `--secret` on the command line). Read one line from stdin, trim CR/LF, cap at 4 KB. Print the result message to stdout and return `Result.Code`.

- [ ] **Step 7: Run tests and vet for both platforms.**
  Run: `cd agent && go test ./preflight . -run "Preflight|preflight" -count=1 && GOOS=linux go vet ./...`
  Expected: PASS, no new vet findings.

- [ ] **Step 8: Commit** `feat(agent): --preflight mode for connectivity, CA trust and secret checks`.

## Task 2: `--secret-stdin` for `--install`

**Files:**
- Modify: `agent/main.go` (the `flagSecret` handling)
- Test: `agent/secret_stdin_test.go`

**Interfaces:**
- Produces: `func readSecretFromStdin(r io.Reader) (string, error)` (one line, CR/LF trimmed, max 4 KB, error on empty).
- Consumes: nothing.

- [ ] **Step 1: Failing tests:** `TestReadSecretFromStdin` table (plain, trailing `\r\n`, empty, over 4 KB, no newline) and `TestInstallRejectsSecretAndSecretStdinTogether`.
- [ ] **Step 2: Run to verify failure.** Expected: `undefined: readSecretFromStdin`.
- [ ] **Step 3: Implement** `readSecretFromStdin`; add flag `--secret-stdin`; in `--install` reject use of both `--secret` and `--secret-stdin`. Keep `--secret` working (the legacy installer still uses it).
- [ ] **Step 4: Run tests.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): accept the install secret on stdin`.

> Execution order for Tasks 1-2 (separate commits): (a) `agent/preflight` package, (b) `readSecretFromStdin` and
> `--secret-stdin` for `--install`, (c) the `--preflight` CLI, which reuses `readSecretFromStdin`. Preflight adds
> `CodeInvalidCA = 24` for a malformed CA PEM (a configuration failure distinct from invalid input).

## Task 3: Signed `deployment.json` (Option A chosen; NOT STARTED until Tasks 1-2 pass)

Do not start until the owner picks option A, B or C in the spec (section 10, "Open problem"). With option A (recommended) the work is:

**Files (proposed):**
- Create: `agent/deployconfig/deployconfig.go` (+ test) and `orchestrator/internal/api/deployment_config.go` (+ test).

**Interfaces (proposed):**
- `type Config struct { Version int; ServerURL, EnrollPort, CARootPEM string; IssuedAt time.Time }`
- `func Verify(configJSON, sigB64 []byte, expectedKeyFingerprint string) (Config, error)`: rejects unknown fields, unsupported `Version`, non-https `ServerURL`, bad port, malformed CA PEM, a signature that does not verify, and a signing key whose SHA-256 fingerprint differs from `expectedKeyFingerprint`.
- Orchestrator: `func SignDeploymentConfig(cfg Config, key crypto.Signer) (configJSON, sig []byte, fingerprint string, err error)`.
- Tests must cover valid, missing signature, tampered byte, wrong key, wrong fingerprint, expired/unsupported version.

## Tasks 4-7 (outlined; detail them after Tasks 1-3 land and the WiX toolchain is installed and pinned on the build host)

4. **WiX MSI, silent only:** files, "Audspect Agent" service via the agent's `--install` custom action (secret on stdin), tray startup entry, Start Menu shortcut, MajorUpgrade with a fixed UpgradeCode, uninstall with `REMOVE_DATA`. Tests: ICE validation; lifecycle on a VM.
5. **Wizard UI:** pages per spec D2, Test connection page calling `bas_agent.exe --preflight`, masked secret field, Audspect branding, EULA supplied by the owner.
6. **Build, signing and serving:** `packaging/windows-build.ps1` builds and signs the MSI, adds it to the signed artifact manifests, orchestrator serves the ZIP bundle (MSI + `deployment.json` + signature + `install.cmd`). Dev signing path clearly separated.
7. **Lifecycle validation and remote uninstall:** real-machine matrix (Windows 10, 11, Server 2019, 2022): interactive, silent, upgrade without re-enroll, repair, rollback at each stage, uninstall, wrong secret, unreachable server. Define and test the authenticated remote-uninstall workflow so Apps & features stays consistent. Update `docs/guides/installation.md` and the stale wizard text in `docs/Audspect_BAS_Product_Guide.md`; then deprecate the legacy exe.

## Execution

Tasks 1 and 2 are small and independent of the open decision, so they can run now. Recommended: native (inline) execution for Tasks 1-2, then review the plan again before Task 3.
