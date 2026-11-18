# Cobalt Group BFSI P2: Additional Persistence and C2 Variants Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 8 custom BFSI scenarios across two new packs — 4 persistence-technique variants and 4 C2-technique variants — that extend `scenarios/cobalt-group-kill-chain.yaml`'s existing persistence (T1543.003, T1053.005) and C2 (T1071.004) coverage without duplicating it.

**Architecture:** Two independent `appctlgen`-built packs, same shape as every pack built in P0/P1 (`header.yaml` + `stages.json` + `lib.ps1` + per-step `.ps1`/`.undo.ps1`, generated, signed with the project's real signer, verified live against this build host — no AD lab, no EDR). The C2 pack reuses the existing `bfsisim.Simulator` (started via `BFSI_SIMULATOR_HOST`/`BFSI_SIMULATOR_PORT`) as the lab-local target server for beaconing, ingress-transfer, and non-standard-port scenarios. The encrypted-channel scenario is fully local: a loopback `TcpListener` wrapped in `SslStream` using a short-lived `CurrentUser`-store self-signed certificate, torn down and removed at the end of the same step.

**Tech Stack:** Go (`appctlgen`, `signer.go`, `internal/scenario`, `internal/bfsisim`), PowerShell 5.1 scenario scripts, YAML scenario format.

**Spec:** The Cobalt Group BFSI Kill Chain spec the user supplied (pasted in full earlier in this session; priority table marks "additional persistence and C2 variants" as P2). No separate spec file exists; this plan is the design doc for P2, same as the (file-less) P0/P1 plans before it.

## Global Constraints

(Identical to every constraint P0/P1 already locked in — restated because every task's requirements implicitly include this section.)

- Always pass `appctlgen -common <pack's own source dir>` explicitly; its default is a different library entirely.
- `product_line: killchain` on every header — `bfsi` is invalid and causes silent scenario rejection.
- Never name a PowerShell variable or parameter `$Host`/`$host` (read-only automatic variable, case-insensitive collision, runtime error not caught by static parsing).
- Sign with `go run orchestrator/scripts/signer.go sign orchestrator/private_key.pem <file>` — never cosign.
- Grep for scenario-id uniqueness across `scenarios-src/*/header.yaml` before picking new pack ids.
- Every write scenario gets a per-id undo record (`Get-CgUndoPath`/`New-CgUndoRecord`/`Read-CgUndoRecord`/`Remove-CgUndoRecord`, exclusive `CreateNew`) with its own tag prefix (`BAS-PERS-`, `BAS-C2-`).
- Verify every scenario by running the assembled lib+step script for real on this build host before signing — inspection alone has missed real bugs every single time so far (P0: 5+ bugs, P1: 2 bugs).
- Sync with origin (`git fetch origin main && git merge --ff-only origin/main`) before every commit; a second session commits to `main` concurrently.
- Run the full unfiltered `go test ./internal/scenario -count=1 -timeout 420s` (not just `-run`) before calling the work done; targeted runs have missed real bugs (invalid product_line, duplicate ids) that the full suite catches.

## Review Focus

- **WMI event subscription cleanup (pers-02):** `Set-WmiInstance`-created `__EventFilter`/`__EventConsumer`/`__FilterToConsumerBinding` objects under `root\subscription` must all three be removed by undo, or a real persistence mechanism survives the test run on the build host. Task 1's live-verification step must assert all three are gone after undo, not just that the step itself ran.
- **Self-signed cert leakage (c2-02):** the loopback TLS cert this step creates must never be installed to `LocalMachine\Root` or any trusted store, must be removed from `CurrentUser\My` by undo, and the listener socket must be closed even if the handshake step throws. Task 2's live-verification step must assert the cert thumbprint is absent from the store after undo.
- **Local account persisted across a crashed run (pers-03/pers-04):** if the step process is killed mid-run, the synthetic test account must not be left enabled with group membership. Both scripts tag accounts with a per-run unique suffix (`$script:CgRun`, matching the existing `cred-*`/`lat-*` convention) and their undo scripts must succeed even when called with no prior successful create (idempotent `Remove-LocalUser`/`Remove-LocalGroupMember` wrapped to tolerate "already absent").
- **Beaconing pattern false-positive on a single request (c2-01):** a single HTTP GET to the simulator is indistinguishable from ordinary discovery traffic; the scenario must issue a genuinely periodic multi-request pattern (matching the structuring-pattern precedent in `fin-04`) so its own test logic — not a human reviewer — can tell beaconing from a one-off call.
- **Non-standard-port scenario silently degrading to the simulator's existing port (c2-04):** since `bfsisim.Simulator` already runs on a non-privileged, non-well-known port by construction, this scenario must explicitly assert the port it connects to is outside the well-known HTTP/HTTPS/DNS set (80, 443, 53) rather than relying on whatever port the simulator happened to bind, so the technique is actually exercised and not vacuously true.

---

### Task 1: Persistence Variants Pack

**Files:**
- Create: `scenarios-src/cobalt-group-bfsi-persistence-variants/header.yaml`
- Create: `scenarios-src/cobalt-group-bfsi-persistence-variants/stages.json`
- Create: `scenarios-src/cobalt-group-bfsi-persistence-variants/lib.ps1`
- Create: `scenarios-src/cobalt-group-bfsi-persistence-variants/pers-01.ps1` / `.undo.ps1` (T1547.001, Registry Run Key)
- Create: `scenarios-src/cobalt-group-bfsi-persistence-variants/pers-02.ps1` / `.undo.ps1` (T1546.003, WMI Event Subscription)
- Create: `scenarios-src/cobalt-group-bfsi-persistence-variants/pers-03.ps1` / `.undo.ps1` (T1136.001, Local Account Creation)
- Create: `scenarios-src/cobalt-group-bfsi-persistence-variants/pers-04.ps1` / `.undo.ps1` (T1098, Account Manipulation / group membership)
- Create (generated): `scenarios/cobalt-group-bfsi-persistence-variants.yaml` + `.yaml.sig`
- Modify: `orchestrator/internal/scenario/cobalt_bfsi_test.go` (add `"cobalt-group-bfsi-persistence-variants": 4` to the `want` map)

**Interfaces:**
- Consumes: the existing undo-record helpers and `$script:CgRun` per-run-id tagging pattern already used by every prior pack's `lib.ps1` (copy the pattern, not the file).
- Produces: nothing other packs depend on — this pack is a leaf.

- [ ] **Step 1: Write `lib.ps1`** with `Write-CgVerdict`/`Complete-CgStep`/`Get-CgUndoPath`/`New-CgUndoRecord`/`Read-CgUndoRecord`/`Remove-CgUndoRecord` (tag prefix `BAS-PERS-`), plus helpers: `New-CgTestAccountName` (returns `'bas-sim-pers-' + $script:CgRun + '-' + <suffix>`, never longer than 20 chars — the Windows `SAM_ACCOUNT_NAME` limit), `Test-CgRunKeyExists`, `Test-CgWmiSubscriptionExists`.

- [ ] **Step 2: Write `pers-01.ps1`/`.undo.ps1` (T1547.001).** Step creates `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\BAS-SIM-Test-<run>` pointing at a harmless command (`powershell.exe -NoProfile -Command exit`), reads it back, PASS if present and FAIL if the write silently didn't take (reflects whatever real Run-key write protections exist on this host). Undo removes that one named value only (never the whole `Run` key).

- [ ] **Step 3: Write `pers-02.ps1`/`.undo.ps1` (T1546.003).** Step creates a WMI `__EventFilter` (querying `__InstanceModificationEvent` on a synthetic `Win32_LocalTime` interval, never a real sensitive class), a `__EventConsumer` (`CommandLineEventConsumer` running the same harmless command as pers-01, or `LogFileEventConsumer` writing to a path under `$env:TEMP` — pick whichever the implementer finds more reliable to verify, since the plan does not pin consumer type), and the `__FilterToConsumerBinding`, all named with the per-run tag so they're individually identifiable; PASS if all three exist read back via `Get-WmiObject -Namespace root\subscription`, FAIL/ERROR otherwise. Undo removes the binding first, then the consumer, then the filter (reverse creation order, since WMI bindings reference the other two).

- [ ] **Step 4: Write `pers-03.ps1`/`.undo.ps1` (T1136.001).** Step creates one local user via `New-LocalUser` with a random `SecureString` password and `-AccountNeverExpires`, name from `New-CgTestAccountName`, PASS if `Get-LocalUser` finds it afterward. Undo calls `Remove-LocalUser` wrapped so an already-absent account (crashed prior run) does not cause the undo script itself to report FAIL — SKIP in that case, per the existing `fin-*` undo convention of tolerating "already gone."

- [ ] **Step 5: Write `pers-04.ps1`/`.undo.ps1` (T1098).** Step creates its own local user (independent of pers-03 — scenarios must not assume execution order) and adds it to the built-in `Users` group (never `Administrators` or any admin-equivalent group — this is a detection-surface test, not a privilege-escalation demo), PASS if `Get-LocalGroupMember` confirms membership. Undo removes group membership then deletes the account, both tolerant of "already gone."

- [ ] **Step 6: Parse-check all 8 new `.ps1` files** with `[System.Management.Automation.Language.Parser]::ParseFile`, 0 parse errors required (same PowerShell one-liner used for every prior pack).

- [ ] **Step 7: Generate and sign.** `appctlgen -src scenarios-src/cobalt-group-bfsi-persistence-variants -common scenarios-src/cobalt-group-bfsi-persistence-variants -out scenarios/cobalt-group-bfsi-persistence-variants.yaml`, then `go run orchestrator/scripts/signer.go sign orchestrator/private_key.pem scenarios/cobalt-group-bfsi-persistence-variants.yaml`.

- [ ] **Step 8: Live-verify all 4 scenarios end to end on this build host** (concatenate `lib.ps1` + each step script exactly as `appctlgen` assembles it, run via `powershell -NoProfile -File`), recording each verdict. This is the step that proves the Review Focus items for pers-02/pers-03/pers-04: after running all 4 undo scripts, re-check with `Get-WmiObject`/`Get-LocalUser`/`Get-LocalGroupMember`/the registry path that nothing persists — zero leftover state is the pass condition for this step, not merely "undo printed PASS."

- [ ] **Step 9: Add `"cobalt-group-bfsi-persistence-variants": 4` to the `want` map in `cobalt_bfsi_test.go`**, run `go test ./internal/scenario -run TestCobaltBFSIPacks_ParseWithCommandAndCleanup -v -count=1`, expect PASS.

- [ ] **Step 10: Sync with origin and commit.** `git fetch origin main && git merge --ff-only origin/main`, then commit the 11 new files + the test map edit.

### Task 2: C2 Variants Pack

**Files:**
- Create: `scenarios-src/cobalt-group-bfsi-c2-variants/header.yaml`
- Create: `scenarios-src/cobalt-group-bfsi-c2-variants/stages.json`
- Create: `scenarios-src/cobalt-group-bfsi-c2-variants/lib.ps1`
- Create: `scenarios-src/cobalt-group-bfsi-c2-variants/c2-01.ps1` / `.undo.ps1` (T1071.001, HTTP/S beaconing)
- Create: `scenarios-src/cobalt-group-bfsi-c2-variants/c2-02.ps1` / `.undo.ps1` (T1573, Encrypted Channel)
- Create: `scenarios-src/cobalt-group-bfsi-c2-variants/c2-03.ps1` / `.undo.ps1` (T1105, Ingress Tool Transfer)
- Create: `scenarios-src/cobalt-group-bfsi-c2-variants/c2-04.ps1` / `.undo.ps1` (T1571, Non-Standard Port)
- Create (generated): `scenarios/cobalt-group-bfsi-c2-variants.yaml` + `.yaml.sig`
- Modify: `orchestrator/internal/scenario/cobalt_bfsi_test.go` (add `"cobalt-group-bfsi-c2-variants": 4` to the `want` map)

**Interfaces:**
- Consumes: `bfsisim.Simulator` via `BFSI_SIMULATOR_HOST`/`BFSI_SIMULATOR_PORT` (same env-var contract as every discovery/collection/financial-impact pack) for c2-01, c2-03, c2-04. No consumer for c2-02 (fully local).
- Produces: nothing other packs depend on — this pack is a leaf.

- [ ] **Step 1: Write `lib.ps1`** with the standard verdict/undo helpers (tag prefix `BAS-C2-`), `Get-BfsiSimulatorHost`/`Get-BfsiSimulatorPort`/`Test-BfsiSimulatorConnectivity` (copy from `cobalt-group-bfsi-financial-impact/lib.ps1`'s equivalents verbatim — same env vars, same defaults), plus `New-CgLoopbackTlsCertificate` (creates a `CurrentUser\My` self-signed cert with a short `NotAfter`, returns its thumbprint) and `Remove-CgLoopbackTlsCertificate` (thumbprint -> `Remove-Item Cert:\CurrentUser\My\<thumbprint>`).

- [ ] **Step 2: Write `c2-01.ps1`/`.undo.ps1` (T1071.001).** Step SKIPs if the simulator is unreachable; otherwise issues 5 GET requests to `/api/banking/apps` at roughly 1-second intervals (periodic pattern, per Review Focus) and records each response's timestamp and status; PASS if all 5 succeeded with strictly increasing timestamps (reflects whether this traffic pattern is distinguishable as beaconing — the test's own logic is what's being proven, same framing as the financial-impact pack). No state is created, so undo is a no-op PASS (same pattern as `fin-07.undo.ps1`).

- [ ] **Step 3: Write `c2-02.ps1`/`.undo.ps1` (T1573).** Step creates the loopback cert, starts a local `TcpListener` on `127.0.0.1:0`, wraps the accepted socket in `SslStream` with that cert, sends one short synthetic payload from a client `SslStream` over the negotiated channel, PASS if the handshake and payload round-trip succeed. The listener and both `SslStream`s must close in a `finally` block even on handshake failure (Review Focus: socket must close even if the handshake throws). Undo calls `Remove-CgLoopbackTlsCertificate` on the thumbprint recorded in the undo record; tolerant of "already gone."

- [ ] **Step 4: Write `c2-03.ps1`/`.undo.ps1` (T1105).** Step SKIPs if the simulator is unreachable; otherwise GETs `/api/banking/apps` from the simulator (standing in for a C2-hosted "tool"), writes the response body to a file under `$env:TEMP\bas-sim-c2\<run>.bin`, PASS if the file exists afterward with non-zero length matching the downloaded byte count. Undo deletes that one file and its parent directory if empty.

- [ ] **Step 5: Write `c2-04.ps1`/`.undo.ps1` (T1571).** Step SKIPs if the simulator is unreachable; otherwise reads the simulator's actual port from `Get-BfsiSimulatorPort`, asserts it is not in `80, 443, 53` (Review Focus: must not vacuously pass), then issues one GET to confirm connectivity on that non-standard port. PASS if both the port-not-well-known assertion and the GET succeed; FAIL if the port happens to be a well-known one (makes the scenario fail loud rather than silently pass, if the simulator's binding ever changes). No state created; undo is a no-op PASS.

- [ ] **Step 6: Parse-check all 8 new `.ps1` files**, 0 parse errors required.

- [ ] **Step 7: Generate and sign.** `appctlgen -src scenarios-src/cobalt-group-bfsi-c2-variants -common scenarios-src/cobalt-group-bfsi-c2-variants -out scenarios/cobalt-group-bfsi-c2-variants.yaml`, then sign with `signer.go`.

- [ ] **Step 8: Live-verify all 4 scenarios end to end** against a real running `bfsisim-lab` process (built the same way Task 4 of the P1 plan did: `go build -o bfsisim-lab.exe ./cmd/bfsisim-lab`, run with `-addr 127.0.0.1:9999`, set `BFSI_SIMULATOR_HOST`/`PORT` env vars). For c2-02 specifically, after running its undo, re-check `Get-ChildItem Cert:\CurrentUser\My` for the recorded thumbprint and confirm it is absent (Review Focus).

- [ ] **Step 9: Add `"cobalt-group-bfsi-c2-variants": 4` to the `want` map**, run the parse test, expect PASS.

- [ ] **Step 10: Sync with origin and commit.**

### Task 3: Integration Test, Full-Suite Verification, QA Log

**Files:**
- Modify: `orchestrator/internal/scenario/cobalt_bfsi_test.go` (add one new integration test)
- Modify: `docs/cobalt-group-bfsi-mastery-qa-log.md` (append P2 section)

**Interfaces:**
- Consumes: `findStepByActionKey`/`findStepByTechnique`/`runCobaltBFSIPowerShell` helpers already defined in `cobalt_bfsi_test.go` (Task 1/2's packs must set a unique `action_key` per step, following the existing convention, so this task's lookup is unambiguous).

- [ ] **Step 1: Write `TestCobaltBFSICSVariants_BeaconPatternAgainstLiveSimulator`.** Runs the real c2-01 command (via `findStepByActionKey` against the generated `cobalt-group-bfsi-c2-variants.yaml`) against a live `bfsisim.NewSimulator("127.0.0.1:0")` (not a mock, matching every existing integration test in this file), asserts the verdict tag is present and the verdict is `PASS:`.

- [ ] **Step 2: Run it.** `go test ./internal/scenario -run TestCobaltBFSICSVariants -v -count=1`, expect PASS.

- [ ] **Step 3: Run the full unfiltered suite.** `go test ./internal/scenario -count=1 -timeout 420s` (background it; it takes several minutes). Confirm zero failures and no "refusing to load"/"duplicate id" warnings for any `cobalt-group-bfsi-*` file.

- [ ] **Step 4: Run `go run orchestrator/scripts/signer.go verify-all scenarios`**, confirm `fail=0` and both new `.yaml` files are in the `ok` set.

- [ ] **Step 5: Append the P2 section to `docs/cobalt-group-bfsi-mastery-qa-log.md`**, matching the P0/P1 sections' exact format (Scope / What was built / What was verified for real / Bugs found and fixed / Honest limits) — honest limits must note no real AD/EDR lab, and that pers-02's `CommandLineEventConsumer`-vs-`LogFileEventConsumer` choice (left open in Task 1 Step 3) gets recorded as whichever the implementer picked.

- [ ] **Step 6: Sync with origin and final commit + push.**

---
