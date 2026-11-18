# Cobalt Group BFSI P0 - QA Log

## Scope
P0 of the Cobalt Group BFSI enterprise expansion (full 9-phase spec covers 40-45 scenarios; P0 is
credential access, lateral movement, and BFSI service discovery, chosen to establish the attack-path
narrative before layering in collection/exfiltration, defense evasion, and the financial-impact
simulator). This extends `scenarios/cobalt-group-kill-chain.yaml` (the existing 8-stage campaign),
not replace it; `product_line: killchain` on all three new packs matches that campaign.

## What was built (2026-11-18, Windows 10 Pro build host, no EDR, no Sysmon, no enforcement)
- `cobalt-group-bfsi-credential-access.yaml` (8 steps): LSASS/SAM access simulation, Credential
  Manager and browser credential discovery, Kerberoasting and AS-REP roasting against synthetic test
  principals, password spraying, unsecured credential file discovery.
- `cobalt-group-bfsi-lateral-movement.yaml` (6 steps): RDP/SMB/WinRM connectivity checks, remote
  service enumeration, system discovery, lateral tool transfer to a sandbox path. All target
  `$env:BAS_TEST_HOST`; SKIP when unset.
- `cobalt-group-bfsi-discovery.yaml` (4 steps): banking app, payment gateway, ATM switch, and
  cardholder-data-location discovery against a deterministic HTTP stub
  (`internal/bfsisim`, `cmd/bfsisim-lab`), not a live banking API.
- All three generated via `appctlgen`, signed with the project's RSA signer
  (`orchestrator/scripts/signer.go`), 18/18 scenarios verify (`verify-all`).

## What was verified for real
- All 36 PowerShell files (18 steps + 18 undo scripts) parse clean
  (`[System.Management.Automation.Language.Parser]::ParseFile`, 0 failures).
- `go test ./internal/scenario` (full package, not just these packs): the three new scenario files
  load without the engine's "refusing to load" / "duplicate id" warnings, and the project-wide
  scenario count (`TestBuiltinScenarios_AllHaveValidProductLine`) reflects their presence.
- `TestCobaltBFSIAttackPath_CredentialToDiscoveryCorrelation` (`internal/scenario/cobalt_bfsi_test.go`)
  runs the real cred-01 PowerShell command and the real bfsi-01 PowerShell command back to back
  against a live `bfsisim.Simulator` instance on a loopback port (no mocking of either the shell or
  the HTTP layer), and asserts: both produce a classifiable verdict with the expected `[BAS-*]` tag,
  the discovery step's verdict text reflects the simulator's actual service count (not a hardcoded
  expectation), and the two steps' wall-clock timestamps are strictly increasing.
- All 4 discovery steps (bfsi-01..04) were run by hand against a real `bfsisim-lab` process: each
  correctly reports FAIL (discovery succeeded, services found) with the simulator up, and bfsi-01
  correctly reports SKIP ("prerequisite not met") with no simulator listening on the configured port.
- `go test ./internal/bfsisim` (3 tests): all four HTTP endpoints serve non-empty JSON; non-GET
  methods are rejected.
- lat-01 was run end to end (lib + step concatenated exactly as `appctlgen` assembles it): SKIP with
  `BAS_TEST_HOST` unset, FAIL (port reachable) with it set to a loopback address.

## Bugs found and fixed during this work (all confirmed via live execution, not inspection alone)
- `appctlgen -common` defaults to an unrelated library; the first generation of all 18 scenarios
  embedded the wrong lib.ps1, so every command/cleanup block called undefined functions. Fixed by
  passing `-common` explicitly to each pack's own source directory.
- `$Host` / `$host` is a PowerShell read-only automatic variable; confirmed live that binding or
  assigning it throws "Cannot overwrite variable Host because it is read-only or constant". Three
  lib functions and five lateral-movement step scripts used it as a parameter/local name; renamed to
  `$TargetHost` / `$simHost`.
- Five lateral-movement step scripts used `$res = $host = $env:BAS_TEST_HOST; if (...) else (...)`,
  which assigns `$res` to the env-var string and discards the if/else result entirely. Rewritten as a
  plain if/else.
- A literal tab character was embedded in a destination path string in lat-06.ps1 (generation
  artifact); fixed to a literal backslash-separated path.
- The discovery lib's URI construction had a stray space before the port's colon
  (`"http://$host :$port..."`), producing an invalid URI; fixed interpolation.
- An unused `New-TestAccount` helper paired `SecureStringToCoTaskMemAnsi` with `PtrToStringAuto`
  (ANSI/Unicode mismatch); simplified to pass the SecureString directly to `New-LocalUser -Password`.
- `product_line: bfsi` is not a value `internal/license.ValidProductLine` accepts; the engine was
  rejecting all 18 scenarios at load time ("refusing to load"). Fixed to `killchain`.
- **Pre-existing, found by this session's full-suite run**: all 5 `cloud-vm-linux-*` headers from a
  prior session's kill-safe-undo work had `id:` and `supported_os:` copied verbatim from their
  Windows counterparts. Each Linux pack's id collided with its Windows twin, so the loader kept only
  the Windows file and silently dropped every Linux scenario -- the entire Linux cloud-vm kill-safe
  undo campaign had been inert since it was committed. Fixed ids to `cloud-vm-linux-<pack>` and
  `supported_os` to `[linux]`; re-signed.
- `TestBuiltinScenarios_AllHaveValidProductLine`'s pinned scenario count (169) was stale after the
  above fixes plus a concurrent session's new DLP scenarios; re-measured and bumped to 180.

## Honest limits
- No real AD lab, Windows domain, or EDR/SIEM was used. Credential-access and lateral-movement steps
  were verified for correct PowerShell execution and verdict classification, not against a real
  Kerberos realm, SMB share, or managed identity -- see memory note on cloud-vm/AD-mastery lab work
  for the same caveat pattern.
- `cobalt-group-bfsi-lateral-movement` needs `BAS_TEST_HOST` set to a reachable lab VM to produce
  anything other than SKIP; no dedicated lateral-movement test target was stood up this session.
- The banking simulator (`internal/bfsisim`) returns a fixed synthetic catalog; it is not connected
  to any real core-banking, payment-gateway, or ATM-switch API, and was never intended to be -- it
  exists to give the discovery scenarios something deterministic to query.
- Evidence correlation is proven at the level the plan asked for (timestamps, verdict tags, real
  simulator response reflected in the verdict text) via one Go test exercising one step per pack. It
  does not exercise the orchestrator's full dispatch/run-grouping path (`internal/campaign`), which
  computes rollups from already-dispatched child runs rather than from a static catalog; wiring a
  full multi-run campaign dispatch for this pack is future work, not part of P0.
- P1 (collection/exfiltration, defense evasion expansion) and P2 (advanced persistence/C2 variants,
  the financial-impact/ATM-cash-out simulator) are not started.

---

# Cobalt Group BFSI P1 - QA Log

## Scope
P1 of the Cobalt Group BFSI expansion: Phase 8 (Collection/Exfiltration), the remainder of Phase 4
(Defense Evasion), and Phase 9 Part 2 (the financial-impact simulator). Plan:
`docs/superpowers/plans/2026-11-18-cobalt-group-bfsi-p1.md`. Every P0 bug class (wrong `appctlgen
-common`, `$Host`/`$host` misuse, invalid `product_line`, duplicate scenario ids) was checked against
from the start of this work and did not recur.

## What was built (2026-11-18, Windows 10 Pro build host, no EDR, no Sysmon, no enforcement)
- `cobalt-group-bfsi-collection-exfil.yaml` (6 steps): local data collection, network share
  collection, email-client presence check, archive creation, simulated exfil-over-C2 (posts to the
  bfsisim ledger), DNS exfiltration probe against a `.invalid` subdomain (RFC 6761, never resolves).
- `cobalt-group-bfsi-defense-evasion.yaml` (7 steps): security-software discovery, a gated read-only
  Defender-preferences permission probe, PowerShell `-EncodedCommand` detection test, masquerading-
  executable detection test, registry-modification detection test (`HKCU:\Software\BAS-SIM-Test`
  only), non-destructive event-log clearing (a dedicated synthetic `BAS-SIM-Test` log only, never
  Security/System/Application), process-injection detection-readiness check (no actual injection
  performed).
- `internal/bfsisim/ledger.go`: extends the P0 discovery simulator with a mutex-guarded in-memory
  transaction ledger (`POST/GET/DELETE /api/ledger/transactions[/{id}]`, `POST /api/ledger/reconcile`).
  Never connects to a real core-banking, payment, or ATM system.
- `cobalt-group-bfsi-financial-impact.yaml` (7 steps, custom BFSI scenarios -- header notes not all
  map to documented Cobalt Group tradecraft): transaction-record manipulation, payment-instruction
  manipulation, ATM dispense-workflow manipulation, fraudulent transaction-pattern simulation,
  transaction-limit bypass, financial-reconciliation manipulation, a read-only resilience check.
- All generated via `appctlgen -common <pack's own dir>` (passed explicitly every time), signed with
  `orchestrator/scripts/signer.go` (never cosign), `product_line: killchain` on every header.

## What was verified for real
- All 32 new PowerShell files (14 collection-exfil, 14 defense-evasion, 14 financial-impact step+undo
  scripts) parse clean.
- Every one of the 20 new scenarios was run end to end (lib+step concatenated exactly as `appctlgen`
  assembles it) on this build host, not just inspected: coll-01/03/04 FAIL (ran, unenforced),
  coll-02/05 SKIP (no target/simulator), coll-06 PASS; eva-01/03/04/05/06 FAIL (ran, unenforced),
  eva-02 SKIP (ungated), eva-07 PASS; fin-01/02/03/04/06/07 PASS against a live `bfsisim-lab`
  process, fin-05 honestly FAILs (the stub ledger does not itself enforce a transaction limit).
- Ran every financial-impact undo script against the live ledger and confirmed via a live GET that
  it ends up completely empty -- zero leftover transactions, not a wildcard sweep.
- `internal/bfsisim`: 5 tests pass, including a full ledger CRUD+reconcile test and a 20-goroutine
  concurrent-write test (`-count=30` stress run, no `-race` available on this host -- no cgo).
- Added `TestCobaltBFSIFinancialImpact_LedgerManipulationDetected`: runs the real fin-01 command
  against a live `bfsisim.Simulator`, asserts PASS and exactly one surviving transaction.
- Full, unfiltered `go test ./internal/scenario -count=1` (not a targeted `-run`): clean pass,
  307s, zero failures -- no "refusing to load" or "duplicate id" warnings for any
  `cobalt-group-bfsi-*` file. `signer.go verify-all scenarios`: ok=228 fail=0.

## Bugs found and fixed during this work (all confirmed via live execution)
- `lib.ps1`'s `Invoke-EncodedCommandProbe` (defense-evasion pack) matched the live command's stdout
  against the *command text being run* instead of its expected printed marker -- it could never
  match, so eva-03 would always report PASS regardless of whether the encoded command actually ran.
  Split into separate `PlainText` (what runs) and `ExpectMarker` (what to look for) parameters.
- `eva-04.ps1` and `eva-07.ps1` both called `$proc.WaitForExit(N)` unpiped, leaking its boolean
  return value as a stray "True" line concatenated before the verdict text. Piped both to `Out-Null`.
  Found only by actually running the assembled scripts and reading their real stdout.

## Honest limits
- No real AD lab, Windows domain, or EDR/SIEM. All verdicts reflect this unenforced build host's
  actual state (e.g. eva-01 correctly FAILs because Windows Defender's `MsMpEng` process is genuinely
  running here) -- they are not simulated or hand-picked.
- `coll-02` (network share collection) needs `BAS_TEST_HOST`; no dedicated test target was stood up.
- The financial-impact pack's control logic is intentionally simple (409-on-duplicate-id models
  "integrity controls reject in-place changes"; the ledger has no real limit enforcement, which
  fin-05 surfaces honestly as a FAIL). It is not a model of any real core-banking or payment system's
  actual fraud/limit logic -- it exists to exercise the scenario and evidence-classification layer.
- Reconciliation-based scenarios (fin-03/04/06) compute their own pre-write ledger total dynamically
  rather than assuming a clean ledger, since all fin-* steps in one run share the same ledger
  instance; this makes them correct regardless of step execution order, but a scenario outside this
  pack that also posts to `/api/ledger/transactions` without cleaning up would still be visible to
  these totals (same caveat as any shared-fixture integration target).
- P2 (additional persistence and C2 variants) is not started. Phase 1 (reconnaissance) and Phase 2
  (initial access) remain out of scope, as agreed before P0.

---

# Cobalt Group BFSI P2 - QA Log

## Scope
P2 of the Cobalt Group BFSI expansion: additional persistence and C2 technique variants beyond the
campaign's existing coverage (persistence: T1543.003 service, T1053.005 scheduled task; C2: T1071.004
DNS). Plan: `docs/superpowers/plans/2026-11-18-cobalt-group-bfsi-p2.md`.

## What was built (2026-11-18, Windows 10 Pro build host, no EDR, no Sysmon, no enforcement, run as Administrator)
- `cobalt-group-bfsi-persistence-variants.yaml` (4 steps): registry Run key value (T1547.001), WMI event
  subscription filter/consumer/binding under `root\subscription` (T1546.003), local account creation
  (T1136.001), account membership change limited to the built-in Users group (T1098).
- `cobalt-group-bfsi-c2-variants.yaml` (4 steps): HTTP/S periodic beaconing to the lab simulator
  (T1071.001), encrypted channel over a loopback TLS session with a CurrentUser\My self-signed cert
  (T1573), ingress tool transfer from the simulator into a per-run temp dir (T1105), traffic on the
  simulator's non-standard port (T1571).
- Generated via `appctlgen -common <pack's own dir>`, signed with `orchestrator/scripts/signer.go`,
  `product_line: killchain` on every header.
- Integration tests: `TestCobaltBFSICSVariants_BeaconPatternAgainstLiveSimulator` runs the real c2-01
  command against a live `bfsisim.Simulator`; the parse test's `want` map covers both packs.

## What was verified for real
- All 18 new PowerShell files (each pack: lib.ps1 plus 4 step and 4 undo scripts) parse clean.
- Every step was run for real on this host, not inspected: pers-01/03/04 PASS; pers-02 PASS after a fix
  (see below); c2-01/03/04 PASS against a live `bfsisim-lab`; c2-02 PASS after a fix.
- Every undo was run, then residue was checked directly on the host:
  - persistence: no `BAS-SIM-pers-*` Run values, no `bas-pers-*` local accounts, no `bas-pers-*`
    Users group members, zero `BAS-SIM-pers-*` WMI filters/consumers/bindings.
  - C2: no loopback localhost certs with a short NotAfter in CurrentUser\My, no `bas-sim-c2` temp dir,
    and the CNG key-file count under %APPDATA%\Microsoft\Crypto is unchanged across a run (before=140 after=140).
- A partially failed pers-02 run left a WMI filter and its undo record behind; running its undo removed
  the filter, confirming undo handles partial state, not just complete state.
- `go test ./internal/scenario -run TestCobaltBFSI` passes (parse test plus the c2-01 live integration test).
- Full unfiltered `go test ./internal/scenario -count=1 -timeout 420s`: ok, zero failures, 317s (run after the final C2 fixes, commit d507e822).
- `signer.go verify-all scenarios`: ok=230 fail=0 with both new packs in the ok set.

## Bugs found and fixed during live verification
- pers-02 (WMI): `Set-WmiInstance` returns an object with an empty `__PATH`, so the
  `__FilterToConsumerBinding` was built from null references and threw "Illegal null value". Fixed by
  re-reading the created filter and consumer by name and binding with `__RELPATH`.
- c2-02 (loopback TLS): the certificate-validation callback was a PowerShell scriptblock, which throws
  when invoked on the .NET thread-pool thread (no runspace). Fixed with a compiled `Add-Type` delegate
  that accepts the loopback test certificate. The client handshake is now async with a synchronous
  server-side auth, avoiding `Task.Run` over a scriptblock.
- c2-02 (key residue): removing the certificate from `Cert:\CurrentUser\My` left its CNG private-key
  file on disk (one per run, measured: 139 -> 140 -> 140 after remove). Fixed by deleting the key via
  `RSACertificateExtensions.GetRSAPrivateKey(...).Key.Delete()` before removing the certificate.
  Found by an independent review, then confirmed on this host.
- c2-02 (blocking handshake): the server-side accept and `AuthenticateAsServer` were synchronous with no
  timeout, so a client that never completes the handshake would hang the step and skip its `finally`
  cleanup. Replaced with async accept, async server auth and async read, each bounded by a 5 second
  wait, with a timeout throwing into the `finally`. Found by review. The timeout path is not exercised
  live; the normal path was re-run after the change.
- c2-04 (port guard): the guard covered only 80, 443 and 53. It now rejects every port below 1024.
- c2-03 (tool transfer): the undo removed the per-run directory but left its empty parent
  `bas-sim-c2` behind. Fixed by also removing the parent when empty, as the plan specified.

## Honest limits
- No AD lab, no EDR, no Sysmon. These verdicts reflect this host's actual unenforced state, not a
  controlled detection test. A PASS for pers-02 means the WMI subscription was created, not that any
  monitoring saw it.
- pers-02 uses a `CommandLineEventConsumer` (the plan left the consumer type open). It runs a no-op
  `exit` command, so even when the filter fires the subscription does nothing harmful. It is a
  persistence artifact only.
- Review findings accepted as rulings, not fixed: the pers-02 WMI subscription fires every 60 seconds
  while it exists, so it is visible if undo never runs (by design: it is a persistence artifact test).
  The c2-01 "strictly increasing timestamps" check is nearly vacuous and does not measure interval
  regularity or jitter; the five 1-second sleeps are the real pattern. The stale-undo-record ERROR path
  matches the P0/P1 convention and is left as is.
- c2-02 accepts any server certificate (validation callback returns true). This is deliberate: the
  listener is loopback-only and the cert is the step's own ephemeral one. It is not a model of any
  real TLS trust decision.
- c2-01 and c2-03 target the lab simulator, not a real C2 infrastructure. Beaconing detection depends
  on a periodic pattern, not on realistic C2 traffic shape.
- P2 is complete for the four persistence and four C2 variants in the plan. Reconnaissance and initial
  access remain out of scope, as agreed before P0.

---

# Cobalt Group BFSI P3 - QA Log

## Scope
P3: the reconnaissance gap in the campaign's Phase 1. Plan:
`docs/superpowers/plans/2026-11-18-cobalt-group-bfsi-p3-recon.md`.

## Audit (what was already covered before P3)
Checked every Phase 1 and Phase 2 technique in the spec against the scenario library and the repo:
- Covered by existing scenarios: T1016, T1018, T1087.002, T1069.002, T1046, T1204.002, T1190,
  T1218.005, T1218.011.
- Covered, but thinly: T1078.002 (only in a privileged-account audit scenario) and T1059.003 (one
  AppControl scenario).
- Covered by the phishing catalog, not the scenario library: T1566.002 (spearphishing link), in
  `orchestrator/internal/phishcatalog`. An earlier audit that searched only `scenarios/*.yaml`
  wrongly listed it as missing.
- Missing as executable scenarios: T1590.001 (subdomain reconnaissance) and T1589.003 (employee
  identity discovery). They appeared only as ATT&CK metadata.

## What was built (2026-11-18, Windows 10 Pro build host)
- `internal/bfsisim/directory.go`: `GET /api/directory/identities`, six fixed synthetic identities
  with `bas-sim-` prefixes. Covered by `TestSimulator_DirectoryListsSyntheticIdentities`.
- `cobalt-group-bfsi-recon.yaml` (2 steps):
  - recon-01 (T1590.001): eight A-record queries for names under `bas-sim.test`, the reserved
    `.test` TLD.
  - recon-02 (T1589.003): reads the synthetic identity directory from the lab simulator. SKIPs when
    the simulator is down.

## What was verified for real
- Both steps ran on this host against a live `bfsisim-lab`.
  - recon-01: PASS, 8 of 8 queries attempted, all NXDOMAIN.
  - recon-02: PASS, 6 identities. With the simulator's port closed, SKIP.
- recon-01 only ever queried `.test` names. The step refuses any other name, and the run's output
  confirms all eight names.
- The undo scripts were run. Both are no-op PASSes because neither step creates state.
- Full unfiltered `go test ./internal/scenario -count=1 -timeout 420s`: see the result line below.
- `signer.go verify-all scenarios`: ok=239 fail=0.

## Bug found and fixed during live verification
- recon-02 returned FAIL with "only 1 identities" against an endpoint that returns six. The cause
  was `$ids = @(Invoke-RestMethod ...)`. `Invoke-RestMethod` emits the JSON array as one object, so
  the `@(...)` wrapper produced a one-element array containing the whole array. Fixed by assigning
  the call to a variable first, then reading `.Count`.
- The same wrapping pattern exists in the financial-impact library's `Get-CgLedgerTransactions`,
  which assigns the call to `$r` before `@($r)`. That is correct. A direct test confirmed the pre-write
  total is 300 for two known transactions, so the financial pack's reconciliation is not affected.

## Honest limits
- recon-02 queries only the synthetic simulator directory. A real Active Directory user enumeration
  (LDAP or ADSI against a lab domain) is not covered. It needs a domain-joined lab host.
- recon-01 depends on the local resolver handling `.test` names as NXDOMAIN. A resolver that
  forwards them upstream would make the queries leave the host, though they would still never
  resolve to a real domain.
- The phishing link variant (T1566.002) is not re-verified here. Its coverage comes from the
  existing phishing catalog, which this audit did not run.
- Full unfiltered suite: ok, zero failures, 298.9s.
