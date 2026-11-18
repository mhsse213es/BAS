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
