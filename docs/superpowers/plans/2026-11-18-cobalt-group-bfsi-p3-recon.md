# Cobalt Group BFSI P3: Reconnaissance Gap Implementation Plan

> **For agentic workers:** Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the two reconnaissance techniques from the spec's Phase 1 that have no executable scenario: domain/subdomain reconnaissance (T1590.001) and employee/identity discovery (T1589.003).

**Architecture:** One new pack `cobalt-group-bfsi-recon` with two scenarios, same shape as the P0-P2 packs. recon-01 resolves a synthetic subdomain wordlist under the reserved `.test` TLD (RFC 6761), so it can never reach a real domain. recon-02 queries a new `/api/directory/identities` endpoint on the lab `bfsisim` simulator, backed by synthetic identities. A real AD directory query is out of scope here and stays a SKIP on hosts without a lab domain.

**Tech Stack:** Go (`internal/bfsisim`, `internal/scenario`), PowerShell scenario scripts, `appctlgen`, `signer.go`.

**Spec:** The Cobalt Group BFSI campaign spec, Phase 1 (Reconnaissance and target discovery), quoted in the transcript. Audit of existing coverage: the 12 other Phase 1-2 techniques are already covered by existing scenarios, the phishing catalog (T1566.002), or kill chains. Only T1590.001 and T1589.003 are missing as executable scenarios.

## Global Constraints

- `appctlgen -common <pack's own dir>` passed explicitly every time.
- `product_line: killchain` on the header.
- Never name a PowerShell variable `$Host`/`$host`.
- Sign with `orchestrator/scripts/signer.go`, never cosign.
- Pack id and scenario ids checked for uniqueness before creating.
- Every step verified live on this host before signing.
- Full unfiltered `go test ./internal/scenario -count=1 -timeout 420s` before calling done.
- Sync with origin before every commit.

## Review Focus

- **Real domain leakage (recon-01):** the wordlist must only ever be joined to `bas-sim.test`. A test asserts no generated query name ends in anything other than `.test`.
- **Identity data leaving the lab (recon-02):** the simulator must return only synthetic identities, and the endpoint must be lab-only (bound to the simulator's loopback address by default, same as every other bfsisim endpoint).
- **Empty-directory false PASS (recon-02):** an empty identity list must be a FAIL ("directory returned no identities"), not a PASS, because a silent empty directory would hide a broken lab.

---

### Task 1: Simulator identity directory endpoint

**Files:**
- Create: `orchestrator/internal/bfsisim/directory.go`
- Modify: `orchestrator/internal/bfsisim/simulator.go` (register the route in `NewSimulator`'s mux)
- Test: `orchestrator/internal/bfsisim/directory_test.go`

**Interfaces:**
- Produces: `GET /api/directory/identities` returns JSON `[]Identity`, where `Identity` is `{ "sam": string, "displayName": string, "department": string }`. Synthetic data only; at least 5 entries.

- [ ] **Step 1: Write the failing test** `TestSimulator_DirectoryListsSyntheticIdentities`: start a simulator, GET `/api/directory/identities`, assert status 200, at least 5 entries, every `sam` starts with `bas-sim-`.
- [ ] **Step 2: Run it, expect FAIL** (route not registered, 404): `go test ./internal/bfsisim -run TestSimulator_DirectoryListsSyntheticIdentities -count=1`
- [ ] **Step 3: Implement** `directory.go` with a fixed slice of identities and a handler registered in `NewSimulator`.
- [ ] **Step 4: Run it, expect PASS.** Then `go test ./internal/bfsisim -count=1` expect all pass.
- [ ] **Step 5: Commit.**

### Task 2: Recon pack scripts

**Files:**
- Create: `scenarios-src/cobalt-group-bfsi-recon/{header.yaml,stages.json,lib.ps1,recon-01.ps1,recon-01.undo.ps1,recon-02.ps1,recon-02.undo.ps1}`
- Create (generated): `scenarios/cobalt-group-bfsi-recon.yaml` + `.yaml.sig`
- Modify: `orchestrator/internal/scenario/cobalt_bfsi_test.go` (add `"cobalt-group-bfsi-recon": 2` to the `want` map)

**Interfaces:**
- Consumes: `/api/directory/identities` from Task 1 via `BFSI_SIMULATOR_HOST`/`BFSI_SIMULATOR_PORT`.

- [ ] **Step 1: Write `header.yaml`** (id `cobalt-group-bfsi-recon`, `product_line: killchain`, `mitre_phases: [reconnaissance]`) and `stages.json` with two steps: `recon-01` (technique `T1590.001`, action_key `recon_subdomain_enumeration`) and `recon-02` (technique `T1589.003`, action_key `recon_employee_discovery`).
- [ ] **Step 2: Write `lib.ps1`** with the standard verdict/undo helpers (tag prefix `BAS-RECON-`) and `Test-BfsiSimulatorConnectivity` copied from the financial-impact pack.
- [ ] **Step 3: Write `recon-01.ps1`.** Build a wordlist of 8 names (`www, mail, api, vpn, portal, intranet, sso, dev`), query each as `<name>.bas-sim.test` with `Resolve-DnsName -Type A -DnsOnly -ErrorAction SilentlyContinue`, count queries attempted and queries that returned a classifiable result (answered or NXDOMAIN). PASS if all 8 were attempted, FAIL if the resolver call itself was unavailable for any. Undo: no state, PASS no-op.
- [ ] **Step 4: Write `recon-02.ps1`.** SKIP if the simulator is unreachable. GET `/api/directory/identities`. FAIL if the list is empty (Review Focus). PASS if at least 5 identities came back and every `sam` starts with `bas-sim-`. Undo: no state, PASS no-op.
- [ ] **Step 5: Parse-check all scripts**, 0 errors.
- [ ] **Step 6: Generate, sign, verify.**
- [ ] **Step 7: Live-verify both steps** against a running `bfsisim-lab` (`-addr 127.0.0.1:9999`). Record each verdict. Also confirm recon-01 never issued a query outside `.test` (the Review Focus item): read the generated query names from the step output.
- [ ] **Step 8: Add the `want` entry, run `go test ./internal/scenario -run TestCobaltBFSIPacks_ParseWithCommandAndCleanup -count=1`.**
- [ ] **Step 9: Commit.**

### Task 3: Verification and QA log

- [ ] **Step 1:** Full unfiltered `go test ./internal/scenario -count=1 -timeout 420s` in the background, expect ok with zero failures.
- [ ] **Step 2:** `signer.go verify-all scenarios`, expect fail=0.
- [ ] **Step 3:** Append the P3 section to `docs/cobalt-group-bfsi-mastery-qa-log.md`, with the audit result (what was already covered, what was missing), the live verdicts, and honest limits (no real AD directory query; `.test` resolution depends on the local resolver's behaviour).
- [ ] **Step 4:** Commit and push.
