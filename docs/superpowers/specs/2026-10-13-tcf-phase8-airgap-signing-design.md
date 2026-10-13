# TCF Phase 8 — Air-Gap Distribution Integrity Design

**Status:** approved for spec; implementation plan to follow via `writing-plans`.

**Goal:** make the air-gap distribution pipeline (`packaging/airgap/{pack,verify,import}.sh` + `packaging/compose/setup.sh`) fail closed on authenticity and integrity before any Docker image is loaded or any host state is mutated, fix the sequencing/path defects that currently make this impossible even in principle, and define explicit, non-destructive recovery behavior for interrupted installs.

**Why this supersedes the original Phase 8 framing:** the roadmap originally scoped this as "wire cosign into airgap." Two rounds of code-backed gap analysis (2026-10-13) established that framing was wrong on every point: cosign was never intended to cover the bundle, GPG is the real mechanism and it is optional at every stage including completely absent from the pre-import check, the airgap install is currently broken end-to-end by an unrelated path bug, and every "fail" path in the current scripts mutates host state before failing. This is a security-boundary defect, not an integration backlog item.

---

## 1. Current state (evidence-backed)

### 1.1 The airgap install path is broken today, and fails after mutating the host

- `pack.sh:56` stages images at `<bundle-root>/images/`, a sibling of `<bundle-root>/compose/`.
- `setup.sh` (copied into `<bundle-root>/compose/setup.sh` by `pack.sh:87`) computes `SCRIPT_DIR` as its own containing directory and globs `"${SCRIPT_DIR}"/images/*.tar.gz` (`setup.sh:607`) — which resolves to `<bundle-root>/compose/images/*`, a path that never exists in a `pack.sh`-produced bundle. No `nullglob` is set, so the glob stays literal, the loop body never runs, and `setup.sh:616-618` aborts: `"No orchestrator artifact ... refusing to install without it."`
- By the time that abort fires, `import.sh:120-134` has already run `docker load` for **both** images unconditionally, and `setup.sh:580-594` has already generated and written `${INSTALL_DIR}/.env` (containing `POSTGRES_PASSWORD`, `JWT_SECRET`, `AGENT_SECRET`, admin credentials) to disk — both before `setup.sh`'s own image-loading block at line 596+607 ever runs.
- Separately, `setup.sh:278-280`'s `_verify_orchestrator_artifact` expects a `cosign.pub` and a `.bundle` signature inside the bundle; `pack.sh` never produces either, so this check would fail even if the path bug were fixed. This is dead, unreachable scaffolding for a verification path that was never finished on the producing side.

**Net: every real airgap run today loads both Docker images and writes generated secrets to disk, then fails.** The signing model is moot while the pipeline can't complete — this is the P0.

### 1.2 Every verification stage silently degrades to "proceed anyway"

- `import.sh:61-74`: if `.asc` is present but `verify-sig.sh` isn't found, **warns and continues**. If `.asc` is absent entirely, **warns and continues**.
- `import.sh:110-112`: if `MANIFEST.sha256` is absent, **warns and continues** — skips the integrity check entirely.
- `pack.sh:158-164`: if no GPG secret key is present on the build host, **warns and produces an unsigned bundle** rather than failing the build.
- `verify.sh` (the pre-import check an operator is told to run first) never calls signature verification at all — only unsigned SHA256 checksums, which catch corruption but not deliberate tampering (an attacker can regenerate self-consistent checksums for altered content).
- There is no Compose-version check anywhere in `import.sh`; the only check (`setup.sh:221-230`'s `check_compose`, called from `page_prereqs` at `setup.sh:473`) runs inside `setup.sh`, which `import.sh` invokes only *after* both images are already loaded (`import.sh:120-134`, before `import.sh:159` ever calls `setup.sh`).

### 1.3 The trust key is not independently provisioned

- `verify-sig.sh` (`packaging/signing/verify-sig.sh:17-20,42`) loads the verification key from `pubkey.asc` in its own script directory — shipped through the same distribution channel as everything else, with no out-of-band fingerprint pinning. A party able to tamper with the release pipeline can tamper with `pubkey.asc` alongside it; "it verifies against the key that travels with it" is not independent authentication.

### 1.4 No rollback, no interruption detection

- `import.sh:78`'s only trap (`rm -rf "$WORK_DIR"` on `EXIT`) removes the temp extraction directory only — it does not undo an already-completed `docker load`, nor anything `setup.sh` wrote.
- `setup.sh` has zero traps of any kind (confirmed: no `trap` anywhere in the file), despite writing secrets to disk before its own failure point.
- No lockfile, sentinel, or completion marker exists anywhere under `packaging/airgap/` or in `setup.sh`. A second run after a kill/power-loss mid-install re-extracts, re-loads images (idempotent), and **re-runs `setup.sh`'s secret generation unconditionally**, overwriting `${INSTALL_DIR}/.env` with freshly generated values — silently rotating credentials for what may have been a working partial or complete install.
- Precedent exists in the separate, non-airgap `install.sh` flow: `install.sh:123-136`'s `_on_interrupt` (bound via `trap _on_interrupt INT TERM`) checks for `${DATA_DIR}/docker-compose.yml` as a stand-in completion marker and tells the operator explicitly how to resume. `install.sh:970`'s upgrade-abort message ("the previous version is still running; nothing was replaced") shows the same codebase already has a rollback-safety convention — the airgap path just never adopted it.

### 1.5 Cosign: resolved, no independent benefit

`pack.sh:132-141` generates `MANIFEST.sha256` (every bundle file's checksum, excluding itself) **before** the tarball is built (`pack.sh:144-146`) and signed (`sign.sh:74-81`, a plain `gpg --detach-sign` over the exact tarball bytes, no re-touch after). The manifest is therefore inside the GPG-signed scope: a valid signature over the tarball transitively authenticates every file the manifest checksums, including both image tarballs, at the same trust level cosign's sign-blob/verify-blob model would add — and for the whole bundle, not one artifact. **Making GPG mandatory and manifest-checked makes `setup.sh`'s dead cosign scaffolding redundant.** Per the approved decision: remove/simplify it rather than finish it. Cosign is not extended to any other artifact in this phase.

### 1.6 Out of scope, confirmed correct, do not touch

`internal/integrity`'s `CompiledVerifier` (RSA-SHA256, compiled-in key) backs builtin scenario `.sig` files and `content_versions.signature_bytes`/`VENDOR_SIGNED` trust via `contentregistry.Registry.AttachVendorSignature`. This is per-artifact content signing, already enforced at runtime load and as a `pack.sh` release gate (`pack.sh:92-97`), and is unrelated to the bundle-transport gap this spec addresses.

---

## 2. Design

### 2.1 Install states (replaces "just run and regenerate")

Define three explicit states, detected at the start of `setup.sh`, before any secret generation:

| State | Detection | Behavior |
|---|---|---|
| **FRESH** | Neither `${INSTALL_DIR}/.env` nor `${INSTALL_DIR}/.install-complete` exists | Proceed normally: generate new secrets, install. |
| **INTERRUPTED** | `.env` exists, `.install-complete` does not | **Reuse** the existing `.env` verbatim (never regenerate secrets). Print the detected state and what will happen (resume install using existing credentials) and require an explicit `--resume` flag (or an interactive confirmation) before proceeding — this is not a silent continue, because a prior partial install may have left containers or DB schema in an unknown state and the operator should know that before the script acts further. |
| **COMPLETE** | Both `.env` and `.install-complete` exist | Refuse to proceed by default (matches `install.sh:970`'s existing "previous version still running, nothing replaced" convention) — require an explicit `--reinstall`/`--upgrade` flag to continue. |

`.install-complete` is written in `_do_install_steps` at the `_step 98 "Finalising..."` point (`setup.sh:647`), after the `_step 93` health-check wait (`setup.sh:640-645`) and before `_step 100 "Installation complete."` (`setup.sh:648`) — never written speculatively, never used as a cleanup trigger. Note the existing health-check loop does not itself fail/abort on timeout (it proceeds to Finalising either way after 24 retries); this spec does not change that behavior, but an implementer should not assume "orchestrator responded healthy" is guaranteed by `.install-complete`'s presence — only "the install steps ran to completion" is guaranteed.

This satisfies the acceptance requirement precisely: a mid-install kill cannot guarantee zero mutation (secrets may already be written, images may already be loaded), but it must guarantee the next run detects INTERRUPTED, preserves the existing secrets, and gives the operator an actionable message — not a silent proceed-as-fresh.

### 2.2 Verification order (P0, before any mutation)

Both `verify.sh` (the standalone pre-flight check) and `import.sh` call one shared verification function — see §2.4 — that runs, in this order, entirely inside a controlled staging directory (§2.3), before either script's first `docker load` or filesystem write outside that staging directory:

1. **GPG signature**, verified against the independently-provisioned trust key (§2.5) — authenticates the tarball as a whole. Hard failure (not warn) if `.asc` is missing, the key is untrusted, or verification fails.
2. **Manifest check** — every file listed in `MANIFEST.sha256`, checksummed from the files as extracted into the staging directory. This is not redundant with step 1: it confirms extraction produced exactly the signed bytes (catches extraction bugs or any swap introduced between signature check and extraction) and ties the verified signature to the literal files about to be consumed. Hard failure if `MANIFEST.sha256` is missing or any entry mismatches.
3. **Compose version** — semantic-parsed, floor `2.8.0`. Reject a missing Compose plugin, a version below the floor, or a version string that doesn't parse. This runs here (host-prerequisite check, independent of bundle contents) rather than only inside `setup.sh`, so a host with an incompatible Compose is rejected before `import.sh` ever reaches `docker load`.

No `docker load` and no write under `${INSTALL_DIR}` may occur until all three pass. This directly fixes §1.2's "proceed anyway" branches: each becomes a hard failure, and §1.4's sequencing defect, by moving the Compose check ahead of image loading rather than inside the script that currently runs after it.

### 2.3 TOCTOU protection — controlled staging directory

Extract the bundle into a fresh `mktemp -d` directory created with restrictive permissions (owner-only), used for the entire verify-then-consume sequence of a single run. Steps 1-3 above and the subsequent `docker load`/file copies all read from that same directory by the same resolved path captured once — never re-resolve a path by name after it has been verified, since a second lookup against a mutable location could return a swapped file. The staging directory is removed on exit (extending the existing `EXIT` trap in `import.sh:78`) regardless of outcome; this is the only destructive cleanup in the design, and it only ever touches temporary extracted copies, never `${INSTALL_DIR}`.

### 2.4 Shared verification, not divergent checks

Extract the GPG + manifest + Compose-version checks (§2.2) into one script, `packaging/airgap/verify-common.sh`, sourced by both `verify.sh` (so an operator's manual pre-flight check enforces the exact same rules) and `import.sh` (so the actual import path cannot diverge from what the operator already approved). `verify.sh` remains usable stand-alone for an operator who wants to check a bundle before transferring it further; `import.sh` calls the same function rather than re-implementing any part of it.

### 2.5 Trust key provisioning

`pubkey.asc` shipping in the same directory as `verify-sig.sh`/`verify-common.sh` (as today) is not independent trust — anyone able to tamper with the distribution channel can tamper with both together. The spec requires:

- The pubkey's fingerprint is documented in the release notes / a channel separate from the bundle transfer (e.g., published on the Audspect support portal or communicated directly to the customer at purchase/onboarding — an operational/documentation deliverable, not new code this phase).
- `verify-common.sh` prints the fingerprint it is about to trust before verifying, so an operator following the documented process can compare it against the independently-communicated value.
- This phase does not build new key-distribution infrastructure (no KMS, no PKI hierarchy) — it documents and surfaces the fingerprint-comparison step that today doesn't exist even as a manual process.

### 2.6 Remove dead cosign scaffolding

Remove `setup.sh:278-280`'s `_verify_orchestrator_artifact` cosign check and the `cosign.pub`-in-bundle expectation it implies, since §1.5 establishes it adds no independent verification property once GPG is mandatory and manifest-checked. `packaging/signing/cosign.sh` itself (the separate, optional Docker-image-blob signer invoked via `sign.sh --cosign`) is untouched — it's a distinct, already-functioning, already-opt-in path for a different distribution channel, not part of the airgap bundle flow this spec covers.

---

## 3. Acceptance criteria

For every negative-path test below, assert **zero `docker load` calls occurred and zero writes under `${INSTALL_DIR}` occurred** — not merely a nonzero exit code:

- Missing `.asc` signature file.
- Invalid/corrupt GPG signature.
- Signature valid but from an untrusted/unknown key.
- Missing `MANIFEST.sha256`.
- `MANIFEST.sha256` present but one or more files altered after signing (manifest mismatch).
- Compose plugin absent.
- Compose version below `2.8.0`.
- Compose version string unparseable (e.g. a non-semver build tag).

For the interruption case (process killed mid-install, after some mutation has legitimately started):

- Assert the next run detects `INTERRUPTED` state (not `FRESH`).
- Assert the existing `.env` secrets are byte-for-byte unchanged after the detecting run (no silent regeneration).
- Assert the operator-facing output names the detected state and the required next action (`--resume` or equivalent) — a mid-install failure cannot guarantee zero mutation, but must guarantee detectable, recoverable partial state, never a silent re-proceed or a silent credential rotation.

For the positive path: a correctly signed, correctly versioned bundle on a host with a compatible Compose still imports successfully end-to-end (this is also the regression test for the §1.1 path-mismatch fix — today this test would fail at `setup.sh:617` even with everything else correct).

`verify.sh` and `import.sh` are tested against the same shared verification function (§2.4) with the same fixture bundles, so a divergence between the two surfaces as a single shared-function test failure rather than needing to be duplicated in both scripts' test suites.

---

## 4. Migration / backward compatibility

- **Unsigned legacy bundles are rejected outright**, with no silent fallback and no migration-compatibility mode in this phase. Any customer on a pre-Phase-8 unsigned bundle must re-pack with a signing key present; this is a deliberate, explicit decision (per the approved scope), not an oversight — a silent-accept path for unsigned bundles would reintroduce exactly the fail-open defect this phase closes.
- Existing `${INSTALL_DIR}/.env` files from installs predating the `.install-complete` marker are treated as `INTERRUPTED` on first encounter under the new logic (no marker present), which is safe: the operator is prompted rather than having secrets silently regenerated. This is acceptable one-time friction, not a breaking change to a working install's actual secrets.

## 5. Out of scope

- Finishing or extending cosign to any artifact (§1.5, resolved no).
- New key-distribution infrastructure beyond documenting fingerprint comparison (§2.5).
- Changes to `internal/integrity`'s content-signing layer (§1.6) — already correct, unrelated.
- Changes to the separate, non-airgap `install.sh`/compose-only installer, except as a design precedent to follow (§1.4) — it is not broken and is not touched by this phase.

## 6. Review Focus (for the implementation plan)

- A bundle whose `.asc` verifies but whose `MANIFEST.sha256` doesn't match the extracted files (simulating a staging-directory tamper between signature check and consumption) must still be rejected — this is the TOCTOU case, and it's easy for an implementation to treat "signature valid" as sufficient and skip a redundant-looking manifest re-check.
- The Compose-version floor must reject an unparseable version string, not just a numerically-low one — a naive semver regex can accept something like `2.8.0-rc1+build` as "below 2.8.0" incorrectly or crash on it.
- `INTERRUPTED` detection must not be fooled by a `.env` left over from a fully uninstalled system (e.g. after `uninstall.sh` ran but didn't clean `.env`) — confirm what `uninstall.sh` actually does to `.env` before assuming its absence/presence cleanly maps to the three states.
- The shared verification function (§2.4) must be the only place either script checks signature/manifest/Compose version — a test should fail if `verify.sh` or `import.sh` is found to have its own inline duplicate of any of these checks.
- A killed-mid-import test must distinguish "killed during `docker load`" from "killed during `setup.sh`'s secret write" — the two leave different partial state, and the acceptance criteria's "preserve existing secrets" guarantee only applies once a `.env` write has actually started.
