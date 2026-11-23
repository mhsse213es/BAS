# Endpoint Mastery 09 — Browser Data-Access Exposure: implementation plan

Status: IMPLEMENTED (decisions in section 7 approved as recommended). See docs/endpoint-mastery-09-qa-log.md.
Current file: scenarios/endpoint-mastery/em-09-browser-attack.yaml (2 steps, on main).

## 1. Defects in the current EM-09

1. **Hardcoded paths.** Both steps read one fixed profile (`Default`). Profiles other than Default, and Chrome's `Network\Cookies` layout variants, are not tested.
2. **PASS means "locked", not "access denied".** The verdict text says "isolated, active process locked, or read attempt flagged by policy". That conflates an OS denial with an EDR detection, which the spec rules out (PASS must not mean an attack was detected or prevented).
3. **Browser lock not handled.** Chrome and Edge hold their SQLite files open. A failed open is reported as "isolated" even when the cause is the browser's own lock, so a locked file reads as a control working.
4. **No WAL or journal awareness.** A `-wal` or `-shm` sidecar can hold recent data even when the main file is not readable. The step never looks at them.
5. **Output is unstructured.** There is no ACCESS_ALLOWED / ACCESS_DENIED / NOT_FOUND / ERROR state, so the runner cannot tell an unreadable file from a missing one.
6. **Citation markers.** `[cite: 4, 5]` and `[BAS-SIM]` remain in the description and output; remove them as in EM-05 and EM-06.
7. **Chrome step blast-radius text** says it "attempts to open a temporary system read handle". The step holds a handle while it tests, so the wording must state exactly what is opened and released.

## 2. Evidence states

Every profile-file check returns exactly one state:

| State | Meaning | Scenario verdict |
|---|---|---|
| ACCESS_ALLOWED | Read-only open succeeded | FAIL (exposure: a local process can open the file) |
| ACCESS_DENIED | OS refused the read-only open with an access error | PASS (control held for this check) |
| NOT_FOUND | Browser or profile or file is not present | SKIP (not assessable, reason given) |
| LOCKED_BY_BROWSER | The browser holds an exclusive lock, so the open was refused by sharing | SKIP (not assessable while the browser holds the file; reason given) — decision 7.2 |
| ERROR | Unexpected exception, or cleanup failed | ERROR |

PASS never implies detection or prevention. Each line states the observed state and the file path class (profile name, file name), with no contents.

## 3. Discovery and checks

- **Profile discovery (both browsers):** read `Local State` (JSON) under the browser's `User Data` folder to get the profile list; fall back to `Default` and `Profile *` directories if `Local State` is missing. Never hardcode one profile.
- **Chrome:** for each profile, check `Network\Cookies` first, then the legacy `Cookies` path. Identify the main database file only.
- **Edge:** for each profile, check `Login Data`. Identify the main database file only.
- **WAL and journal sidecars:** report whether `<file>-wal`, `<file>-shm` and `<file>-journal` exist and their sizes. Do not open them.
- **Open mode:** `FileAccess.Read` with `FileShare.ReadWrite | FileShare.Delete`, opened and closed immediately. No SQLite query, no copy, no read of content.

## 4. What is not done

- No cookie or credential value is read, parsed, decrypted or exported.
- No DPAPI or key material is touched.
- No browser process is started, stopped or signalled.
- No file is copied, moved, renamed or written.
- No user-session disruption: nothing is opened in a way that changes the file.

## 5. Test plan

1. **Fixture-backed tests (Pester, no browser needed).** Build a temp tree that mimics `User Data`: `Local State`, several profile folders, a `Cookies` file, a `Login Data` file, and a `-wal` sidecar. Test discovery, the state for each file (set read ACLs to force ACCESS_DENIED), NOT_FOUND for a missing profile, and LOCKED_BY_BROWSER by holding an exclusive stream on a fixture file.
2. **Lab-gated tests (Windows lab host only).** Run against a real Chrome and Edge profile only when `BAS_EM09_LAB=1` is set, in the same way EM-06 gates side-effect probes. Skipped in CI.
3. **Scenario signature.** Re-sign `em-09-browser-attack.yaml.sig` after the edit and verify it loads.

## 6. Acceptance mapping to the spec

| Spec criterion | How this plan meets it |
|---|---|
| 1. Fixture-backed tests | Section 5.1 |
| 2. Lab-gated tests | Section 5.2 |
| 3. No credential or cookie extraction | Section 4 |
| 4. ACCESS_ALLOWED / ACCESS_DENIED / NOT_FOUND / ERROR | Section 2 (adds LOCKED_BY_BROWSER, decision 7.2) |
| 5. PASS is not detection or prevention | Section 2 verdict column; PASS wording states "OS denied read access for this check" |
| 6. No browser modification, termination or disruption | Section 4 |

## 7. Decisions for you

1. **Step shape.** Keep one step per browser that emits one line per discovered profile (recommended), or one step per profile found at build time? Per-profile steps cannot be known in advance, so the first option is recommended.
2. **Locked database.** Report LOCKED_BY_BROWSER as SKIP (recommended: the test could not assess access, and a lock is not an OS denial), or as ERROR?
3. **Helper script.** Keep the logic inline in each step (recommended, so the signed YAML is the whole scenario), or ship a helper script that the agent runs? An inline block is harder to unit-test, which is why section 5.1 extracts it into Pester.
4. **Lab gate name.** Use `BAS_EM09_LAB=1` (recommended), following the EM-06 pattern?
5. **Technique mapping.** Keep T1539 and T1555.003 as the spec states. Note that T1555.003 is credentials from web browsers, so an ACCESS_ALLOWED result means the file was readable, not that credentials were stolen.
6. **Class label.** Keep the scenario name, and add a line in the description that it is a data-access exposure simulation rather than a credential-theft simulation (as the spec recommends).

## 8. Not started

No YAML edits, no signature change, no tests written. This plan is uncommitted. Approve the decisions in section 7 and the work follows the same order as sections 5 and 6.
