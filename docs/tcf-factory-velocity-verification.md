# TCF Factory Velocity — Live Verification Runbook

How to prove the threat→content→validated-coverage velocity metric end-to-end
on a running deployment, and the bug that had to be fixed first.

> **Listener note:** the orchestrator serves the human API/console on **:9543**
> (JWT, no client cert). **:9443 is agents-only mTLS** and rejects curl/browsers
> with `tlsv13 alert certificate required`. Use `:9543` for every API call here.
> Admin login: `POST /api/auth/login {"username":"<BAS_ADMIN_EMAIL>","password":"<BAS_ADMIN_PASSWORD>"}`
> → use the `token` field (values in `/opt/audspect/.env`).

---

## 0. Background — the wiring bug (fixed)

The connector scheduler's **evidence store was never wired** in
`cmd/server/main.go`: it was built as `NewScheduler(...).WithIdentityStore(...)`
with no `.WithEvidenceStore(evStore)`. `WithEvidenceStore` is opt-in, so
`s.evidence` was nil and `recordSourceSync` returned immediately — **no source
instances, trust versions, observations, or threat clocks ever recorded from a
live sync.** `threat_observed`, the threat/intelligence clocks, and all velocity
silently never recorded, while content generation (its own evidence store) kept
working, which hid the gap.

**Fix (merged to `main`, PR #8, fix commit `0f3aaa7a`):** added
`connector.NewProductionScheduler(... evStore, identityStore)` which composes the
full wiring in one place, routed `cmd/server` through it, guarded by
`TestNewProductionScheduler_WiresEvidenceAndIdentity`. This is compiled Go, so a
**rebuild from `main` + `install.sh --upgrade` is required** — there is no runtime
workaround.

**Confirming signature of the bug on an un-fixed build:** `source_instances` empty,
`threat_clock_starts` empty, `threat_observed = 0`, `POST /api/intel/sources/opencti/trust`
returns an FK violation, and `docker logs audspect-orchestrator | grep -c '\[connector/(evidence|tcv)\]'`
is `0`.

---

## Part A — Deploy the fix

1. Rebuild the orchestrator image from `main` on the Windows build host (diff the
   build time against `git log` first — the stale-build trap).
2. On staging: `sudo bash install.sh --upgrade --config setup.conf`
   (never `--install` over existing data).
3. Confirm:
   ```bash
   docker logs audspect-orchestrator 2>&1 | grep -icE '\[connector/(evidence|tcv)\]'  # now > 0 after a sync
   ```

---

## Part B — Observe → Created (no agent required)

A signed, local threat-intel **bundle** is the most reliable source: trusted by
default, no network, deterministic. OpenCTI/MISP also work but see the gaps in §D.

### The bundle
Three fresh actors (fresh names avoid colliding with existing threats, so every
stage fires cleanly), each ≥2 ATT&CK techniques, each with a recent `last_seen`
(the threat clock starts at `last_seen`; a missing/zero value starts the clock at
year 0001 → the delta is flagged anomalous and excluded). See the appendix for the
exact JSON and the signing command. Current verification bundle sha256:
`cad39e8d3b3b744a72a513cdac7fe5f729d1b081d7876cfe3b7f45ac45d147ed`
(actors: Jade Cicada, Umber Wraith, Cobalt Harrier).

### Signature
`VerifyScenarioFile` requires `<file>.sig` = base64(RSA-PKCS1v15 over SHA-256 of the
file bytes), verified against the embedded `ScenarioPublicKeyPEM`. Sign with the
release key `orchestrator/private_key.pem`. See the appendix for the exact command.

### Drop + sync + verify
```bash
BDIR=$(docker inspect audspect-orchestrator \
  --format '{{range .Mounts}}{{if eq .Destination "/intel-bundles"}}{{.Source}}{{end}}{{end}}')
# write ti-bundle.json + ti-bundle.json.sig into $BDIR (base64 -d | sudo tee), then:
sudo sha256sum "$BDIR/ti-bundle.json"      # must match the sha256 above

curl -sk -X POST https://localhost:9543/api/connector/sync -H "Authorization: Bearer $TOK"
sleep 20
docker logs audspect-orchestrator 2>&1 | grep -iE 'bundle|sync complete' | tail

q(){ docker exec audspect-postgres psql -U bas_user -d bas_platform -tAc "$1" 2>&1; }
q "SELECT clock, count(*) FROM threat_clock_starts GROUP BY clock ORDER BY 1"          # threat = 3
q "SELECT event_type||' = '||count(*) FROM tcf_pipeline_events GROUP BY event_type ORDER BY 1"
q "SELECT event_type||'  '||to_char(event_time,'HH24:MI:SS') FROM tcf_pipeline_events \
   WHERE threat_id=(SELECT threat_id FROM threat_clock_starts WHERE clock='threat' ORDER BY started_at DESC LIMIT 1) \
   ORDER BY event_time"
```
Success = the timeline shows **`threat_observed → threat_eligible → generation_attempted → content_created`**
with ascending timestamps.

---

## Part C — Created → Validated (lab agent)

`validated_coverage` and the end-to-end velocity require the validation lab, which
dispatches factory-validation runs of the generated content to a dedicated agent.

**Requirements (verified in code):**
- **The lab agent must be a dedicated WINDOWS endpoint.** Factory-validation runs
  are OS-checked (`handlers.go` live-run `SupportedOS` gate → `"os mismatch"` skip),
  and the generated content targets Windows detection profiles. A Linux agent is
  skipped and content never reaches `VALIDATED`.
- **It is dedicated.** The dispatch guard bars the lab agent from customer runs and
  bars customer runs from targeting it (both directions). Do not reuse a customer agent.
- **`is_factory_lab` is set automatically** from `VALIDATION_LAB_AGENT_ID` at boot
  (`EnsureSoleFactoryLabAgent` flags that agent and clears all others) — no manual SQL.

**Steps:**
1. Enroll a dedicated, capable Windows VM as an agent; let it go `active`.
2. Get its id:
   ```bash
   docker exec audspect-postgres psql -U bas_user -d bas_platform -c \
     "SELECT agent_id, hostname, os_version, state FROM agents WHERE os_version ILIKE '%windows%' ORDER BY last_update DESC"
   ```
3. In `setup.conf`: `VALIDATION_LAB_AGENT_ID=<agent_id>` (optional `VALIDATION_LAB_POLL_MINUTES=5`).
   The compose passthrough already exists on `main`.
4. `sudo bash install.sh --upgrade --config setup.conf`
5. Confirm:
   ```bash
   docker logs audspect-orchestrator 2>&1 | grep -i validationlab | tail
   #   expect: [validationlab] enabled, lab agent <id>, poll every 5m
   docker exec audspect-postgres psql -U bas_user -d bas_platform -c \
     "SELECT agent_id, is_factory_lab FROM agents WHERE is_factory_lab"
   ```
6. Wait one poll cycle (≤5 min), then verify:
   ```bash
   q "SELECT event_type||' = '||count(*) FROM tcf_pipeline_events \
      WHERE event_type IN ('validation_dispatched','validation_resulted','validated_coverage') GROUP BY event_type ORDER BY 1"
   q "SELECT lifecycle||' = '||count(*) FROM content_versions GROUP BY lifecycle ORDER BY 1"   # some VALIDATED
   curl -sk "https://localhost:9543/api/intel/factory/sla?stage=end_to_end" -H "Authorization: Bearer $TOK"
   ```

**Caveat:** content reaches `VALIDATED` only if the Windows host executes the
generated scenario cleanly (a few techniques need local admin / an EDR-free box).
`ERROR` runs leave the content `DRAFT` to retry next cycle.

---

## D. Known gaps / follow-ups (not blocking the above)

- **OpenCTI connector has a hardcoded 30s HTTP timeout, no override**
  (`internal/connector/opencti.go`), and no partial-success path — a real/cold
  OpenCTI whose actor+TTP query exceeds 30s drops the whole sync. Make it
  configurable before relying on a live OpenCTI feed.
- **Container → host-IP reachability.** On staging, OpenCTI answered in ~43ms from
  the host but the orchestrator *container* timed out reaching the same
  `host-ip:port` (hairpin). Prefer a reachable address/network for the container.
- **Only trusted, actor-rich sources start the clock.** `opencti`/`misp`/`bundle`
  are trusted by default; `otx` is untrusted and activity-only (no curated actors)
  so it never starts a threat clock.

---

## Appendix — bundle JSON and signing command

`ti-bundle.json` (drop at `<intel-bundles>/ti-bundle.json`; regenerate `last_seen`
to a recent time when re-verifying):

```json
{
  "version": "audspect-verify-2026-11-02-b",
  "generated_at": "2026-11-02T07:25:01Z",
  "actors": [
    { "name": "Jade Cicada",   "confidence": "high", "source": "bundle", "last_seen": "2026-11-02T07:25:01Z",
      "techniques": [ {"id":"T1567.002"}, {"id":"T1071.004"}, {"id":"T1560.001"}, {"id":"T1059.001"} ] },
    { "name": "Umber Wraith",  "confidence": "high", "source": "bundle", "last_seen": "2026-11-02T07:25:01Z",
      "techniques": [ {"id":"T1567.002"}, {"id":"T1071.004"}, {"id":"T1003.001"}, {"id":"T1021.001"} ] },
    { "name": "Cobalt Harrier","confidence": "high", "source": "bundle", "last_seen": "2026-11-02T07:25:01Z",
      "techniques": [ {"id":"T1560.001"}, {"id":"T1071.004"}, {"id":"T1047"}, {"id":"T1566.001"} ] }
  ]
}
```
(Techniques above are abbreviated; the deployed bundle also carries each technique's
`name`/`tactic`. The signature is over the exact file bytes, so sign the file you ship.)

Sign with the release key (produces the `.sig` the server verifies):
```bash
openssl dgst -sha256 -sign orchestrator/private_key.pem ti-bundle.json \
  | base64 -w0 > ti-bundle.json.sig
# verify locally against the embedded public key before shipping:
openssl dgst -sha256 -verify scenario_pub.pem -signature <(base64 -d ti-bundle.json.sig) ti-bundle.json
```

## What `VALIDATED` means (representative profile)

Factory validation runs the **representative** profile: a deterministic,
capped subset of a scenario's server-expanded steps (default: one atomic per
technique, at most 25 steps), not the full expansion. This keeps a validation
fast and reliable regardless of scenario length.

Therefore a content version in `VALIDATED` means **"its representative
validation profile passed"** — not that every step or variant was executed.
The limitation is recorded in the evidence, never implied away:

- `scenario_runs.validation_profile` (`representative`) and
  `scenario_runs.validation_coverage` (jsonb: `total_steps`, `selected_steps`,
  `skipped_steps`, `techniques_total`, `techniques_selected`, `truncated`).
- The same `profile` + `coverage` are copied into the run's
  `content_validations.detail` row and the `validation_resulted` SLA event, so
  a PASS is self-describing (e.g. "representative, 3 of 462 steps, 8 of 8
  techniques").

Failure modes never produce PASS: a run that times out, executes nothing
(all-skipped), errors a step, or never reports is recorded ERROR/FAIL/NO_DATA.

Selection is reproducible for a fixed immutable content version (keyed on the
stable per-step `TaskID`). The run-completion wait is
`VALIDATION_LAB_TIMEOUT_MINUTES` (default 10, hard max 30) — a budget, not a
substitute for bounding. A `full` profile (complete execution) is defined for
deeper validation but the routine lab does not dispatch it.

See `docs/superpowers/specs/2026-11-03-factory-representative-validation-design.md`.
