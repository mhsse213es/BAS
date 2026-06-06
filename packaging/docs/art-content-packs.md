# ART content packs — updating the technique library

The orchestrator serves Atomic Red Team (ART) content from **Postgres**, not from
files at request time. Disk is only the **seed source**: on first boot the server
imports the baked atomics and the mounted payloads into Postgres, and from then on
the database is the source of truth (queryable, `pg_dump`-able, surviving image
upgrades).

This means you can ship a **content pack** — newer atomics and/or payloads — and
apply it **without rebuilding or redistributing the orchestrator image**.

```
Disk (seed)                Postgres (runtime)              Engine
/art-atomics/*.yaml  ──┐                                  ┌─ ART scenarios
/art-payloads/*      ──┼─ import ─→ art_atomic_tests  ───┤
(content pack)        ──┘            art_payloads (meta)   └─ dispatched to agent
                                     techniques, …
```

## What lives where

- **Atomics (YAML)** → parsed into `art_atomic_tests` (execution-ready rows).
- **Technique metadata** → `techniques` (+ knowledge-graph tables for CVE/OWASP).
- **Payload binaries** → **stay on disk**; Postgres stores only their metadata
  (`art_payloads`: sha256, size, `storage_path`, type). At dispatch the server
  reads the file from `storage_path` and streams it to the agent's temp dir.
- **Version + counts** → `art_content_meta`.

## First boot (automatic)

No action needed. The image bakes atomics at `/art-atomics`; compose bind-mounts
payloads at `/art-payloads`. On startup the server runs the importer and logs:

```
[+] ART content seeded: <N> techniques, <M> payloads (version "")
```

## Updating content without an image rebuild

### 1. Put the new content on the server

- **Payloads** are already on a host-mounted volume (`/art-payloads`). Drop the
  new/updated binaries into that directory on the server.
- **Atomics** are baked into the image by default. To update them in the field
  without a new image, mount a host directory over the atomics path and point
  `ART_DIR` at it (see "Mounting a writable atomics dir" below), then place the
  new `T*.yaml` files there.

### 2. Bump the content version (recommended)

Set `ART_CONTENT_VERSION` (env / `.env`) to a new value, e.g. `v2026.07`. The
importer records this and uses it as a fast-path: on restart it re-imports only
when the version changed, and the console shows it.

### 3. Reseed

Two equivalent ways (admin only):

- **Console:** Settings → **ART Content Library** → **Reseed from Pack**.
- **API:**

  ```bash
  curl -fsS -X POST https://<server>/api/art/content/reseed \
       -H "Authorization: Bearer <admin-jwt>" \
       -H "Content-Type: application/json" \
       -d '{"version":"v2026.07"}'
  ```

Reseed re-imports atomics + payload metadata into Postgres (idempotent — only
changed techniques are touched) and **hot-reloads the engine** (no restart). The
body `version` is optional; it overrides `ART_CONTENT_VERSION` for this import.

Check status any time:

```bash
curl -fsS https://<server>/api/art/content/status -H "Authorization: Bearer <admin-jwt>"
```

```json
{ "seeded": true, "version": "v2026.07", "techniqueCount": 312,
  "payloadCount": 7, "source": "disk-seed", "techniquesLoaded": 312 }
```

## Mounting a writable atomics dir (optional, for field atomic updates)

By default atomics ship inside the image. If you want to update atomics in the
field, bind-mount a host directory and point `ART_DIR` at it. In compose:

```yaml
services:
  orchestrator:
    environment:
      ART_DIR: /art-content
      ART_CONTENT_VERSION: v2026.07
    volumes:
      - ./art-content:/art-content:ro   # drop new T*.yaml here, then reseed
```

Populate `./art-content` from a content pack (a tarball of `atomics/` YAML), bump
the version, and reseed. Payloads continue to come from `./art-payloads`.

## Notes

- Payload binaries are never stored in Postgres — keeps `pg_dump`/backups small.
- An atomic whose payload is missing is **skipped cleanly** (not failed).
- The agent is unaffected by all of this — it remains a dumb executor that runs
  the command and payloads the server sends.
- Curating payloads on the build host is unchanged — see
  [`art-payloads/README.md`](../art-payloads/README.md).
