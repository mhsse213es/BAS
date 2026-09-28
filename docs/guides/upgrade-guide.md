# Audspect BAS — Upgrade Guide

**Platform Version:** v1.7.5

---

## Overview

Audspect BAS upgrades are delivered as a new versioned delivery ZIP (`bas-install-<version>.zip`). The supported upgrade path is the bundled installer, `install.sh --upgrade`, which:

1. Backs up your current `docker-compose.yml`, `.env`, and version marker to a timestamped folder
2. Loads the new Docker images
3. Refreshes the bundle files (scenarios, dashboard static files, ART payloads, license) and `docker-compose.yml`
4. Rewrites `.env` with the new `BAS_VERSION` — **existing secrets (`DB_PASSWORD`, `JWT_SECRET`, `AGENT_SECRET`) are preserved, never regenerated**
5. Restarts the stack and waits for the health check to pass

**Always use `install.sh --upgrade` — never `docker compose down` / `docker compose up` directly, and never hand-copy `.env` between versions.** Each fresh build generates a *new* `POSTGRES_PASSWORD` in its own bundle, but the Postgres data volume from your existing install keeps the *old* password. Swapping images without going through `install.sh` (which preserves your existing secrets automatically) silently breaks database authentication and puts the orchestrator into a crash-loop that looks unrelated to the upgrade.

**Upgrade path supported:**
- v1.6.x → v1.7.5 (supported, data preserved)
- v1.7.x → v1.7.5 (supported, data preserved)
- Versions below v1.6.0: contact Audspect support before upgrading

---

## Before You Upgrade

- [ ] Locate your original `setup.conf` (the config file used for `--install`, or reconstruct one — see [setup.conf reference](#setupconf-reference) below). `--upgrade` requires it.
- [ ] Take an extra full database dump as a second safety net on top of `install.sh`'s own automatic config backup (see Step 1 below) — `install.sh`'s upgrade-time backup covers `docker-compose.yml`/`.env`/version, not the database contents itself (those live in the persistent Postgres volume, which the upgrade never touches directly, but a standalone dump is cheap insurance)
- [ ] If this upgrade crosses into the mTLS agent trust model (see the section immediately below), also run a real `sudo bash install.sh --backup` beforehand — this is a separate, encrypted, retention-managed mechanism (distinct from the small automatic config backup `--upgrade` always takes) that includes the deployment CA alongside the database and config, and is the right thing to restore from if anything about the CA goes wrong during or after this upgrade
- [ ] Note the current version: `sudo bash install.sh --status`
- [ ] Read the [Release Notes](release-notes.md) for the target version — specifically **Breaking Changes** and **Migration Notes**
- [ ] Confirm you have the new delivery ZIP: `bas-install-<version>.zip`
- [ ] Schedule during a low-activity window — the orchestrator is offline for a few minutes during the rolling restart
- [ ] Agents will reconnect automatically once the orchestrator is back up

---

## ⚠ Upgrading From a Pre-mTLS Install (v1.7.5 and earlier's single-listener topology)

If your current deployment predates this platform's per-agent mTLS trust
model, every enrolled agent is configured to talk to `http://<host>:9443`
in plaintext. After this upgrade, port 9443 requires a client certificate
-- a plaintext request to it fails outright, and existing agent binaries
have no built-in awareness of the new port layout to fall back to
automatically. Skipping the steps below will disconnect your entire fleet
until each agent is manually repointed. `install.sh --upgrade` detects this
case automatically (checking for `BAS_ENROLL_PORT` in your existing `.env`)
and will warn you before proceeding -- but read this section first so you
know what to do about it.

**Do this BEFORE running `install.sh --upgrade`:**

1. Repoint every existing agent's configured server URL from
   `http://<host>:9443` to `http://<host>:9000` (the new temporary legacy
   listener this upgrade publishes) -- this works against your CURRENT,
   not-yet-upgraded orchestrator, since it doesn't care what port number
   the agent uses as long as it's reachable. Per-platform:
   ```bash
   # Re-run the agent installer with the new URL (Linux/macOS)
   sudo ./bas-agent --install --server http://<host>:9000
   ```
   ```powershell
   # Windows: re-run the installer with the new URL, or edit the service
   # config directly and restart the BAS Agent service
   ```
2. Confirm agents are checking in against the *current* orchestrator on
   `:9000` before proceeding (Agents page in the dashboard, or
   `docker logs audspect-orchestrator | grep enroll`).
3. **Now** run `install.sh --upgrade --config setup.conf` as normal (Step 3
   below). All four listeners come up; your already-repointed agents keep
   working unaffected on `:9000`.
4. New agent installs, from this point on, enroll via the new mTLS flow
   automatically (`--ca-root` flag, bundled CA root + bootstrap secret) --
   no `:9000` involvement.
5. Existing agents migrate off `:9000` automatically on their *next binary
   upgrade* (agents already re-enroll on every upgrade) -- no further
   manual action needed per-agent.
6. `:9000` traffic is logged distinctly in the orchestrator's logs
   (`legacy_listener_requests_total` metric / `"legacy listener request"`
   log lines) -- use this to confirm when migration is complete (zero
   remaining `:9000` traffic) before a future release retires it entirely.

**If you're already running a version with the four-listener topology**
(i.e. this isn't your first upgrade since mTLS was introduced), skip this
section -- your agents are already using the new topology and this
upgrade is routine.

---

## Step 1 — Back Up the Database (extra safety net)

```bash
# Run from the current deployment directory (DATA_DIR, default /opt/audspect)
BACKUP_FILE="/opt/backups/bas-pre-upgrade-$(date +%Y%m%d-%H%M%S).sql"
mkdir -p /opt/backups
docker exec audspect-postgres pg_dump -U bas_user bas_platform > "$BACKUP_FILE"
gzip "$BACKUP_FILE"
echo "Backup saved: ${BACKUP_FILE}.gz"
```

Verify the backup is non-empty:
```bash
ls -lh "${BACKUP_FILE}.gz"
```

This is in addition to, not a replacement for, the automatic backup `install.sh --upgrade` takes of your config files in Step 3 below.

---

## Step 2 — Extract the New Package

```bash
cd /opt
sudo unzip bas-install-<version>.zip
cd bas-install-<version>
```

If the bundle was GPG-signed, verify it first — see the `VERIFY.md` staged alongside the ZIP, or `dist/VERIFY.md` in the build output.

---

## Step 3 — Run the Upgrade

```bash
sudo bash install.sh --upgrade --config setup.conf
```

This single command performs all 5 steps described in the Overview above — image load, bundle refresh, secret-preserving `.env` rewrite, systemd unit refresh, and a rolling restart with a health-check wait — and prints a status summary when done.

If you don't have your original `setup.conf` handy, see [setup.conf reference](#setupconf-reference) below to reconstruct one with the same `DATA_DIR`/`ADMIN_EMAIL`/`LIC_PATH` your existing install used — `DB_PASSWORD`/`JWT_SECRET`/`AGENT_SECRET` in this file are only used if no existing `.env` is found, so it's safe to leave those blank/placeholder for an upgrade.

---

## Step 4 — Verify the Upgrade

```bash
sudo bash install.sh --status
```

Expected output shows all containers running (`audspect-orchestrator`, `audspect-caldera`, `audspect-postgres`, `audspect-chrome`), the new version number, and the four listener ports (defaults `9443`/`9444`/`9000`/`9543`).

```bash
# Health check directly -- port 9443 now requires a client certificate
# (per-agent mTLS), so it's no longer the right port for a manual health
# check. Use the enrollment listener's unauthenticated /health instead
# (self-signed cert against the deployment CA by default, hence -k).
curl -sfk https://localhost:9444/health

# Check logs for errors
docker logs audspect-orchestrator --tail=50

# Check agents reconnecting — watch the Agents page in the dashboard;
# agents should return to Active within 60s.
```

---

## Step 5 — Update Agent Binaries (if required)

Check the release notes for whether the agent binary has changed. If a new agent binary is included in the delivery ZIP:

1. Download the new binary from the dashboard: **Agents → Download Installer**
2. Deploy to each endpoint using your standard deployment method
3. The old agent continues to function but may lack new collection capabilities

Agent binary trust verification will flag outdated binaries in the dashboard if the `BINARIES.sha256` manifest has changed.

---

## Post-Upgrade Cleanup

After confirming the new deployment is healthy, clean up old images to reclaim disk space:

```bash
docker image prune -f
```

`install.sh --upgrade` keeps a timestamped backup under `<DATA_DIR>/backups/` automatically — no manual old-directory cleanup is needed the way a hand-rolled `docker compose` upgrade would require. Old backups can be pruned manually once you're confident you won't need to roll back.

---

## Rollback Procedure

```bash
sudo bash install.sh --rollback
```

This restores the most recent timestamped backup under `<DATA_DIR>/backups/` (the `docker-compose.yml`, `.env`, and version marker `install.sh --upgrade` saved in Step 3) and restarts the stack on the previous version. It prompts for confirmation unless run with `--yes`.

If the target Docker images for the previous version are no longer present locally (e.g. pruned after upgrade), reload them first:

```bash
cd /path/to/previous/bas-install-<previous-version>/images
for f in *.tar; do sudo docker load < "$f"; done
sudo bash install.sh --rollback
```

If a schema change means the old binary can no longer read the current database, restore from the pre-upgrade database dump instead:

```bash
# Stop the stack first
sudo systemctl stop audspect 2>/dev/null || (cd /opt/audspect && docker compose down)

# Restore database (destructive — all data after the backup is lost)
docker start audspect-postgres
gunzip < /opt/backups/bas-pre-upgrade-<timestamp>.sql.gz | \
  docker exec -i audspect-postgres psql -U bas_user -d bas_platform

# Then roll back the images/config too
sudo bash install.sh --rollback
```

---

## Upgrading Agents

| Scenario | Action Required |
|---|---|
| Agent version matches server version | No action needed |
| Older agent, no new agent capabilities needed | Agents continue working; no upgrade required |
| New agent binary released | Download from dashboard, deploy via your standard method |
| `BINARIES.sha256` manifest updated | Dashboard shows binary trust warning on outdated agents |

---

## setup.conf Reference

`setup.conf` is a plain `key=value` file (no shell syntax). Fields recognized by `install.sh`:

| Key | Required | Default | Description |
|---|---|---|---|
| `DATA_DIR` | | `/opt/audspect` | Installation directory |
| `BAS_PORT` | | `9443` | mTLS agent traffic port (no browser access -- requires a client certificate) |
| `BAS_ENROLL_PORT` | | `9444` | New-agent enrollment + healthcheck port |
| `BAS_LEGACY_PORT` | | `9000` | Temporary, pre-migration agent traffic |
| `BAS_DASHBOARD_PORT` | | `9543` | Browser dashboard access port |
| `BAS_TLS` | | `false` | Use a properly-trusted certificate on `BAS_DASHBOARD_PORT` instead of the deployment CA's self-signed one |
| `TLS_CERT` / `TLS_KEY` | if `BAS_TLS=true` | | Certificate/key paths |
| `DB_PASSWORD` | yes | | Postgres password (only used if no existing `.env` is found) |
| `ADMIN_EMAIL` | yes | | Initial admin account email |
| `ADMIN_PASSWORD` | yes | | Initial admin account password |
| `LOG_RETENTION_DAYS` | | `90` | Log retention window |
| `JWT_SECRET` | | auto-generated | JWT signing key (only used if no existing `.env` is found) |
| `AGENT_SECRET` | | auto-generated | Agent MAC secret (only used if no existing `.env` is found) |
| `LIC_PATH` | yes | | Path to the customer license file |

---

## Other install.sh Commands

```bash
sudo bash install.sh --check                            # prereq report
sudo bash install.sh --install --config setup.conf       # first-time install
sudo bash install.sh --status                            # current state
sudo bash install.sh --uninstall [--purge-images] [--yes]
```

---

*© Audspect — Confidential — Customer Distribution*
