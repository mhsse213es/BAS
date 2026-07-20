# Docker Auto-Install — Staging Host Verification

Run on a real VM or CAB-provisioned staging host (not a container) with a
genuine systemd PID 1, for both supported OS families, before this ships to
a production client install.

## Prerequisites
- A fresh Ubuntu 22.04 VM with no Docker installed.
- A fresh Rocky Linux 9 VM with no Docker installed.
- `packaging/compose/install.sh`, `docker-compose.yml`, and a valid
  `setup.conf` (real `LIC_PATH`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, etc. --
  see `setup.conf.template`) staged on each host.

## Ubuntu 22.04
1. `sudo bash install.sh --check --config setup.conf` -- confirm `[INST]`
   lines for Docker/Compose, no `[FAIL]` for either, full report prints
   through to the final summary line (validates the render_checks
   fail/warn counter fix on a real host).
2. `sudo bash install.sh --install --config setup.conf`, answer `no` at
   the Docker prompt -- confirm clean abort, `docker` still not installed,
   `/opt/audspect` (or configured `DATA_DIR`) not created.
3. `sudo bash install.sh --install --config setup.conf`, answer `yes` --
   confirm: Docker CE installs, `systemctl status docker` shows
   `active (running)`, the install proceeds through all 10 steps, the
   dashboard becomes reachable at the configured port, and
   `${DATA_DIR}/install.log` contains `Docker CE : auto-installed by
   installer`.
4. `sudo bash install.sh --uninstall --yes` to reset the host, confirm
   Docker itself is left installed (only the BAS stack is removed --
   uninstall was never in scope for touching Docker).
5. Re-run `sudo bash install.sh --install --config setup.conf --yes`
   fully unattended -- confirm no prompt appears and it completes the
   same as step 3.

## Rocky Linux 9
Repeat steps 1-3 and 5 above. Confirm the dnf-based `_install_docker`
branch installs cleanly and `systemctl status docker` is `active
(running)`.

## Already-has-Docker host
On a host that already has Docker + Compose installed (either from a
prior run above, or pre-existing), run
`sudo bash install.sh --check --config setup.conf` and confirm both
report `[PASS]`, then `--install` and confirm step `2/10` logs
`Docker already present -skipping` with no network calls and
`install.log` shows `Docker CE : pre-existing`.

## Sign-off
Record pass/fail for each scenario above, plus OS + Docker + Compose
versions observed, before this is approved for a production client
deployment.

| Scenario | Ubuntu 22.04 | Rocky Linux 9 |
|---|---|---|
| `--check` full report (INST, no crash) | | |
| `--install`, answer no -> clean abort | | |
| `--install`, answer yes -> full install + running stack | | |
| `--install --yes` unattended | | |
| Already-has-Docker -> skip path | | |

Docker version observed: ____________
Docker Compose version observed: ____________
Signed off by: ____________  Date: ____________
