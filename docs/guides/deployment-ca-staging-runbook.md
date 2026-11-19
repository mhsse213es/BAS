# Deployment CA: Ubuntu staging runbook

Purpose: verify on a real Ubuntu server what the unit tests cannot: file ownership, persistence across restarts,
and upgrade behaviour of the deployment CA. Behaviour being verified is described in
[deployment-ca.md](deployment-ca.md). No CA features are added by this runbook.

**Rules**

* Run on the **staging server only** (never a customer installation). Checks 3 and 4 are destructive to the CA.
* Paths below assume the default `DATA_DIR=/opt/audspect`; adjust if `setup.conf` says otherwise.
* Run as root (`sudo -i`). Keep this page open and fill in the record at the end.
* Stop at the first FAIL, note it, and do not continue to the destructive checks.

Convenience variables used throughout:

```bash
D=/opt/audspect
fp() { openssl x509 -in "$D/pki/ca-cert.pem" -noout -fingerprint -sha256; }
```

## 0. Record the environment

```bash
lsb_release -ds; uname -r; docker --version
grep -E '^(BAS_|VERSION)' "$D/.env" 2>/dev/null | grep -v -i -E 'secret|password|key'   # version only; never paste secrets
docker inspect audspect-orchestrator --format '{{.Config.Image}} user={{.Config.User}}'
```

Expected: the image is the version under test and the user is `nonroot` (UID/GID 65532).

## 1. Fresh install

Install with the normal procedure (`install.sh --check`, then `--install --config setup.conf`). Then:

```bash
ls -ln "$D/pki"; stat -c '%u:%g %a %n' "$D/pki" "$D/pki/ca-key.pem" "$D/pki/ca-cert.pem"
fp
docker ps --filter name=audspect-orchestrator --format '{{.Status}}'
docker logs audspect-orchestrator 2>&1 | grep -i -E 'CA|pki' | tail
```

| Check | Pass when |
|---|---|
| Files exist | both `ca-key.pem` and `ca-cert.pem` are present |
| Directory | `65532:65532 700 .../pki` |
| Key | `65532:65532 600 .../ca-key.pem` |
| Certificate | `65532:65532 644` (or owned by 65532) |
| Server | `Up`, healthy, dashboard loads |
| Logs | no "incomplete CA" or "not usable" error; no "readable by other users" warning |

Save the fingerprint printed by `fp` as **FP1**. Enroll one test agent (Linux agent from the dashboard) and confirm
it shows as connected in the dashboard.

## 2. Upgrade keeps the CA and the agent

Install the newer package (`install.sh --upgrade --config setup.conf`), then:

```bash
fp                                  # must equal FP1
ls -d "$D"/backups/*/pki            # the upgrade backup contains the CA
stat -c '%u:%g %a %n' "$D/pki/ca-key.pem"
docker logs audspect-orchestrator 2>&1 | grep -i -E 'new deployment CA|CA expires|not usable' | tail
```

| Check | Pass when |
|---|---|
| Fingerprint | identical to **FP1** |
| Backup | the newest `backups/<timestamp>/pki` holds both files |
| Ownership | unchanged (`65532:65532 600`) |
| Logs | no "new deployment CA was just generated" |
| Agent | the enrolled test agent is still connected without re-enrollment (check the dashboard, or restart the agent service and see it reconnect) |
| Server certificate | `server-cert.pem` and `server-key.pem` now exist in `pki/`, owned `65532:65532`; `openssl x509 -in "$D/pki/server-cert.pem" -noout -issuer -subject -ext extendedKeyUsage,basicConstraints` shows the CA as issuer, `TLS Web Server Authentication` only and `CA:FALSE`; the CA fingerprint is still **FP1** |
| Agents after the server-certificate change | the agent reconnects after the upgrade **without** any change on the agent. This is the check that confirms the leaf certificate is accepted by real agents (the unit tests only simulate it) |

## 3. Missing key fails closed (disposable installation only)

```bash
cd "$D"
mkdir -p /root/ca-backup && cp -a pki/. /root/ca-backup/ && ls -l /root/ca-backup
sha256sum pki/ca-cert.pem > /root/ca-cert.sha256
docker compose stop orchestrator
rm pki/ca-key.pem
docker compose up -d orchestrator; sleep 15
docker ps -a --filter name=audspect-orchestrator --format '{{.Status}}'
docker logs audspect-orchestrator 2>&1 | tail -5
sha256sum -c /root/ca-cert.sha256
ls pki
```

Pass when the orchestrator is **not** running (restart loop or exited), the log refuses to start, the certificate
checksum still matches
(`ca-cert.pem: OK`), and `ls pki` shows **no** new `ca-key.pem`.

Which message you see depends on whether an agent is enrolled. With an enrolled agent (the normal staging case)
the older startup guard answers first: `a new deployment CA was just generated ... looks like CA loss on an
EXISTING deployment`. With no enrolled agent the CA loader answers: `incomplete CA ... key present: false,
certificate present: true`. Either is a pass; record which one appeared. A line saying a new CA was generated
and the server running is a FAIL.

Recover:

```bash
docker compose stop orchestrator
cp -a /root/ca-backup/. pki/
chown 65532:65532 pki/ca-key.pem pki/ca-cert.pem; chmod 600 pki/ca-key.pem; chmod 644 pki/ca-cert.pem
docker compose up -d orchestrator; sleep 15
fp                                  # must equal FP1
```

Pass when the server starts, the fingerprint equals **FP1**, and the test agent reconnects.

## 4. Restore ownership

Simulate a careless restore as root:

```bash
docker compose stop orchestrator
cp /root/ca-backup/ca-key.pem /root/ca-backup/ca-cert.pem "$D/pki/"     # leaves root:root
stat -c '%u:%g %a %n' "$D/pki"/ca-*.pem                                   # note the owner
docker compose up -d orchestrator; sleep 15
docker logs audspect-orchestrator 2>&1 | tail -5
```

Record what happens with root-owned files (a key owned by root with mode 600 is unreadable to UID 65532, so the
expected result is a startup failure with a permission error). Then apply the documented fix and confirm recovery:

```bash
docker compose stop orchestrator
chown 65532:65532 "$D"/pki/ca-key.pem "$D"/pki/ca-cert.pem
docker compose up -d orchestrator; sleep 15
docker ps --filter name=audspect-orchestrator --format '{{.Status}}'; fp
```

Pass when the server runs again after the `chown`, the fingerprint equals **FP1**, and the agent reconnects.
If the first half does **not** fail (the server starts with root-owned files), record that too: it means the
mount is more permissive than the guide assumes and the guide's wording must change.

Also try a loose key readable by others (`chmod 644 pki/ca-key.pem`, restart): the server should start, log
`restricted to 0600`, and `stat` should then show `600`.

## 5a. Planned CA rotation (disposable installation only; added for audit F-09, NOT yet validated)

Needs at least two enrolled test agents running a build that includes the `command_trust_ca` change. Record FP1 first.

```bash
cd "$D"
docker exec audspect-orchestrator /orchestrator ca-rotation status            # stable
docker exec audspect-orchestrator /orchestrator ca-rotation start --yes       # prepared
docker compose restart orchestrator; sleep 15
fp                                                                          # still FP1
curl -sk -H "Authorization: Bearer $ADMIN_TOKEN" https://localhost:9443/api/ca-rotation/status
curl -sk -X POST -H "Authorization: Bearer $ADMIN_TOKEN" https://localhost:9443/api/ca-rotation/distribute
curl -sk -H "Authorization: Bearer $ADMIN_TOKEN" https://localhost:9443/api/ca-rotation/status   # wait for readyToPromote:true
```

Pass when: both agents stay connected throughout; each agent's `deployment-ca.pem` now holds two certificates; status reaches
`readyToPromote: true`. Then `ca-rotation promote --yes`, restart the orchestrator, and confirm: `fp` shows a **different**
fingerprint (FP2), the server certificate chains to FP2, both agents reconnect without any action, and after an agent renews (or is
restarted after its certificate nears expiry) its certificate is issued by FP2. Only then `ca-rotation retire --yes`; confirm the
agents still connect. Also test `ca-rotation rollback --yes` on a second run before retiring. `ca-rotation start` with the CA files
removed must refuse. An agent that was offline during `distribute` must receive the root when `distribute` is run again.

## 5b. Token enrolment and 24-hour recovery (disposable installation; added for audit F-03, NOT yet validated)

Set `BAS_ENROLLMENT_MODE=token` for the orchestrator and restart it. Use one Ubuntu agent host and one Windows host.

| Step | Do | Pass when |
|---|---|---|
| 1 | Deploy Agent page: generate a token for each host's exact hostname | tokens shown once; the CSV downloads |
| 2 | Ubuntu: `sudo ./bas-agent-setup-linux.run`, paste the token at the hidden prompt | agent enrols and connects; `ps aux \| grep bas` shows neither the secret nor the token; `ls /tmp` leaves no token file |
| 3 | Windows: run the MSI wizard, paste the token in the masked field | agent enrols; the MSI log (`/l*v`) contains no token |
| 4 | Windows silent: `set AUDSPECT_ENROLLMENT_TOKEN=<token>` then `msiexec /i ... /qn` | enrols; token not in the process list or log |
| 5 | Reuse the same token on a clean host | refused with exit 26 and the "refused the enrolment token" message |
| 6 | Use host A's token on host B | refused with exit 26 |
| 7 | Generate a token, block the enrolment port with the firewall, install | exit 27, "could not reach the server" (not a token message) |
| 8 | Expired token (set lifetime 4 h, wait or edit `expires_at`) | refused with exit 26 |
| 9-11 | **Expired-certificate recovery cannot be exercised on real hosts in practice.** Agent certificates last a fixed 365 days, and moving only the agent clock a year ahead also expires the server's own certificate (issued earlier), so the agent could not reach the server at all. These cases (recovery inside 24 h, refusal after 24 h, refusal for a revoked agent, no second use) are covered by the automated tests `TestRecover_*` and `agent/recovery_test.go`. A live check is only possible on a disposable installation by moving the clock of BOTH the server and the agent forward by 365 days + 2 hours, and is optional. | n/a |
| 12 | While an agent holds an expired certificate, confirm it cannot reach the agent listener (:9443) | TLS handshake fails (expired certificates are still refused there) |

## 5. Cleanup

```bash
grep -rn BAS_CONFIRM_NEW_CA "$D/.env" "$D/docker-compose.yml" /etc/environment 2>/dev/null
docker inspect audspect-orchestrator --format '{{range .Config.Env}}{{println .}}{{end}}' | grep BAS_CONFIRM_NEW_CA
rm -rf /root/ca-backup /root/ca-cert.sha256
```

Pass when `BAS_CONFIRM_NEW_CA` is unset or empty in the compose environment, and the temporary copies of the key
are deleted. This runbook never sets it.

## Record (fill in and keep with the CAB/QA log)

| Item | Value |
|---|---|
| Ubuntu version / kernel | |
| Docker / compose versions | |
| Installation method and package version | |
| Upgraded from / to | |
| FP1 (fresh) / after upgrade / after recovery | |
| `stat` of pki dir, key, certificate (fresh) | |
| Check 1 / 2 / 3 / 4 / 5 result | |
| Agent connected after upgrade? after recovery? | |
| Root-owned restore: observed behaviour | |
| Anything unexpected | |
