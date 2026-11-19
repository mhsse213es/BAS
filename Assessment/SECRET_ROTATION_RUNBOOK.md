# Secret Rotation & Git-History Purge Runbook

**Incident:** live-looking credentials were committed to the repo (finding **A1**).
**Status as of this runbook:**
- ✅ Secret files untracked + added to `.gitignore` (commit `38517354`, working tree only).
- ✅ Recurrence prevention added: `.pre-commit-config.yaml` (gitleaks) + `.github/workflows/secret-scan.yml` (CI gate, full-history weekly sweep).
- ❌ **Secrets still exist in git history** — the removal commit did NOT rewrite history.
- ❌ **Credentials not yet rotated.**

> The two ❌ items require human action (and, for the purge, team coordination). They cannot be done safely or automatically from a coding session. Do them in the order below.

---

## Step 1 — ROTATE every exposed credential FIRST (do this today)

Rotate **before** purging history. Until rotated, the credentials are compromised regardless of what the repo looks like — they were in a repo cloned from a public URL, so assume they are already harvested.

Exposed credentials (files at repo root; values intentionally not repeated here):

| File | Credential | Rotation action |
|---|---|---|
| `keys.txt`, `tenantID.txt` | **AWS access key + secret** (region ap-south-1) | AWS Console → IAM → the user → Security credentials → **deactivate then delete** the exposed access key; create a new one; update the deployment's secret store. Review CloudTrail for use of the old key. |
| `setting.json`, `Model Configurator.txt` | **OpenRouter API key** (`sk-or-...`) | OpenRouter dashboard → API keys → **revoke** the exposed key; issue a new one; check usage/billing for abuse. |
| `tenantID.txt` | **Azure/OIDC tenant GUID + client secret** | Entra ID → App registrations → the app → Certificates & secrets → **delete** the exposed client secret; add a new one; update config. (The tenant GUID itself is not secret, but the client secret is.) |
| `keys.txt` | stray strings (`12@com`, `12345678`) | If these are/were real passwords anywhere, change them. |

After rotation, confirm the new secrets are delivered via env vars / a secrets manager (the orchestrator already reads `DATABASE_URL`, `JWT_SECRET`, `AGENT_SECRET`, etc. from the environment) — never a committed file.

---

## Step 2 — Purge the secrets from git history (coordinate with the team)

⚠️ **This rewrites history and force-pushes.** Every collaborator must re-clone or hard-reset afterward, and any open PR/branch based on old history must be rebased. A teammate is actively pushing to `main`/`staging`, so **coordinate a freeze window** first. Do NOT run this unilaterally.

### 2a. Freeze
- Announce a short freeze; ensure no one has unpushed work; merge or note open PRs.

### 2b. Rewrite (use `git filter-repo` — the modern, recommended tool)
```bash
pip install git-filter-repo            # or: brew install git-filter-repo
# Fresh mirror clone so the rewrite is clean:
git clone --mirror https://github.com/mhsse213es/BAS.git BAS-mirror
cd BAS-mirror
git filter-repo --invert-paths \
  --path keys.txt \
  --path tenantID.txt \
  --path setting.json \
  --path "Model Configurator.txt"
# (add any other paths gitleaks flags — see Step 3)
git push --force --mirror
```
Alternative (BFG): `bfg --delete-files '{keys.txt,tenantID.txt,setting.json}'` then `git reflog expire --expire=now --all && git gc --prune=now --aggressive` and force-push.

### 2c. Everyone re-clones
- All collaborators delete their local clone and clone fresh (a plain `git pull` will re-introduce the old objects via merge).
- Delete stale local/remote branches that still carry the secrets; rebase any survivors.

### 2d. Ask the host to purge cached views
- On GitHub, rewritten commits can linger in the web UI / forks / PR caches. Contact GitHub Support to purge cached commit views if needed, and check for **forks** (a fork keeps its own copy of the old objects).

---

## Step 3 — Verify

```bash
# No secret should remain anywhere in history:
git log --all --full-history -- keys.txt tenantID.txt setting.json "Model Configurator.txt"   # expect empty
gitleaks detect --source . --log-opts="--all"                                                   # expect no leaks
```
- Confirm the CI **Secret Scan** workflow is green and its weekly full-history sweep is scheduled.
- Confirm `pre-commit install` has been run in each active clone (blocks new secrets locally).

---

## Step 4 — Post-incident hardening (already in place / recommended)

- ✅ `.gitignore` blocks the secret files, `.env`, `*.pem`, `*.pfx`.
- ✅ gitleaks pre-commit hook + CI gate.
- ▶ Move all runtime secrets to env vars / a secrets manager (Vault, AWS Secrets Manager, or Docker/K8s secrets).
- ▶ Enable branch protection requiring the Secret Scan check to pass before merge to `main`.
- ▶ Consider short-lived / scoped credentials (e.g. per-service IAM roles) so a future leak is lower-impact.

---

*Prepared 2026-09-30. Related: `AUDSPECT_ASSESSMENT_REPORT.md` finding A1, `README.md`. Secret values are deliberately omitted from this document.*
