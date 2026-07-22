# Threat-Intel Connector Rich Status Cards Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** give MISP and OpenCTI their own status cards (Status/raw count/actors extracted/last fetch/error) in the Threat Intel Connector settings section, using the per-source data sub-project 1 already exposes via `GET /api/connector/status`'s `bySource` field.

**Architecture:** frontend-only change to `orchestrator/wwwroot/index.html` (and its hardlinked twin) — two new `.conn-cfg-card` blocks above the existing status card, populated by a small shared JS helper (`_renderConnectorCard`) called once per connector from the existing `loadConnectorStatus()`.

**Tech Stack:** vanilla JS (no framework, no build step), inline in the single HTML file — same conventions as every other UI change this session.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-07-22-connector-rich-status-cards-design.md` — read it first.
- No backend changes — `GET /api/connector/status` already returns everything needed (`bySource.misp`/`bySource.opencti`, each `{name, rawCount, actorCount, fetchedAt, error}`) as of sub-project 1.
- MISP's raw-count row is labeled "Events"; OpenCTI's is labeled "Threat Actor Nodes" — they're genuinely different kinds of raw data, not interchangeable labels for the same concept.
- OTX and Bundle stay exactly as they are today (simple rows in the existing card) — not part of this sub-project.
- Every edit to `orchestrator/wwwroot/index.html` must be applied identically to `orchestrator/cmd/server/wwwroot/index.html` (OS-level hardlinks, but two separate git paths) — verify with `diff` before committing, `git add` both paths together.

---

### Task 1: Per-connector status cards for MISP and OpenCTI

**Files:**
- Modify: `orchestrator/wwwroot/index.html:1813-1821` (new card markup, replacing the MISP/OpenCTI rows)
- Modify: `orchestrator/wwwroot/index.html` (new `_renderConnectorCard` helper + `loadConnectorStatus()` update)
- Modify: `orchestrator/cmd/server/wwwroot/index.html` (same edits, hardlinked twin)

**Interfaces:**
- Consumes: `GET /api/connector/status`'s existing `bySource: {misp?: SourceStat, opencti?: SourceStat}` field (each `SourceStat = {name, rawCount, actorCount, fetchedAt, error}` — JSON field names from `orchestrator/internal/connector/types.go`, already shipped in sub-project 1), `apicall`, existing `.conn-cfg-card`/`.conn-cfg-row`/`.conn-cfg-label`/`.conn-cfg-val` CSS classes.
- Produces: `_renderConnectorCard(prefix, enabled, stat, rawCountElId)` — not consumed elsewhere in this plan; this is the only task.

- [ ] **Step 1: Replace the MISP/OpenCTI rows with two per-connector cards**

In `orchestrator/wwwroot/index.html`, find:
```html
          <div class="conn-cfg-card" id="connector-status-card">
            <div class="conn-cfg-row">
              <span class="conn-cfg-label">MISP</span>
              <span id="cs-misp" class="conn-cfg-val">—</span>
            </div>
            <div class="conn-cfg-row">
              <span class="conn-cfg-label">OpenCTI</span>
              <span id="cs-opencti" class="conn-cfg-val">—</span>
            </div>
            <div class="conn-cfg-row">
              <span class="conn-cfg-label">OTX (AlienVault)</span>
              <span id="cs-otx" class="conn-cfg-val">—</span>
            </div>
```
Replace with:
```html
          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:0.75rem;margin-bottom:0.75rem">
            <div class="conn-cfg-card" id="cs-misp-card">
              <div style="font-weight:600;font-size:0.82rem;color:var(--text);margin-bottom:0.5rem">MISP</div>
              <div class="conn-cfg-row">
                <span class="conn-cfg-label">Status</span>
                <span id="cs-misp-status" class="conn-cfg-val">—</span>
              </div>
              <div class="conn-cfg-row">
                <span class="conn-cfg-label">Events</span>
                <span id="cs-misp-events" class="conn-cfg-val">—</span>
              </div>
              <div class="conn-cfg-row">
                <span class="conn-cfg-label">Actors extracted</span>
                <span id="cs-misp-actors" class="conn-cfg-val">—</span>
              </div>
              <div class="conn-cfg-row">
                <span class="conn-cfg-label">Last Fetch</span>
                <span id="cs-misp-lastfetch" class="conn-cfg-val">—</span>
              </div>
              <div id="cs-misp-error" style="display:none;margin-top:0.5rem;font-size:0.72rem;color:#f85149"></div>
            </div>
            <div class="conn-cfg-card" id="cs-opencti-card">
              <div style="font-weight:600;font-size:0.82rem;color:var(--text);margin-bottom:0.5rem">OpenCTI</div>
              <div class="conn-cfg-row">
                <span class="conn-cfg-label">Status</span>
                <span id="cs-opencti-status" class="conn-cfg-val">—</span>
              </div>
              <div class="conn-cfg-row">
                <span class="conn-cfg-label">Threat Actor Nodes</span>
                <span id="cs-opencti-nodes" class="conn-cfg-val">—</span>
              </div>
              <div class="conn-cfg-row">
                <span class="conn-cfg-label">Actors extracted</span>
                <span id="cs-opencti-actors" class="conn-cfg-val">—</span>
              </div>
              <div class="conn-cfg-row">
                <span class="conn-cfg-label">Last Fetch</span>
                <span id="cs-opencti-lastfetch" class="conn-cfg-val">—</span>
              </div>
              <div id="cs-opencti-error" style="display:none;margin-top:0.5rem;font-size:0.72rem;color:#f85149"></div>
            </div>
          </div>

          <div class="conn-cfg-card" id="connector-status-card">
            <div class="conn-cfg-row">
              <span class="conn-cfg-label">OTX (AlienVault)</span>
              <span id="cs-otx" class="conn-cfg-val">—</span>
            </div>
```

- [ ] **Step 2: Add the `_renderConnectorCard` helper and wire it into `loadConnectorStatus()`**

Find:
```js
function loadConnectorStatus() {
  var wrap = document.getElementById('connector-status-wrap');
  if (!wrap) return;
  wrap.style.display = '';
  apicall('/api/connector/status').then(function(s) {
    document.getElementById('cs-misp').textContent    = s.mispEnabled    ? '✓ Enabled' : '✗ Not configured';
    document.getElementById('cs-opencti').textContent = s.openctiEnabled ? '✓ Enabled' : '✗ Not configured';
    document.getElementById('cs-otx').textContent     = s.otxEnabled     ? '✓ Enabled' : '✗ Not configured';
    document.getElementById('cs-bundle').textContent = s.bundleEnabled ? ('✓ Enabled (v' + (s.bundleVersion || '?') + ')') : '✗ Not configured';
    document.getElementById('cs-last-sync').textContent = s.lastSyncAt ? new Date(s.lastSyncAt).toLocaleString() : 'Never';
    document.getElementById('cs-created').textContent = (s.scenariosCreated || 0) + ' created, ' + (s.scenariosUpdated || 0) + ' updated';
    document.getElementById('cs-next').textContent = s.nextSyncAt ? new Date(s.nextSyncAt).toLocaleString() : '—';
    var statusEl = document.getElementById('cs-status');
    statusEl.textContent = s.lastSyncStatus || 'never';
    statusEl.style.color = s.lastSyncStatus === 'ok' ? '#5cead8' : s.lastSyncStatus === 'error' ? '#f85149' : 'var(--muted)';
    var errEl = document.getElementById('cs-error');
    if (s.lastError) { errEl.textContent = s.lastError; errEl.style.display = ''; }
    else { errEl.style.display = 'none'; }
  }).catch(function() {});
}
```
Replace with:
```js
// _renderConnectorCard fills one per-connector card (MISP/OpenCTI) from its
// ConnectorStatus.BySource entry. rawCountElId differs per connector because
// the two label their raw fetch count differently ("Events" for MISP vs
// "Threat Actor Nodes" for OpenCTI) — they're genuinely different kinds of
// raw data, not the same concept under two names. See
// docs/superpowers/specs/2026-07-22-connector-rich-status-cards-design.md.
function _renderConnectorCard(prefix, enabled, stat, rawCountElId) {
  var statusEl = document.getElementById('cs-' + prefix + '-status');
  if (!enabled) {
    statusEl.textContent = '✗ Not configured';
    statusEl.style.color = 'var(--muted)';
  } else if (stat && stat.error) {
    statusEl.textContent = '⚠ Error';
    statusEl.style.color = '#f85149';
  } else {
    statusEl.textContent = '✓ Connected';
    statusEl.style.color = '#5cead8';
  }
  document.getElementById(rawCountElId).textContent = stat ? stat.rawCount.toLocaleString() : '—';
  document.getElementById('cs-' + prefix + '-actors').textContent = stat ? stat.actorCount.toLocaleString() : '—';
  document.getElementById('cs-' + prefix + '-lastfetch').textContent = (stat && stat.fetchedAt) ? new Date(stat.fetchedAt).toLocaleString() : '—';
  var errEl = document.getElementById('cs-' + prefix + '-error');
  if (stat && stat.error) { errEl.textContent = stat.error; errEl.style.display = ''; }
  else { errEl.style.display = 'none'; }
}

function loadConnectorStatus() {
  var wrap = document.getElementById('connector-status-wrap');
  if (!wrap) return;
  wrap.style.display = '';
  apicall('/api/connector/status').then(function(s) {
    var bySource = s.bySource || {};
    _renderConnectorCard('misp', s.mispEnabled, bySource.misp, 'cs-misp-events');
    _renderConnectorCard('opencti', s.openctiEnabled, bySource.opencti, 'cs-opencti-nodes');
    document.getElementById('cs-otx').textContent     = s.otxEnabled     ? '✓ Enabled' : '✗ Not configured';
    document.getElementById('cs-bundle').textContent = s.bundleEnabled ? ('✓ Enabled (v' + (s.bundleVersion || '?') + ')') : '✗ Not configured';
    document.getElementById('cs-last-sync').textContent = s.lastSyncAt ? new Date(s.lastSyncAt).toLocaleString() : 'Never';
    document.getElementById('cs-created').textContent = (s.scenariosCreated || 0) + ' created, ' + (s.scenariosUpdated || 0) + ' updated';
    document.getElementById('cs-next').textContent = s.nextSyncAt ? new Date(s.nextSyncAt).toLocaleString() : '—';
    var statusEl = document.getElementById('cs-status');
    statusEl.textContent = s.lastSyncStatus || 'never';
    statusEl.style.color = s.lastSyncStatus === 'ok' ? '#5cead8' : s.lastSyncStatus === 'error' ? '#f85149' : 'var(--muted)';
    var errEl = document.getElementById('cs-error');
    if (s.lastError) { errEl.textContent = s.lastError; errEl.style.display = ''; }
    else { errEl.style.display = 'none'; }
  }).catch(function() {});
}
```

- [ ] **Step 3: Verify the hardlink twin is in sync**

```bash
diff orchestrator/wwwroot/index.html orchestrator/cmd/server/wwwroot/index.html
```
Expected: no output.

- [ ] **Step 4: Structural verification**

```bash
grep -n "cs-misp-status\|cs-misp-events\|cs-opencti-status\|cs-opencti-nodes\|_renderConnectorCard" orchestrator/wwwroot/index.html
```
Expected: matches for both cards' element IDs and the new helper function (defined once, called twice).

- [ ] **Step 5: Live-server smoke test**

```bash
docker run -d --name masd-connstat-verify -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=bas -p 55520:5432 postgres:16-alpine
```
Wait for it to accept connections (`docker exec masd-connstat-verify pg_isready -U postgres`), then from `orchestrator/`:
```bash
DATABASE_URL="postgres://postgres:postgres@localhost:55520/bas?sslmode=disable" JWT_SECRET=dev-secret BAS_LICENSE_PATH="C:/Users/Administrator/Downloads/Audspect_Cloud/audspect-dev.lic" HTTP_PORT=8210 go run ./cmd/server
```
In a second shell:
```bash
curl -s http://localhost:8210/ | grep -o "cs-misp-events\|cs-opencti-nodes\|_renderConnectorCard"
```
Expected: all three strings present in the served HTML.

Then clean up:
```bash
powershell -Command "Get-NetTCPConnection -LocalPort 8210 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique | ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }"
docker rm -f masd-connstat-verify
```

- [ ] **Step 6: Record the manual browser checklist (cannot be executed by the implementer — no browser automation tool is available in this environment)**

Before this is considered fully verified, a human should check in an actual browser, logged in as Admin, in Settings → Threat intel:
1. With MISP and OpenCTI both configured and their last sync healthy — confirm both cards show "✓ Connected" with real Events/Threat Actor Nodes/Actors extracted numbers and a recent Last Fetch time.
2. Force one source to fail (e.g. temporarily point `MISP_URL` at an unreachable host and restart, or wait for a real transient failure) — confirm that card switches to "⚠ Error" with the error detail line visible, while the healthy card is unaffected.
3. With neither MISP nor OpenCTI configured — confirm both cards show "✗ Not configured" with `—` for the numeric rows.
4. Confirm OTX and Bundle rows, and the Last Sync/Status/Scenarios Created/Next Sync summary below, are unchanged from their current behavior.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/wwwroot/index.html orchestrator/cmd/server/wwwroot/index.html
git commit -m "feat(ui): add per-connector rich status cards for MISP and OpenCTI"
git push
```

---

## Self-Review Notes

**Spec coverage:** covers the spec's entire "Design" section — the two-card layout, the "Events" vs "Threat Actor Nodes" label distinction, the error state, the shared `_renderConnectorCard` helper, and leaving OTX/Bundle/the summary rows untouched. The spec's "Explicitly out of scope" items (new MISP/OpenCTI API calls, OTX rich card, Bundle card) are correctly not built.

**Placeholder scan:** none — every step has complete code or an exact command with expected output.

**Type consistency:** `_renderConnectorCard(prefix, enabled, stat, rawCountElId)`'s parameters match exactly how it's called twice in `loadConnectorStatus()`. `stat.rawCount`/`stat.actorCount`/`stat.fetchedAt`/`stat.error` match the exact JSON field names `SourceStat` already serializes as (`orchestrator/internal/connector/types.go`, shipped in sub-project 1) — no new backend fields invented here.
