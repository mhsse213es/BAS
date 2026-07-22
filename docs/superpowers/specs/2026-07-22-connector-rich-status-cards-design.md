# Threat-Intel Connector Rich Status Cards — Design Spec

**Goal:** replace MISP's and OpenCTI's single status rows in the existing "Threat Intel Connector" card with per-connector cards showing their own real numbers (from sub-project 1's `ConnectorStatus.BySource`), so operators can tell the two apart instead of seeing one merged total. Sub-project 2 of 4 — see `docs/superpowers/specs/2026-07-22-connector-per-source-stats-design.md` for sub-project 1 (already shipped) and the overall initiative context.

**Why now:** sub-project 1 added `ConnectorStatus.BySource` (per-source `RawCount`/`ActorCount`/`FetchedAt`/`Error`), but nothing in the UI reads it yet — `GET /api/connector/status`'s response carries real per-connector data that's currently invisible.

---

## Scope

**In scope:** MISP and OpenCTI get rich per-connector cards using only data `ConnectorStatus.BySource` already provides (no new backend work).

**Explicitly out of scope** (per user decision):
- No new MISP/OpenCTI API calls for Server Version, Feeds, or Tags — deferred until there's a concrete need, not built speculatively here.
- OTX's card stays exactly as it is today (the simple "✓ Enabled / ✗ Not configured" row shipped earlier) — it has no real periodic-sync data yet (sub-project 3), so a richer card would either show fake data or an empty shell.
- Bundle (the air-gapped source) stays a simple row too — it was never part of the original mockup and isn't a live third-party connector.

## Design

### Layout (`orchestrator/wwwroot/index.html`)

Two new cards, side by side above the existing status card, replacing MISP's and OpenCTI's current rows there:

```
┌─ MISP ──────────────────┐  ┌─ OpenCTI ────────────────┐
│ Status      ✓ Connected │  │ Status       ✓ Connected │
│ Events              142 │  │ Threat Actor Nodes    89 │
│ Actors extracted     37 │  │ Actors extracted      22 │
│ Last Fetch  <datetime>  │  │ Last Fetch  <datetime>   │
└──────────────────────────┘  └───────────────────────────┘
```

The existing status card keeps OTX, Bundle, Last Sync, Status, Scenarios Created, and Next Sync unchanged — those describe the combined sync/generation step, not one source.

**"Events" vs "Threat Actor Nodes":** the two connectors' raw counts are genuinely different kinds of data — MISP's `RawCount` is literally event objects; OpenCTI's is already actor-shaped GraphQL nodes (see sub-project 1's spec). Using the same label for both would misrepresent OpenCTI's data, so each card labels its raw-count row with what it actually is.

**Error state:** when `BySource[x].Error` is set (that source's last fetch failed), the card's Status line shows "⚠ Error" instead of "✓ Connected", and an error-detail line appears below the stats — mirrors the existing card's `#cs-error` pattern, just scoped per-connector instead of global.

### Rendering (`loadConnectorStatus()`)

A small shared helper, `_renderConnectorCard(prefix, enabled, stat, rawCountElId)`, since the two cards' rendering logic is identical except for which raw-count element it targets — avoids maintaining two near-duplicate 6-line blocks that could drift out of sync on a future edit:

```js
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
```

Called from `loadConnectorStatus()` as `_renderConnectorCard('misp', s.mispEnabled, (s.bySource||{}).misp, 'cs-misp-events')` and the OpenCTI equivalent with `'cs-opencti-nodes'`. The rest of `loadConnectorStatus()` (OTX, Bundle, Last Sync, Status, Scenarios Created, Next Sync) is untouched.

### No backend changes

`GET /api/connector/status` already returns everything this needs (`BySource` shipped in sub-project 1). This sub-project is frontend-only.

## Testing

No Go test changes (no backend touched). Verification is structural (grep for the new element IDs) + a live-server smoke test confirming the new markup is served, matching every prior UI-only plan in this session. A manual browser checklist covers the actual behavior: MISP/OpenCTI configured and healthy → cards show real numbers; one of them erroring → its card shows the error state; neither configured → both show "Not configured."
