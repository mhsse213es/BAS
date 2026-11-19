// Pure helpers for the redesigned Email page: banner numbers, coverage ring and area rows, the
// time-based metric tiles, catalogue cards, latest-run lookup and the campaign filter. No DOM, no
// network: everything comes from the responses the page already loads
// (/api/emailgw/coverage, /api/emailgw/metrics, /api/emailgw-runs, /api/emailgw-campaigns).

function n(v) { var k = Number(v); return isFinite(k) ? k : 0; }

// heroStats: the four banner numbers from the run and campaign lists (null until both are loaded).
export function heroStats(runs, campaigns) {
  if (!Array.isArray(runs) || !Array.isArray(campaigns)) return { runs: null, completed: null, failed: null, campaigns: null };
  var by = function(st) { return runs.filter(function(r) { return r.status === st; }).length; };
  return { runs: runs.length, completed: by('completed'), failed: by('failed'), campaigns: campaigns.length };
}

// coverageSummary: ring percentage and one row per area. An excluded area is neither covered nor missing.
export function coverageSummary(areas) {
  var list = Array.isArray(areas) ? areas : [];
  var covered = list.filter(function(a) { return a.status === 'covered'; }).length;
  var excluded = list.filter(function(a) { return a.status === 'excluded'; }).length;
  var scope = list.length - excluded;
  return {
    total: list.length, covered: covered, excluded: excluded,
    pct: scope > 0 ? Math.round(covered / scope * 100) : 0,
    rows: list.map(function(a) {
      return {
        label: (a.areaId ? a.areaId + ' — ' : '') + (a.areaName || ''),
        status: a.status === 'covered' ? 'covered' : a.status === 'excluded' ? 'excluded' : 'missing',
        reason: a.exclusionReason || '',
      };
    }),
  };
}

// fmtSeconds: a mean latency as a short human string.
export function fmtSeconds(s) {
  s = n(s);
  if (s < 60) return Math.round(s) + 's';
  if (s < 3600) return (Math.round(s / 6) / 10) + ' min';
  return (Math.round(s / 360) / 10) + ' h';
}

// latencyTile: value and note for one MTTD/MTTR figure. Without enough samples it says so, never a number.
export function latencyTile(label, lat) {
  if (!lat || lat.unavailable) return { label: label, value: '—', note: 'no eligible samples', tone: 'muted' };
  if (!lat.sufficient) return { label: label, value: '—', note: n(lat.sampleCount) + '/' + n(lat.minimumSampleSize) + ' samples', tone: 'muted' };
  return { label: label, value: lat.meanSeconds != null ? fmtSeconds(lat.meanSeconds) : '—', note: 'n=' + n(lat.sampleCount), tone: 'ok' };
}

// metricTiles: MTTD and MTTR for each environment that returned data.
export function metricTiles(m) {
  m = m || {};
  var out = [];
  [['Lab', m.lab], ['Customer', m.customer]].forEach(function(e) {
    if (!e[1]) return;
    out.push(latencyTile('Mean time to detect · ' + e[0], (e[1].detection || {}).latency));
    out.push(latencyTile('Mean time to respond · ' + e[0], (e[1].response || {}).latency));
  });
  return out;
}

// outcomeShare: the share of runs with a confirmed-success outcome for one dimension (null with no runs).
export function outcomeShare(dim) {
  var o = (dim || {}).outcomes || {};
  var succ = n(o.confirmedSuccess);
  var total = succ + n(o.confirmedFailure) + n(o.inconclusive) + n(o.notTested) + n(o.notApplicable);
  return total ? { pct: succ / total * 100, succ: succ, total: total } : null;
}

// catalogCards: one card per scenario; the tags are the kinds of check it holds.
export function catalogCards(catalog) {
  var known = { 'known-good': 1, 'known-bad': 1, detection: 1, response: 1 };
  return (catalog || []).map(function(sc) {
    var kinds = [];
    sc.expectations.forEach(function(e) {
      var k = e.id.split('.').pop();
      if (known[k] && kinds.indexOf(k) < 0) kinds.push(k);
    });
    return { id: sc.id, name: sc.name, count: sc.expectations.length, kinds: kinds };
  });
}

// latestByScenario: scenarioId -> the most recently started run.
export function latestByScenario(runs) {
  var out = {};
  (runs || []).forEach(function(r) {
    var cur = out[r.scenarioId];
    if (!cur || String(r.startedAt || '') > String(cur.startedAt || '')) out[r.scenarioId] = r;
  });
  return out;
}

// campaignName: the template's display name, else its id.
export function campaignName(c, templates) {
  var t = (templates || []).filter(function(x) { return x.id === c.templateId; })[0];
  return t ? t.name : (c.templateId || 'Campaign');
}

// filterCampaigns: status chip plus free-text search over name, id and template id.
export function filterCampaigns(list, templates, status, q) {
  var needle = String(q || '').trim().toLowerCase();
  return (list || []).filter(function(c) {
    if (status && status !== 'all' && c.status !== status) return false;
    if (!needle) return true;
    return (campaignName(c, templates) + ' ' + (c.id || '') + ' ' + (c.templateId || '')).toLowerCase().indexOf(needle) >= 0;
  });
}

// templateUse: how many campaigns were launched from a template.
export function templateUse(list, templateId) {
  return (list || []).filter(function(c) { return c.templateId === templateId; }).length;
}
