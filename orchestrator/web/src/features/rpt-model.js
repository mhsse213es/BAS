// Pure helpers for the redesigned Reports page (Reports / Compliance report / SLA compliance): history
// rows and their filter, the per-agent launcher rows, the framework cards, the generate-modal formats
// and the SLA numbers. No DOM, no network.
// Everything comes from what the page already loads: /api/reports (history), /api/scenarios/runs
// (agents with completed runs), /api/compliance/frameworks and /api/compliance/scores, /api/sla/report.

function n(v) { return Number(v) || 0; }

export var TYPE_LABEL = { posture: 'Posture report', audit: 'Audit pack', compliance: 'Compliance evidence' };

export function typeLabel(t) { return TYPE_LABEL[t] || String(t || '—'); }

// formatsFor: the formats the report endpoint really supports for each type.
export function formatsFor(type) {
  if (type === 'audit') return [{ value: '', label: 'Package' }];
  if (type === 'compliance') return [{ value: 'html', label: 'HTML' }, { value: 'csv', label: 'CSV' }];
  return [{ value: 'html', label: 'HTML' }, { value: 'csv', label: 'CSV (forensic)' }];
}

// historyRows: one display row per /api/reports entry, newest first as the server sent them.
export function historyRows(list) {
  return (Array.isArray(list) ? list : []).map(function(r) {
    var fmt = String(r.format || '').toLowerCase();
    return {
      id: String(r.id || ''),
      shortId: String(r.id || '').slice(0, 8),
      type: r.reportType || '',
      name: typeLabel(r.reportType),
      title: typeLabel(r.reportType) + (r.scopeLabel ? ' — ' + r.scopeLabel : ''),
      scope: r.scopeLabel || '—',
      // The server sends the agent id; an older response carries it only inside the scope label ("framework · agent").
      agentId: r.agentId || String(r.scopeLabel || '').split(' · ').pop() || '',
      // "7f3e2d…9a4c": enough of the id to recognise a report without the full 36 characters.
      idShort: String(r.id || '').length > 12 ? String(r.id).slice(0, 6) + '…' + String(r.id).slice(-4) : String(r.id || ''),
      at: r.generatedAt || '',
      by: r.generatedBy || '—',
      fmt: fmt ? fmt.toUpperCase() : (r.reportType === 'audit' ? 'PACKAGE' : '—'),
      failed: r.status === 'failed',
      downloadPath: r.downloadPath || '',
      // An HTML report is the only one a browser can show inline; the rest are file downloads.
      canPreview: fmt === 'html' && !!r.downloadPath,
    };
  });
}

// typeOptions: the distinct report types present, as [value, label] for the type filter.
export function typeOptions(rows) {
  var seen = {}, out = [];
  (rows || []).forEach(function(r) { if (r.type && !seen[r.type]) { seen[r.type] = 1; out.push([r.type, typeLabel(r.type)]); } });
  return out;
}

// The date ranges the history can be limited to ("all" shows everything).
export var DATE_RANGES = [['all', 'All time'], ['7', 'Last 7 days'], ['30', 'Last 30 days'], ['90', 'Last 90 days']];
export var SORTS = [['new', 'Newest first'], ['old', 'Oldest first'], ['type', 'Type']];

// filterHistory: free-text over name, type, scope and id, plus an exact type filter. opt = { agent, days, now } adds
// an agent filter and a "last N days" window; a row with no readable date is kept rather than silently dropped.
export function filterHistory(rows, q, type, opt) {
  var s = String(q == null ? '' : q).trim().toLowerCase();
  var o = opt || {};
  var days = parseInt(o.days, 10);
  var cutoff = days > 0 ? (o.now == null ? Date.now() : o.now) - days * 86400000 : null;
  return (rows || []).filter(function(r) {
    if (type && r.type !== type) return false;
    if (o.agent && r.agentId !== o.agent) return false;
    if (cutoff != null) {
      var t = Date.parse(r.at);
      if (!isNaN(t) && t < cutoff) return false;
    }
    if (!s) return true;
    return (r.title + ' ' + r.type + ' ' + r.scope + ' ' + r.id + ' ' + r.by).toLowerCase().indexOf(s) !== -1;
  });
}

// sortHistory returns a sorted copy: newest or oldest first by generation time, or grouped by type name.
export function sortHistory(rows, how) {
  var t = function(r) { var v = Date.parse(r.at); return isNaN(v) ? 0 : v; };
  var out = (rows || []).slice();
  if (how === 'old') out.sort(function(a, b) { return t(a) - t(b); });
  else if (how === 'type') out.sort(function(a, b) { return a.name < b.name ? -1 : a.name > b.name ? 1 : t(b) - t(a); });
  else out.sort(function(a, b) { return t(b) - t(a); });
  return out;
}

// agentOptions: the agents that appear in the history, as [id, label] using the host name when known.
export function agentOptions(rows, hostOf) {
  var seen = {}, out = [];
  (rows || []).forEach(function(r) {
    if (r.agentId && !seen[r.agentId]) { seen[r.agentId] = 1; out.push([r.agentId, (hostOf && hostOf[r.agentId]) || r.agentId]); }
  });
  return out.sort(function(a, b) { return a[1] < b[1] ? -1 : 1; });
}

// osKind groups an agent's osVersion into the icon the page shows.
export function osKind(osVersion) {
  var l = String(osVersion || '').toLowerCase();
  if (l.indexOf('windows') >= 0) return 'windows';
  if (/(linux|ubuntu|debian|centos|red hat|rhel|fedora|suse|alma|rocky|amazon)/.test(l)) return 'linux';
  if (/(mac|darwin)/.test(l)) return 'mac';
  return 'other';
}

// heroStats: the two banner numbers the page can back with real data.
export function heroStats(list, frameworks) {
  var latest = '';
  (Array.isArray(list) ? list : []).forEach(function(r) { if (r.generatedAt && Date.parse(r.generatedAt) > (Date.parse(latest) || 0)) latest = r.generatedAt; });
  return {
    latest: latest,
    reports: Array.isArray(list) ? list.length : null,
    frameworks: Array.isArray(frameworks) ? frameworks.length : null,
  };
}

// A run that is still going, or waiting to, has nothing to report on yet and is shown on Live Runs instead.
var LIVE = { running: 1, queued: 1, pending: 1, paused: 1, dispatched: 1 };
// A report is offered only for a run that finished and produced results.
export function isReportable(status) { return status === 'completed' || status === 'partial'; }

// runResult: the headline verdict of one run, from the same counts the Live Runs badge uses (score first, then the
// per-step results). Errors and skips are not passes, so a run with errors and no failures reads ERROR, never PASS.
// Returns { result, pass, fail, error, skipped }; result is '' when the run carries no verdicts (e.g. it failed to start).
export function runResult(r) {
  var sc = r && r.score, c;
  if (sc && typeof sc.totalTechniques !== 'undefined') {
    c = { pass: n(sc.passedTechniques), fail: n(sc.failedTechniques), error: n(sc.erroredTechniques), skipped: n(sc.skippedTechniques) + n(sc.vetoedTechniques) };
  } else {
    var res = (r && r.results) || [], by = function(f) { return res.filter(f).length; };
    c = { pass: by(function(x) { return x.result === 'pass' || x.result === 'blocked'; }), fail: by(function(x) { return x.result === 'fail'; }),
          error: by(function(x) { return x.result === 'error'; }), skipped: by(function(x) { return x.result === 'skipped' || x.result === 'vetoed'; }) };
  }
  var total = c.pass + c.fail + c.error + c.skipped;
  c.result = !total ? '' : c.fail ? 'FAIL' : c.error ? 'ERROR' : c.pass ? 'PASS' : 'SKIPPED';
  return c;
}

// agentRows: one row per agent that has finished runs, newest first. `runs` counts the runs that can be reported on and
// `list` holds every finished run of the agent (failed ones too, marked as such) so none is hidden behind "latest".
// `recentExecutions` holds up to 5 most recent scenario runs (newest first) with name, status, and timestamp.
// Sweep rows are grouped on Live Runs and left out here.
export function agentRows(runs, hostOf, infoOf, now) {
  var by = {}, order = [];
  (runs || []).forEach(function(r) {
    var id = r.agentId;
    if (!id || r.sweepId || r.emSweepId || LIVE[r.status]) return;
    if (!by[id]) { by[id] = { id: id, host: (hostOf && hostOf[id]) || id, lastName: '', last: '', runs: 0, failed: 0, total: 0, scenarios: 0, recentExecutions: [], list: [] }; order.push(id); }
    var row = by[id], ok = isReportable(r.status);
    var at = r.completedAt || r.startedAt || '';
    row.list.push({ id: r.id || '', name: r.name || 'unnamed scenario', status: r.status || '', at: at, reportable: ok && !!r.id, verdict: runResult(r) });
    if (ok) {
      if (!row.lastName) { row.lastName = r.name || ''; row.last = at; }
      row.runs++;
    } else { row.failed++; }
  });
  order.forEach(function(id) {
    var row = by[id];
    if (!row.lastName && row.list.length) { row.lastName = row.list[0].name; row.last = row.list[0].at; }
    // Every finished run counts as an execution (failed ones too); `scenarios` is how many distinct ones they cover.
    row.total = row.list.length;
    var names = {}; row.list.forEach(function(e) { names[e.name] = 1; });
    row.scenarios = Object.keys(names).length;
    // Newest first for the at-a-glance list. The sort is on a copy so `list` keeps the order the server sent; a run
    // with no timestamp sinks to the bottom rather than posing as the newest.
    var stamp = function(e) { var v = Date.parse(e.at); return isNaN(v) ? -Infinity : v; };
    row.recentExecutions = row.list.map(function(e, i) { return { e: e, i: i }; })
      .sort(function(a, b) { var d = stamp(b.e) - stamp(a.e); return d === 0 || isNaN(d) ? a.i - b.i : d; })
      .map(function(w) { return w.e; });
  });
  var t = now == null ? Date.now() : now;
  return order.map(function(id) {
    var row = by[id], info = (infoOf && infoOf[id]) || {};
    row.os = osKind(info.os);
    row.online = !!info.status && info.status !== 'offline';
    var last = Date.parse(row.last);
    row.recent = !isNaN(last) && t - last >= 0 && t - last < 24 * 3600000;
    return row;
  });
}

// frameworkCards: one card per compliance framework from /api/compliance/scores.
export function frameworkCards(scores) {
  return (Array.isArray(scores) ? scores : []).map(function(s) {
    var tested = n(s.testedControls), pass = n(s.passingControls), fail = n(s.failingControls);
    var has = tested > 0, pct = n(s.compliancePct);
    var testable = n(s.testableControls) || tested;
    var untested = s.untestedControls != null ? n(s.untestedControls) : Math.max(0, n(s.testableControls) - tested);
    // The percentage is the resistance rate over tested controls only. It is never shown without coverage, and it
    // is not coloured as good when too little was tested for a framework-level conclusion.
    var cov = s.coveragePct != null ? n(s.coveragePct) : (testable > 0 ? tested / testable * 100 : 0);
    var sufficient = has && (s.sufficientCoverage != null ? !!s.sufficientCoverage : cov >= 50);
    var detail = !has ? 'No controls tested yet.'
      : pass + ' of ' + tested + ' tested controls resisted the executed techniques' + (fail ? ' · ' + fail + ' failing' : '') + (untested ? ' · ' + untested + ' untested' : '');
    return {
      id: s.frameworkId || '',
      name: s.frameworkName || s.shortName || s.frameworkId || '',
      has: has,
      pct: has ? Math.round(pct) : null,
      tone: !has ? 'muted' : !sufficient ? 'warn' : pct >= 75 ? 'ok' : pct >= 50 ? 'warn' : 'bad',
      detail: detail,
      coverage: has ? 'Control coverage ' + tested + ' of ' + testable + ' (' + Math.round(cov * 10) / 10 + '%)' : '',
      sufficient: sufficient,
      note: has && !sufficient ? (s.coverageNote || 'Insufficient coverage for framework-level conclusions') : '',
      warning: s.mappingWarning || '',
    };
  });
}

// ---- SLA ----

export function slaTone(rate) { return rate >= 90 ? 'ok' : rate >= 75 ? 'warn' : 'bad'; }

// medianDays: median time from an episode opening to its resolution, over the recently resolved list.
export function medianDays(recent) {
  var d = (recent || []).map(function(r) {
    var a = Date.parse(r.startedAt), b = Date.parse(r.resolvedAt);
    return isNaN(a) || isNaN(b) || b < a ? null : (b - a) / 86400000;
  }).filter(function(v) { return v != null; }).sort(function(a, b) { return a - b; });
  if (!d.length) return null;
  var m = d.length >> 1;
  return d.length % 2 ? d[m] : (d[m - 1] + d[m]) / 2;
}

export function daysText(v) {
  if (v == null) return '—';
  return v < 1 ? Math.max(1, Math.round(v * 24)) + ' h' : (v < 10 ? Math.round(v * 10) / 10 : Math.round(v)) + ' d';
}

// slaKpis: the four SLA numbers. The rate shows an em dash until something has resolved.
export function slaKpis(overall, recent) {
  var o = overall || {};
  var resolved = n(o.onTime) + n(o.late);
  var med = medianDays(recent);
  return {
    rate: resolved ? Number(o.complianceRate).toFixed(1) + '%' : '—',
    rateTone: resolved ? slaTone(n(o.complianceRate)) : 'muted',
    rateSub: resolved ? n(o.onTime) + ' of ' + resolved + ' resolved on time' : 'nothing resolved yet',
    median: daysText(med),
    medianSub: med == null ? 'no resolved episodes yet' : 'over the ' + (recent || []).length + ' most recent resolved',
    late: n(o.late),
    lateSub: 'resolved after the deadline',
    open: n(o.currentlyOpen),
    openSub: 'of ' + n(o.totalEpisodes) + ' episodes',
  };
}

var SEV = { Critical: 0, High: 1, Medium: 2, Low: 3 };

// slaSeverityRows: rows for kit.hbars in severity order: [label, percent, tone, valueText].
export function slaSeverityRows(bySeverity) {
  var rank = function(s) { return s in SEV ? SEV[s] : 9; };
  return (bySeverity || []).slice().sort(function(a, b) { return rank(a.severity) - rank(b.severity); }).map(function(s) {
    var has = n(s.onTime) + n(s.late) > 0;
    return [s.severity + ' · ' + n(s.onTime) + ' on time / ' + n(s.late) + ' late', has ? n(s.complianceRate) : 0, has ? slaTone(n(s.complianceRate)) : 'muted', has ? Math.round(n(s.complianceRate)) + '%' : '—'];
  });
}

// slaTrend: months in order with their compliance rate.
export function slaTrend(monthly) {
  return (monthly || []).slice().sort(function(a, b) { return a.month < b.month ? -1 : a.month > b.month ? 1 : 0; }).map(function(m) {
    return { month: m.month, rate: n(m.complianceRate) };
  });
}
