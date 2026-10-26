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

// filterHistory: free-text over name, type, scope and id, plus an exact type filter.
export function filterHistory(rows, q, type) {
  var s = String(q == null ? '' : q).trim().toLowerCase();
  return (rows || []).filter(function(r) {
    if (type && r.type !== type) return false;
    if (!s) return true;
    return (r.title + ' ' + r.type + ' ' + r.scope + ' ' + r.id + ' ' + r.by).toLowerCase().indexOf(s) !== -1;
  });
}

// heroStats: the two banner numbers the page can back with real data.
export function heroStats(list, frameworks) {
  return {
    reports: Array.isArray(list) ? list.length : null,
    frameworks: Array.isArray(frameworks) ? frameworks.length : null,
  };
}

// agentRows: agents with at least one completed/partial run, with the latest run's scenario name.
export function agentRows(runs, hostOf) {
  var by = {}, order = [];
  (runs || []).forEach(function(r) {
    if (r.status !== 'completed' && r.status !== 'partial') return;
    var id = r.agentId;
    if (!id) return;
    if (!by[id]) { by[id] = { id: id, host: (hostOf && hostOf[id]) || id, lastName: r.name || '', last: r.completedAt || r.startedAt || '', runs: 0 }; order.push(id); }
    by[id].runs++;
  });
  return order.map(function(id) { return by[id]; });
}

// frameworkCards: one card per compliance framework from /api/compliance/scores.
export function frameworkCards(scores) {
  return (Array.isArray(scores) ? scores : []).map(function(s) {
    var tested = n(s.testedControls), pass = n(s.passingControls), fail = n(s.failingControls);
    var has = tested > 0, pct = n(s.compliancePct);
    var untested = s.untestedControls != null ? n(s.untestedControls) : Math.max(0, n(s.testableControls) - tested);
    var detail = !has ? 'No controls tested yet.'
      : pass + ' of ' + tested + ' tested controls passing' + (fail ? ' · ' + fail + ' failing' : '') + (untested ? ' · ' + untested + ' untested' : '');
    return {
      id: s.frameworkId || '',
      name: s.frameworkName || s.shortName || s.frameworkId || '',
      has: has,
      pct: has ? Math.round(pct) : null,
      tone: !has ? 'muted' : pct >= 75 ? 'ok' : pct >= 50 ? 'warn' : 'bad',
      detail: detail,
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
