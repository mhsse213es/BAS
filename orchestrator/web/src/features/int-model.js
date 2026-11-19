// Pure helpers for the redesigned Integrations page: the connector cards (ITSM + EPP response connectors
// already loaded from GET /api/ticketing/configs and GET /api/actions/configs), the banner figures, the
// category filter and the read-only TAXII table (GET /api/taxii/connectors). No DOM, no network.
// A figure with no source is left out: the EPP API returns no test result, so an EPP connector has no
// "last tested" time and is never counted as connected or as needing attention.

export var KIND_LABEL = { itsm: 'ITSM', epp: 'EPP' };
export var KIND_FILTERS = [['', 'All'], ['itsm', 'ITSM'], ['epp', 'EPP']];

var PROVIDER = {
  servicenow: 'ServiceNow', jira: 'Jira', webhook: 'Webhook',
  crowdstrike: 'CrowdStrike Falcon', microsoft_defender: 'Microsoft Defender for Endpoint', sentinelone: 'SentinelOne',
};
var AUTO = { off: 'Manual only', critical: 'critical', critical_high: 'critical+high', all: 'all findings' };

export function providerLabel(p) { return PROVIDER[p] || String(p == null ? '' : p); }

function ts(v) { var t = v ? new Date(v).getTime() : NaN; return isFinite(t) ? t : null; }

// itsmStatus: four honest states, same rule as the page always used.
export function itsmStatus(c) {
  c = c || {};
  if (!c.enabled) return { tone: 'muted', label: 'Disabled', title: 'Connector is turned off' };
  if (c.lastTestOk === null || c.lastTestOk === undefined) return { tone: 'warn', label: 'Not tested', title: 'Click Test to verify connectivity' };
  if (c.lastTestOk === true) return { tone: 'ok', label: 'Connected', title: 'Last test passed' };
  return { tone: 'bad', label: 'Connection error', title: c.lastTestError || 'Last test failed' };
}

export function eppStatus(c) {
  return c && c.enabled ? { tone: 'ok', label: 'Enabled', title: 'Connector is enabled' } : { tone: 'muted', label: 'Disabled', title: 'Connector is turned off' };
}

function itsmDetail(c) {
  var st = itsmStatus(c);
  if (st.tone === 'bad' && c.lastTestError) return c.lastTestError;
  var a = c.autoCreate && AUTO[c.autoCreate] ? AUTO[c.autoCreate] : 'Manual only';
  return 'Auto-create: ' + a;
}
function eppDetail(c) { return c.baseUrl || (c.tenantId ? 'Tenant ' + c.tenantId : 'Response actions from Findings'); }

// connectorRows merges both lists into one card list: ITSM first, then EPP, each in server order.
export function connectorRows(itsm, epp) {
  var a = Array.isArray(itsm) ? itsm : [], b = Array.isArray(epp) ? epp : [];
  var rows = a.map(function(c) {
    return { kind: 'itsm', id: c.id, name: c.name || '', provider: c.provider, providerLabel: providerLabel(c.provider), status: itsmStatus(c), tested: ts(c.lastTestAt), detail: itsmDetail(c) };
  });
  return rows.concat(b.map(function(c) {
    return { kind: 'epp', id: c.id, name: c.name || '', provider: c.provider, providerLabel: providerLabel(c.provider), status: eppStatus(c), tested: null, detail: eppDetail(c) };
  }));
}

export function filterRows(rows, q, kind) {
  var s = String(q || '').trim().toLowerCase();
  return (rows || []).filter(function(r) {
    if (kind && r.kind !== kind) return false;
    if (!s) return true;
    return (r.name + ' ' + KIND_LABEL[r.kind] + ' ' + r.providerLabel + ' ' + r.detail + ' ' + r.status.label).toLowerCase().indexOf(s) >= 0;
  });
}

export function kindCounts(rows) {
  var c = { '': (rows || []).length, itsm: 0, epp: 0 };
  (rows || []).forEach(function(r) { c[r.kind] = (c[r.kind] || 0) + 1; });
  return c;
}

// heroStats: total connectors, ITSM connectors whose last test passed, enabled ITSM connectors that
// failed or were never tested, and the most recent test time.
export function heroStats(rows) {
  var r = rows || [];
  var fresh = null;
  r.forEach(function(x) { if (x.tested != null && (fresh == null || x.tested > fresh)) fresh = x.tested; });
  return {
    total: r.length,
    connected: r.filter(function(x) { return x.kind === 'itsm' && x.status.tone === 'ok'; }).length,
    attention: r.filter(function(x) { return x.kind === 'itsm' && (x.status.tone === 'bad' || x.status.tone === 'warn'); }).length,
    freshest: fresh,
  };
}

// since: "2 min", "3 h", "4 d" for the banner; sinceAgo adds the word the cards use.
export function since(t, now) {
  if (t == null) return '—';
  var s = Math.max(0, Math.floor(((now == null ? Date.now() : now) - t) / 1000));
  if (s < 60) return s + ' s';
  if (s < 3600) return Math.floor(s / 60) + ' min';
  if (s < 86400) return Math.floor(s / 3600) + ' h';
  return Math.floor(s / 86400) + ' d';
}
export function sinceAgo(t, now) { return t == null ? '' : since(t, now) + ' ago'; }

// cardMeta: the caption under the card name.
export function cardMeta(r, now) {
  var base = KIND_LABEL[r.kind] + ' · ' + r.providerLabel;
  return r.kind === 'itsm' ? base + ' · ' + (r.tested != null ? 'last tested ' + sinceAgo(r.tested, now) : 'never tested') : base;
}

// ---- TAXII (read-only table, same figures as the Settings table) ----
export function taxiiStatus(c) {
  c = c || {};
  if (!c.enabled) return { tone: 'muted', label: 'Disabled' };
  if (c.lastPollStatus === 'error') return { tone: 'bad', label: 'Error' };
  if (c.lastPollStatus === 'ok') return { tone: 'ok', label: 'Active' };
  return { tone: 'warn', label: 'Not polled' };
}
export function taxiiRows(list, now) {
  return (Array.isArray(list) ? list : []).map(function(c) {
    var t = ts(c.lastPollAt);
    return { name: c.name || '', url: c.serverUrl || '', status: taxiiStatus(c), last: t == null ? 'Never' : sinceAgo(t, now) };
  });
}
