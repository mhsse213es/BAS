// Integrations page: charts (the KPI figures are the banner stats, see int-model.js) over the ITSM and EPP connector lists the page already loads.
import { grid, card, hbars } from '../core/kit.js';
import { chartSlot, CHART_COLORS } from '../core/charts.js';

var itsm = null, epp = null;
var PROV = { servicenow: 'ServiceNow', jira: 'Jira', webhook: 'Webhook', crowdstrike: 'CrowdStrike Falcon', microsoft_defender: 'Defender for Endpoint', sentinelone: 'SentinelOne' };

export function connectorStats(itsmList, eppList) {
  var a = Array.isArray(itsmList) ? itsmList : [], b = Array.isArray(eppList) ? eppList : [];
  var connected = a.filter(function(c) { return c.enabled && c.lastTestOk === true; }).length;
  var failed = a.filter(function(c) { return c.enabled && c.lastTestOk === false; }).length;
  var untested = a.filter(function(c) { return c.enabled && (c.lastTestOk === null || c.lastTestOk === undefined); }).length;
  var disabled = a.filter(function(c) { return !c.enabled; }).length;
  var byProv = {};
  a.concat(b).forEach(function(c) { var k = PROV[c.provider] || c.provider || 'Other'; byProv[k] = (byProv[k] || 0) + 1; });
  var prov = Object.keys(byProv).map(function(k) { return [k, byProv[k]]; });
  prov.sort(function(p, q) { return q[1] - p[1] || (p[0] < q[0] ? -1 : 1); });
  return {
    itsm: a.length, epp: b.length, connected: connected, failed: failed, untested: untested, disabled: disabled,
    auto: a.filter(function(c) { return c.enabled && c.autoCreate && c.autoCreate !== 'off'; }).length,
    eppEnabled: b.filter(function(c) { return c.enabled; }).length, prov: prov,
  };
}

export function integrationsInsightsHtml(itsmList, eppList) {
  var s = connectorStats(itsmList, eppList);
  if (!s.itsm && !s.epp) return '';
  var segs = [
    { label: 'Connected', value: s.connected, color: CHART_COLORS.ok },
    { label: 'Not tested', value: s.untested, color: CHART_COLORS.warn },
    { label: 'Test failed', value: s.failed, color: CHART_COLORS.bad },
    { label: 'Disabled', value: s.disabled, color: CHART_COLORS.muted },
  ].filter(function(g) { return g.value > 0; });
  var cards = [];
  if (segs.length) cards.push(card('ITSM connector health', chartSlot({ type: 'donut', segments: segs, center: String(s.itsm), centerSub: 'connectors', h: 140, legend: true })));
  cards.push(card('Connectors by provider', hbars(s.prov.map(function(r) { return [r[0], r[1] / s.prov[0][1] * 100, 'accent', String(r[1])]; }))));
  return grid(2, cards);
}

function paint() {
  var el = document.getElementById('integrations-insights');
  if (el) el.innerHTML = integrationsInsightsHtml(itsm, epp);
}
export function setItsmConnectors(list) { itsm = list; paint(); }
export function setEppConnectors(list) { epp = list; paint(); }
