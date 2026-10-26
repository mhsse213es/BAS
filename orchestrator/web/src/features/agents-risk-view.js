// Agents page: the Risk & Remediation view's KPI strip and charts.
// shell.js owns the view switch and the table; this wraps the switch so the strip loads with it.
import { apicall } from '../core/api.js';
import { setAgentsView } from './shell.js';
import { agentRiskInsightsHtml } from './agents-insights.js';

export function setAgentsViewRich(view) {
  setAgentsView(view);
  if (view !== 'risk') return;
  var el = document.getElementById('agent-risk-tiles');
  if (!el) return;
  apicall('/api/agents/risk-summary').then(function(d) {
    el.innerHTML = agentRiskInsightsHtml((d && d.agents) || []);
  }).catch(function() { el.innerHTML = ''; });
}
