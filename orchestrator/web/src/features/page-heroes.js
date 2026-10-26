import { mountHero } from './shell-ui.js';

// One place for the banner at the top of every page: icon, title, subtitle, actions and the stat
// chips. A page's own loader fills the chips (setHeroStat) from data it already fetched, so a banner
// never shows a number the server did not return -- until the data arrives a chip shows an em dash.
// Icons are internal inline SVG; action buttons use the normal data-on-click registry.

function svg(paths) {
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">' + paths + '</svg>';
}
var ICON = {
  agents: svg('<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>'),
  ok: svg('<path d="M5 12l4 4 10-10"/>'),
  warn: svg('<path d="M12 3l9 16H3z"/><path d="M12 10v4M12 17v.01"/>'),
  bad: svg('<path d="M6 6l12 12M18 6L6 18"/>'),
  retired: svg('<circle cx="12" cy="12" r="8"/><path d="M8 12h8"/>'),
  total: svg('<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8"/>'),
  posture: svg('<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/>'),
  runs: svg('<path d="M7 5l12 7-12 7z"/>'),
  technique: svg('<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/>'),
  clock: svg('<circle cx="12" cy="12" r="8"/><path d="M12 8v4l3 2"/>'),
  trend: svg('<path d="M4 18l5-6 4 3 7-9"/>'),
};

var HEROES = {
  'hero-dashboard': {
    icon: ICON.posture,
    title: 'Security Posture',
    sub: 'Continuous validation of your security controls against real adversary techniques.',
    actions:
      '<button class="btn btn-outline btn-sm" data-on-click="showTab" data-args="[&quot;reports&quot;]">Generate report</button>' +
      '<button class="btn btn-primary btn-sm" data-on-click="openModal">&#9654; New simulation</button>',
    stats: [
      { id: 'hs-dash-agents', icon: ICON.agents, value: '—', label: 'Agents' },
      { id: 'hs-dash-techniques', icon: ICON.technique, value: '—', label: 'ATT&CK techniques tested' },
      { id: 'hs-dash-runs', icon: ICON.runs, value: '—', label: 'Runs' },
      { id: 'hs-dash-last', icon: ICON.clock, value: '—', label: 'Last assessment' },
    ],
  },
  'hero-executive': {
    icon: ICON.trend,
    title: 'Executive Dashboard',
    sub: 'Fleet-wide risk, exposure, and detection-coverage trends over time — daily snapshots, not a single point-in-time report.',
    actions:
      '<select id="ed-range" data-on-change="loadExecDashboard" aria-label="Time range">' +
        '<option value="30">30 days</option><option value="90" selected>90 days</option><option value="365">1 year</option></select>' +
      '<button class="btn btn-outline btn-sm" data-on-click="loadExecDashboard">Refresh</button>',
  },
  'hero-agents': {
    icon: ICON.agents,
    title: 'Simulation agents',
    sub: 'Lightweight collectors across your environment — they execute safe emulations locally and stream telemetry back.',
    actions:
      '<button class="btn btn-outline btn-sm" data-on-click="loadAgents">Refresh</button>' +
      '<button class="btn btn-primary btn-sm" data-on-click="showAgentDownload">&#8595; Deploy agent</button>',
    stats: [
      { id: 'hs-agents-total', icon: ICON.total, value: '—', label: 'Agents' },
      { id: 'hs-agents-online', icon: ICON.ok, tone: 'ok', value: '—', label: 'Online' },
      { id: 'hs-agents-degraded', icon: ICON.warn, tone: 'warn', value: '—', label: 'Degraded' },
      { id: 'hs-agents-offline', icon: ICON.bad, tone: 'bad', value: '—', label: 'Offline' },
      { id: 'hs-agents-retired', icon: ICON.retired, tone: 'muted', value: '—', label: 'Retired' },
    ],
  },
};

export function mountPageHeroes() {
  Object.keys(HEROES).forEach(function(id) { mountHero(id, HEROES[id]); });
}
