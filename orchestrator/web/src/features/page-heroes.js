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
};

var HEROES = {
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
