// Shell-level product features for the Audspect demo:
// breadcrumbs, pinned + recent pages, saved views, collapsible sidebar, environment badge,
// time-range picker, last-updated stamp, per-panel export. State persists in localStorage when available.
const SHELL = { pins: [], recent: [], views: [], range: '30d', env: 'Production', collapsed: false };
const lsGet = (k, d) => { try { const v = localStorage.getItem('aud-demo-' + k); return v ? JSON.parse(v) : d; } catch (e) { return d; } };
const lsSet = (k, v) => { try { localStorage.setItem('aud-demo-' + k, JSON.stringify(v)); } catch (e) { /* storage blocked: demo still works */ } };
SHELL.pins = lsGet('pins', ['findings', 'agents']);
SHELL.recent = lsGet('recent', []);
SHELL.views = lsGet('views', [
  { name: 'My critical findings', sev: 'critical', q: '' },
  { name: 'High severity on domain controllers', sev: 'high', q: 'DC-' },
]);
SHELL.collapsed = lsGet('collapsed', false);
SHELL.range = lsGet('range', '30d');
SHELL.theme = lsGet('theme', 'dark') === 'light' ? 'light' : 'dark'; // Dark / Light only
SHELL.compact = lsGet('compact', false);
SHELL.reduce = lsGet('reduce', false);
SHELL.accent = lsGet('accent', null);

// Theme / density / motion / accent. Light theme is a full variable override in demo.css.
function shellResolvedTheme() { return SHELL.theme === 'system' ? (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark') : SHELL.theme; }
function shellSetAccent(hex) {
  SHELL.accent = hex; lsSet('accent', hex);
  const n = parseInt(hex.slice(1), 16), r = (n >> 16) & 255, g = (n >> 8) & 255, b = n & 255;
  const lift = c => Math.round(c + (255 - c) * 0.3);
  const st = document.documentElement.style;
  st.setProperty('--accent', hex);
  st.setProperty('--accent-hi', `rgb(${lift(r)},${lift(g)},${lift(b)})`);
  st.setProperty('--accent-dim', `rgba(${r},${g},${b},.14)`);
  st.setProperty('--accent-border', `rgba(${r},${g},${b},.4)`);
}
function shellApplyTheme() {
  const t = shellResolvedTheme();
  document.documentElement.dataset.theme = t;
  document.body.classList.toggle('compact', SHELL.compact);
  document.body.classList.toggle('reduce-motion', SHELL.reduce);
  const tb = document.getElementById('theme-btn');
  if (tb) { tb.innerHTML = ic(t === 'light' ? 'moon' : 'sun'); tb.setAttribute('aria-label', t === 'light' ? 'Switch to dark theme' : 'Switch to light theme'); }
  if (SHELL.accent) shellSetAccent(SHELL.accent);
}
if (window.matchMedia) matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => { if (SHELL.theme === 'system') { shellApplyTheme(); if (window.AUD) AUD.render(); } });

const navLookup = () => { const m = {}; D.NAV.forEach(g => g.items.forEach(([id, label, icon]) => { m[id] = { label, icon, group: g.group }; })); return m; };

function shellApplyChrome() {
  document.body.classList.toggle('nav-collapsed', SHELL.collapsed);
  $$('#range-pick button').forEach(b => b.classList.toggle('on', b.dataset.v === SHELL.range));
  const envName = document.getElementById('env-name');
  if (envName) envName.textContent = SHELL.env;
  document.body.dataset.env = SHELL.env;
  const strip = document.getElementById('env-strip');
  if (strip) {
    strip.classList.toggle('hidden', SHELL.env === 'Production');
    strip.textContent = SHELL.env === 'Production' ? '' : `You are viewing ${SHELL.env.toUpperCase()} data — changes here do not affect production.`;
  }
}
function $$(s, r = document) { return [...r.querySelectorAll(s)]; }

// Extra nav groups (Pinned / Saved views / Recent) injected above the standard groups
SHELL.shut = lsGet('shut', { Recent: true });
function shellNavExtra(route) {
  const lk = navLookup(), item = (id) => lk[id] ? `<div class="nav-item ${route === id ? 'active' : ''}" data-act="nav" data-a="${id}" title="${lk[id].label}">${ic(lk[id].icon)}<span>${lk[id].label}</span></div>` : '';
  const label = (name) => `<div class="nav-group-label togglable ${SHELL.shut[name] ? 'shut' : ''}" data-sh="grp" data-g="${name}">${name}${ic('chev', 'sm')}</div>`;
  let out = '';
  if (SHELL.pins.length) out += `<div class="nav-group">${label('Pinned')}${SHELL.shut.Pinned ? '' : SHELL.pins.map(item).join('')}</div>`;
  if (SHELL.views.length) out += `<div class="nav-group">${label('Saved views')}${SHELL.shut['Saved views'] ? '' : SHELL.views.map((v, i) => `<div class="nav-item" data-act="applyView" data-a="${i}" title="${v.name}">${ic('filter')}<span>${v.name}</span><button class="view-x" data-sh="delview" data-i="${i}" title="Remove saved view">${ic('x', 'sm')}</button></div>`).join('')}</div>`;
  const rec = SHELL.recent.filter(r => r !== route && !SHELL.pins.includes(r)).slice(0, 3);
  if (rec.length) out += `<div class="nav-group">${label('Recent')}${SHELL.shut.Recent ? '' : rec.map(id => { const x = lk[id]; return x ? `<div class="nav-item recent" data-act="nav" data-a="${id}" title="${x.label}">${ic('clock')}<span>${x.label}</span></div>` : ''; }).join('')}</div>`;
  return out;
}

function shellVisit(route) {
  if (!route || route === 'profile') return;
  SHELL.recent = [route, ...SHELL.recent.filter(r => r !== route)].slice(0, 6);
  lsSet('recent', SHELL.recent);
}

// Breadcrumb row + last-updated + pin, placed at the top of the page
function shellCrumbs(route, S) {
  const lk = navLookup();
  let crumbs = [];
  if (route === 'profile') crumbs = [['Account', null], ['My Profile', null]];
  else if (lk[route]) {
    const base = [[lk[route].group, null], [lk[route].label, null]];
    let sub = null;
    if (route === 'scenarios' && S.cat !== 'all') sub = (D.CATEGORIES.find(c => c[0] === S.cat) || [])[1];
    if (route === 'agents' && S.agSel !== 'All agents') sub = S.agSel;
    if (route === 'settings') sub = ({ users: 'Users & roles', caldera: 'Caldera Engine', intel: 'Threat Intel Connector', taxii: 'TAXII Connectors', art: 'ART Content Library', audit: 'Audit Logs', theme: 'Theme & Display', dashprefs: 'Dashboard Preferences', license: 'License', backup: 'Backup & Recovery' })[S.sttab];
    if (route === 'reports') sub = ({ compliance: 'Compliance report', sla: 'SLA compliance' })[(S.tab || {}).reports];
    if (route === 'attackpath') sub = (D.ATTACK_PATHS.find(p => p.id === S.apSel) || {}).name;
    if (route === 'findings' && S.findSev !== 'all') sub = S.findSev + ' severity';
    if (sub) { base[1][1] = route; base.push([sub, null]); }
    crumbs = base;
  }
  const pinned = SHELL.pins.includes(route);
  const t = new Date(), hh = String(t.getHours()).padStart(2, '0'), mm = String(t.getMinutes()).padStart(2, '0'), ss = String(t.getSeconds()).padStart(2, '0');
  return `<div class="crumbs"><nav aria-label="Breadcrumb">${crumbs.map(([l, r], i) => `${i ? '<span class="sep">›</span>' : ''}${r ? `<a data-act="nav" data-a="${r}">${l}</a>` : `<span class="${i === crumbs.length - 1 ? 'cur' : ''}">${l}</span>`}`).join('')}</nav>
    <span class="grow"></span>
    <span class="upd" title="Data refreshes automatically every 60 seconds"><i class="dot pulse"></i>Updated ${hh}:${mm}:${ss}</span>
    <button class="icon-btn sm" data-sh="refresh" title="Refresh now">${ic('refresh', 'sm')}</button>
    ${lk[route] ? `<button class="icon-btn sm pin ${pinned ? 'on' : ''}" data-sh="pin" data-r="${route}" title="${pinned ? 'Unpin from sidebar' : 'Pin to sidebar'}">${ic('star', 'sm')}</button>` : ''}</div>`;
}

// Called after every render: adds the crumb row and a per-panel export button
function shellDecorate(route, S) {
  const c = document.getElementById('content');
  c.insertAdjacentHTML('afterbegin', shellCrumbs(route, S));
  c.querySelectorAll('.card > .card-hd').forEach(hd => {
    if (hd.querySelector('.pexp')) return;
    let act = hd.querySelector('.actions');
    if (!act) { act = document.createElement('div'); act.className = 'actions'; hd.appendChild(act); }
    act.insertAdjacentHTML('beforeend', `<button class="icon-btn sm pexp" data-sh="panelexp" title="Export this panel">${ic('download', 'sm')}</button>`);
  });
  shellApplyChrome();
}

function shellExportPanel(btn) {
  const card = btn.closest('.card');
  const title = (card.querySelector('.card-hd h2') || {}).textContent || 'panel';
  const slug = title.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-');
  const svg = card.querySelector('svg.chart-svg');
  const tk = card.querySelector('[data-tk]');
  if (svg) {
    const css = '.grid-line{stroke:#1e2f4a;stroke-dasharray:3 4}.axis-t{fill:#7a94b0;font:10px monospace}.donut-v{fill:#e6edf7;font:700 24px sans-serif}.donut-l{fill:#7a94b0;font:11px sans-serif}';
    const clone = svg.cloneNode(true);
    clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
    clone.insertAdjacentHTML('afterbegin', `<style>${css}</style><rect width="100%" height="100%" fill="#0e1a2f"/>`);
    const url = URL.createObjectURL(new Blob([clone.outerHTML], { type: 'image/svg+xml' }));
    const a = document.createElement('a'); a.href = url; a.download = slug + '.svg'; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    return AUD.toast('Chart exported', slug + '.svg');
  }
  if (tk && typeof dtExport === 'function' && DT.reg[tk.dataset.tk]) return dtExport(tk.dataset.tk, false);
  AUD.toast('Panel exported', slug + '.csv');
}

// One delegated handler for all data-sh controls
document.addEventListener('click', e => {
  const t = e.target.closest && e.target.closest('[data-sh]');
  if (!t) return;
  e.stopPropagation();
  const k = t.dataset.sh;
  if (k === 'collapse') { SHELL.collapsed = !SHELL.collapsed; lsSet('collapsed', SHELL.collapsed); shellApplyChrome(); setTimeout(() => hydrateCharts(), 260); return; }
  if (k === 'range') { SHELL.range = t.dataset.v; lsSet('range', SHELL.range); shellApplyChrome(); AUD.render(); return AUD.toast('Time range: ' + SHELL.range, 'Trends and KPIs updated'); }
  if (k === 'refresh') { AUD.skeleton(); setTimeout(() => { AUD.render(); AUD.toast('Refreshed', 'Latest data loaded'); }, 380); return; }
  if (k === 'theme') { SHELL.theme = t.dataset.v; lsSet('theme', SHELL.theme); shellApplyTheme(); AUD.render(); return AUD.toast('Theme: ' + t.dataset.v, 'Preference saved'); }
  if (k === 'themetoggle') { SHELL.theme = shellResolvedTheme() === 'light' ? 'dark' : 'light'; lsSet('theme', SHELL.theme); shellApplyTheme(); AUD.render(); return; }
  if (k === 'compact') { SHELL.compact = !SHELL.compact; lsSet('compact', SHELL.compact); shellApplyTheme(); AUD.render(); return; }
  if (k === 'reduce') { SHELL.reduce = !SHELL.reduce; lsSet('reduce', SHELL.reduce); shellApplyTheme(); AUD.render(); return; }
  if (k === 'pin') { const r = t.dataset.r; SHELL.pins = SHELL.pins.includes(r) ? SHELL.pins.filter(x => x !== r) : [...SHELL.pins, r]; lsSet('pins', SHELL.pins); AUD.render(); return AUD.toast(SHELL.pins.includes(r) ? 'Pinned to sidebar' : 'Unpinned', navLookup()[r].label); }
  if (k === 'grp') { const g = t.dataset.g; SHELL.shut[g] = !SHELL.shut[g]; lsSet('shut', SHELL.shut); AUD.render(); return; }
  if (k === 'panelexp') return shellExportPanel(t);
  if (k === 'delview') { e.preventDefault(); SHELL.views.splice(+t.dataset.i, 1); lsSet('views', SHELL.views); AUD.render(); return; }
  if (k === 'env') {
    document.querySelectorAll('.popover').forEach(p => p.remove());
    const p = document.createElement('div'); p.className = 'popover env-pop'; p.style.right = '170px';
    p.innerHTML = '<div class="p-head">Environment</div>' + [['Production', '#10b981', 'Live estate — 428 agents'], ['Staging', '#f59e0b', 'Pre-release validation — 12 agents'], ['Lab', '#a78bfa', 'Sandbox for scenario authoring']].map(([n, c, d]) => `<div class="p-item" data-sh="setenv" data-v="${n}"><span class="dot" style="background:${c};box-shadow:none;margin-top:5px"></span><div><div style="font-weight:500">${n}${SHELL.env === n ? ' ✓' : ''}</div><div class="muted" style="font-size:12px">${d}</div></div></div>`).join('');
    document.getElementById('topbar').appendChild(p);
    return;
  }
  if (k === 'setenv') { SHELL.env = t.dataset.v; document.querySelectorAll('.popover').forEach(p => p.remove()); shellApplyChrome(); AUD.render(); return AUD.toast('Environment: ' + SHELL.env, SHELL.env === 'Production' ? 'Live data' : 'Non-production data'); }
}, true);

// Save the current Findings filter as a sidebar view
function shellSaveView(name, sev, q) {
  SHELL.views.push({ name, sev, q });
  lsSet('views', SHELL.views);
}
shellApplyChrome();
shellApplyTheme();
