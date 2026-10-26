// Shared building blocks for the deep page modules (demo-pages1..3.js). Loaded after demo-app.js.
const KIT = (() => {
  const { S, h } = AUD;
  const K = {};
  // Hero banner + stat strip, the same pattern the Scenarios page uses
  K.hero = (icon, title, sub, actions, stats) => `<div class="scn-banner"><div class="row" style="align-items:flex-start;gap:16px">
    <div class="brand-mark" style="width:56px;height:56px;border-radius:14px">${ic(icon)}</div>
    <div class="grow"><h1 style="font-size:26px">${title}</h1><div class="muted" style="margin-top:6px">${sub}</div></div>
    <div class="row hero-actions">${actions}</div></div>
    <div class="stats">${stats.map(([i, v, l]) => `<div class="stat"><span class="ico">${ic(i)}</span><div><b>${v}</b><span>${l}</span></div></div>`).join('')}</div></div>`;
  K.search = (key, ph) => `<div class="input-icon">${ic('search')}<input class="input" placeholder="${ph}" value="${S[key] || ''}" data-input="${key}"></div>`;
  K.select = (key, label, opts) => `<select class="select" data-change="setSel" data-a="${key}"><option value="">${label}</option>${opts.map(o => { const [v, l] = Array.isArray(o) ? o : [o, o]; return `<option value="${v}" ${S[key] === v ? 'selected' : ''}>${l}</option>`; }).join('')}</select>`;
  K.filters = (...parts) => `<div class="filter-bar">${parts.join('')}</div>`;
  K.clearBtn = keys => `<button class="btn ghost" data-act="clearKeys" data-a="${keys.join(',')}">${ic('x', 'sm')}Clear</button>`;
  K.card = (title, body, right = '', cls = '') => `<div class="card ${cls}"><div class="card-hd"><h2>${title}</h2>${right ? `<div class="actions">${right}</div>` : ''}</div>${body}</div>`;
  K.kv = rows => `<dl class="kv">${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl>`;
  K.empty = (icon, title, sub) => `<div class="card empty">${ic(icon)}<b>${title}</b><div>${sub}</div></div>`;
  K.hbars = rows => rows.map(([n, v, c, sfx = '%']) => `<div class="hbar-row"><span>${n}</span>${h.bar(typeof v === 'number' && sfx === '%' ? v : Math.min(100, v), c)}<span class="v">${v}${sfx}</span></div>`).join('');
  K.prog = (v, c = '') => `<div class="row" style="gap:8px;min-width:120px"><div class="grow">${h.bar(v, c)}</div><span class="mono muted" style="width:36px;text-align:right">${v}%</span></div>`;
  K.pct = v => v >= 80 ? 'green' : v >= 60 ? 'amber' : 'red';
  K.avatar = n => `<span class="avatar-sm">${n.split(/[ .]/).filter(Boolean).slice(0, 2).map(x => x[0].toUpperCase()).join('')}</span>`;
  K.donut = (segs, sub, h2 = 170, center) => chartSlot({ type: 'donut', h: h2, legendRight: true, centerSub: sub, center, segments: segs });
  K.hist = (route, list) => h.tabs(route, list);
  K.list = (arr, f) => arr.map(f).join('');
  K.dr = (title, sub, icon, body, foot = '') => h.drawer(h.dhd(title, sub, icon) + `<div class="drawer-bd">${body}</div><div class="drawer-ft"><button class="btn" data-act="closeDrawer">Close</button>${foot}</div>`);
  // Generic "clear these state keys" action
  AUD.A.clearKeys = d => { d.a.split(',').forEach(k => { S[k] = ''; }); AUD.render(); };
  return K;
})();

// Login screen interactions
(() => {
  const $ = q => document.querySelector(q);
  document.addEventListener('click', e => {
    const t = e.target.closest('[data-lg]'); if (!t) return;
    if (t.dataset.lg === 'eye') { const i = $('#login-pw'); i.type = i.type === 'password' ? 'text' : 'password'; }
    if (t.dataset.lg === 'sso') { const b = $('#login-btn'); b.textContent = 'Redirecting to identity provider…'; setTimeout(() => { b.textContent = 'Sign in'; b.click(); }, 600); }
    if (t.dataset.lg === 'forgot') { e.preventDefault(); AUD.toast('Password reset', 'A reset link would be emailed (demo)', 'info'); }
  });
})();

// Ctrl+B toggles the sidebar
document.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'b' && !document.querySelector('#app').classList.contains('hidden')) { e.preventDefault(); document.querySelector('#collapse-btn').click(); }
});
