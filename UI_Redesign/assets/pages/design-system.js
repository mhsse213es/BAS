/* Design system page — swatches read live from CSS tokens, computed contrast, component demos. */
(function () {
  'use strict';
  var D = window.AUD, h = UI.h, icon = UI.icon, $ = UI.$;

  function tok(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
  function hexToRgb(hex) {
    var m = /^#([0-9a-f]{6})$/i.exec(hex); if (!m) return null;
    var n = parseInt(m[1], 16); return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
  }
  function lum(rgb) { return rgb.map(function (c) { c /= 255; return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4); }).reduce(function (a, c, i) { return a + c * [0.2126, 0.7152, 0.0722][i]; }, 0); }
  function ratio(a, b) { var x = hexToRgb(a), y = hexToRgb(b); if (!x || !y) return null; var l1 = lum(x), l2 = lum(y); return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05); }

  function swatches(host, list) {
    host.replaceChildren();
    list.forEach(function (s) {
      var v = tok(s[0]);
      var meta = s[2] ? (function () { var r = ratio(v, tok('--surface-1')); return r ? r.toFixed(2) + ':1 on surface-1' : ''; })() : (s[3] || '');
      host.appendChild(h('div', { class: 'swatch' }, h('i', { style: 'background:var(' + s[0] + ')' + (s[4] ? ';box-shadow:inset 0 0 0 1px var(--border)' : '') }),
        h('div', null, h('b', null, s[1]), h('code', null, s[0] + ' · ' + v), meta ? h('div', { class: 'xs muted' }, meta) : null)));
    });
  }
  function paint() {
    swatches($('#sw-surface'), [['--bg', 'Page', 0, '', 1], ['--surface-1', 'Card', 0, '', 1], ['--surface-2', 'Raised / header', 0, '', 1], ['--surface-3', 'Hover / track', 0, '', 1], ['--border-strong', 'Border (strong)'], ['--text-1', 'Text primary', 1], ['--text-2', 'Text secondary', 1], ['--text-3', 'Text muted', 1]]);
    swatches($('#sw-brand'), [['--accent', 'Accent', 1], ['--accent-hover', 'Accent hover'], ['--accent-text', 'Link text', 1], ['--accent-soft-2', 'Selection wash', 0, '', 1]]);
    swatches($('#sw-ramp'), ['50', '100', '200', '300', '400', '500', '600', '700', '800', '900'].map(function (n) { return ['--brand-' + n, 'Brand ' + n]; }));
    swatches($('#sw-status'), [['--good', 'Good · prevented', 0, 'Fills, dots and bars'], ['--warning', 'Warning · detected only', 0, 'Always with icon + label'], ['--serious', 'Serious · high', 0, 'Always with icon + label'], ['--critical', 'Critical · missed', 0, 'Fills, dots and bars'], ['--success-text', 'Success text', 1], ['--danger-text', 'Danger text', 1], ['--warning-text', 'Warning text', 1], ['--untested', 'Not tested', 0, 'Empty, never a colour', 1]]);
    swatches($('#sw-viz'), [['--series-1', 'Series 1 · single series'], ['--series-2', 'Series 2'], ['--series-3', 'Series 3 · needs labels on light'], ['--viz-grid', 'Gridline', 0, 'Hairline, solid', 1], ['--viz-axis', 'Baseline / axis'], ['--viz-muted', 'De-emphasis']]);
  }
  paint();
  new MutationObserver(paint).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

  /* --------------------------------------------------------- Demo rows */
  ['P', 'D', 'M', 'U'].forEach(function (c) { $('#demo-outcome').appendChild(UI.outcome(c)); });
  ['critical', 'high', 'medium', 'low'].forEach(function (s) { $('#demo-sev').appendChild(UI.sev(s)); });
  [['good', 'Completed', 'checkCircle'], ['accent', 'Running', 'zap'], ['warning', 'Partial', 'alert'], ['critical', 'Failed', 'xoct'], ['outline', 'Scheduled', 'clock'], ['', 'Risk accepted', 'minus'], ['good', 'Verified fixed', 'badge']].forEach(function (p) { $('#demo-pills').appendChild(UI.pill(p[0], p[1], p[2])); });
  $('#demo-delta').append(UI.delta(6, 'up', ' pts', 'good when up'), UI.delta(-65, 'down', '', 'good when down', '−1m 05s'), UI.delta(-3, 'up', ' pts', 'bad'));

  /* --------------------------------------------------------- Type scale */
  [['Hero figure · 64 / 600', 'hero-num', '72'], ['KPI value · 28 / 600', 'kpi-value', '78%'], ['Page title · 22 / 600', 'page-title', 'Security posture'], ['Panel title · 16 / 600', 'panel-title', 'LSASS memory dumping not prevented'], ['Card title · 14 / 600', 'card-title', 'Where attacks get through'], ['Body · 14 / 400', '', 'Validated control gaps, ranked by projected score gain.'], ['Table · 13 / 400', 'small', 'Weekly BFSI threat pack · 312 simulations'], ['Overline · 11 / 600', 'block-title', 'What happened'], ['Mono · JetBrains Mono', 'mono', 'T1003.001 · F-1042 · SHA-256 3f9a…c21e']].forEach(function (t) {
    $('#type-scale').appendChild(h('div', { class: 'spec' }, h('span', null, t[0]), h('div', { class: t[1] + ' mt-0', style: t[1] === 'block-title' ? 'margin:0' : '' }, t[2])));
  });

  /* --------------------------------------------------- Space/radius/shadow */
  [4, 8, 12, 16, 20, 24, 32, 40].forEach(function (s) { $('#demo-space').appendChild(h('span', { class: 'stack', style: 'gap:4px;align-items:center' }, h('i', { style: 'display:block;width:' + s + 'px;height:' + s + 'px;background:var(--accent-soft-2);border-radius:2px' }), h('span', { class: 'xs muted' }, String(s)))); });
  [['--r-sm', '6'], ['--r-md', '8'], ['--r-lg', '12'], ['--r-pill', 'pill']].forEach(function (r) { $('#demo-radius').appendChild(h('span', { class: 'stack', style: 'gap:4px;align-items:center' }, h('i', { style: 'display:block;width:44px;height:30px;border:1px solid var(--border-strong);background:var(--surface-2);border-radius:var(' + r[0] + ')' }), h('span', { class: 'xs muted' }, r[1]))); });
  ['--shadow-1', '--shadow-2', '--shadow-3'].forEach(function (s, i) { $('#demo-shadow').appendChild(h('span', { class: 'stack', style: 'gap:4px;align-items:center' }, h('i', { style: 'display:block;width:54px;height:34px;border-radius:8px;background:var(--surface-1);border:1px solid var(--border);box-shadow:var(' + s + ')' }), h('span', { class: 'xs muted' }, ['Card', 'Panel / menu', 'Overlay'][i]))); });

  /* ----------------------------------------------------------- KPI + meters */
  var k = D.kpis[0];
  $('#demo-kpi').appendChild(h('div', { class: 'card kpi', style: 'width:240px' }, h('div', { class: 'kpi-label' }, k.label), h('div', { class: 'kpi-value' }, String(k.value), h('span', { class: 'unit' }, '%')), h('div', { class: 'kpi-ctx' }, k.ctx), h('div', { class: 'kpi-foot' }, UI.delta(k.delta, 'up', ' pts', 'vs 30d'), UI.spark(k.spark, { w: 72, h: 28 }))));
  [92, 72, 52, 34].forEach(function (v) { $('#demo-meter').appendChild(h('div', { class: 'metric', style: 'max-width:360px' }, UI.meter(v, UI.band(v), 'sm'), h('span', null, v + '%'))); });
  $('#demo-meter').appendChild(h('div', { style: 'max-width:360px' }, UI.segbar([{ n: 'Prevented', v: 241, color: 'var(--prevented)' }, { n: 'Detected only', v: 37, color: 'var(--detected)' }, { n: 'Missed', v: 34, color: 'var(--missed)' }])));

  /* -------------------------------------------------------------- Table */
  $('#demo-table').appendChild(h('table', { class: 't' },
    h('thead', null, h('tr', null, h('th', null, 'Finding'), h('th', null, 'Outcome'), h('th', { class: 'r' }, 'Endpoints'))),
    h('tbody', null, D.findings.slice(0, 3).map(function (f, i) {
      return h('tr', { class: i === 0 ? 'selected' : null }, h('td', null, h('div', { class: 't-title' }, f.title), h('div', { class: 't-sub' }, f.tech)), h('td', null, UI.outcome(f.detected ? 'D' : 'M')), h('td', { class: 'r' }, String(f.assets)));
    }))));
})();
