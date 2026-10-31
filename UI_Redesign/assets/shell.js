/* =============================================================================
   Audspect design proposal — shared shell, DOM helpers and chart kit.
   No dependencies, no network, works from file://. Labels are always inserted
   with textContent (never innerHTML) — the same rule the console should follow.
   ========================================================================== */
(function () {
  'use strict';
  var NS = 'http://www.w3.org/2000/svg';

  /* ---------------------------------------------------------------- DOM --- */
  function setAttrs(el, attrs) {
    if (!attrs) return;
    Object.keys(attrs).forEach(function (k) {
      var v = attrs[k];
      if (v == null || v === false) return;
      if (k === 'class') el.setAttribute('class', v);
      else if (k === 'style') el.style.cssText = v;
      else if (k === 'text') el.textContent = v;
      else if (k.slice(0, 2) === 'on' && typeof v === 'function') el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : v);
    });
  }
  function append(el, kids) {
    kids.forEach(function (kid) {
      if (kid == null || kid === false) return;
      if (Array.isArray(kid)) { append(el, kid); return; }
      el.appendChild(typeof kid === 'object' ? kid : document.createTextNode(String(kid)));
    });
  }
  function h(tag, attrs) { var el = document.createElement(tag); setAttrs(el, attrs); append(el, [].slice.call(arguments, 2)); return el; }
  function s(tag, attrs) { var el = document.createElementNS(NS, tag); setAttrs(el, attrs); append(el, [].slice.call(arguments, 2)); return el; }
  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) { return [].slice.call((root || document).querySelectorAll(sel)); }

  /* -------------------------------------------------------------- Icons --- */
  var ICONS = {
    gauge: '<path d="m12 14 4-4"/><path d="M3.34 19a10 10 0 1 1 17.32 0"/>',
    play: '<circle cx="12" cy="12" r="10"/><path d="m10 8 6 4-6 4Z"/>',
    library: '<path d="m16 6 4 14"/><path d="M12 6v14"/><path d="M8 8v12"/><path d="M4 4v16"/>',
    users: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
    grid: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/>',
    radar: '<path d="M19.07 4.93A10 10 0 0 0 6.99 3.34"/><path d="M2.29 9.62A10 10 0 1 0 21.31 8.35"/><path d="M16.24 7.76A6 6 0 1 0 8.23 16.67"/><path d="M17.99 11.66A6 6 0 0 1 15.77 16.67"/><circle cx="12" cy="12" r="2"/><path d="m13.41 10.59 5.66-5.66"/>',
    route: '<circle cx="6" cy="19" r="3"/><path d="M9 19h8.5a3.5 3.5 0 0 0 0-7h-11a3.5 3.5 0 0 1 0-7H15"/><circle cx="18" cy="5" r="3"/>',
    target: '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>',
    alert: '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
    wrench: '<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>',
    scale: '<path d="m16 16 3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1Z"/><path d="m2 16 3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1Z"/><path d="M7 21h10"/><path d="M12 3v18"/><path d="M3 7h2c2 0 5-1 7-2 2 1 5 2 7 2h2"/>',
    file: '<path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/><path d="M10 9H8"/><path d="M16 13H8"/><path d="M16 17H8"/>',
    monitor: '<rect width="20" height="14" x="2" y="3" rx="2"/><path d="M8 21h8"/><path d="M12 17v4"/>',
    plug: '<path d="M12 22v-5"/><path d="M9 8V2"/><path d="M15 8V2"/><path d="M18 8v5a4 4 0 0 1-4 4h-4a4 4 0 0 1-4-4V8Z"/>',
    settings: '<path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/>',
    search: '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>',
    bell: '<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/>',
    help: '<circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><path d="M12 17h.01"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/>',
    moon: '<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/>',
    note: '<path d="M7.9 20A9 9 0 1 0 4 16.1L2 22Z"/><path d="M8 12h.01"/><path d="M12 12h.01"/><path d="M16 12h.01"/>',
    chevDown: '<path d="m6 9 6 6 6-6"/>',
    chevRight: '<path d="m9 18 6-6-6-6"/>',
    arrowRight: '<path d="M5 12h14"/><path d="m12 5 7 7-7 7"/>',
    up: '<path d="m6 14 6-6 6 6"/>',
    down: '<path d="m6 10 6 6 6-6"/>',
    calendar: '<rect width="18" height="18" x="3" y="4" rx="2"/><path d="M16 2v4"/><path d="M8 2v4"/><path d="M3 10h18"/>',
    filter: '<path d="M22 3H2l8 9.46V19l4 2v-8.54Z"/>',
    download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/><path d="M12 15V3"/>',
    share: '<path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8"/><path d="m16 6-4-4-4 4"/><path d="M12 2v13"/>',
    more: '<circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/><circle cx="5" cy="12" r="1"/>',
    info: '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>',
    shield: '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/>',
    eye: '<path d="M2.06 12.35a1 1 0 0 1 0-.7 10.75 10.75 0 0 1 19.88 0 1 1 0 0 1 0 .7 10.75 10.75 0 0 1-19.88 0"/><circle cx="12" cy="12" r="3"/>',
    xoct: '<path d="M7.86 2h8.28L22 7.86v8.28L16.14 22H7.86L2 16.14V7.86Z"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/>',
    minus: '<circle cx="12" cy="12" r="10"/><path d="M8 12h8"/>',
    check: '<path d="M20 6 9 17l-5-5"/>',
    checkCircle: '<circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/>',
    x: '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
    plus: '<path d="M5 12h14"/><path d="M12 5v14"/>',
    refresh: '<path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/>',
    clock: '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
    server: '<rect width="20" height="8" x="2" y="2" rx="2"/><rect width="20" height="8" x="2" y="14" rx="2"/><path d="M6 6h.01"/><path d="M6 18h.01"/>',
    crown: '<path d="M11.56 3.27a.5.5 0 0 1 .88 0l2.95 5.6a1 1 0 0 0 1.52.3l4.27-3.67a.5.5 0 0 1 .8.52l-2.83 10.25a1 1 0 0 1-.96.73H5.81a1 1 0 0 1-.96-.73L2.02 6.02a.5.5 0 0 1 .8-.52l4.27 3.67a1 1 0 0 0 1.52-.3z"/><path d="M5 21h14"/>',
    lock: '<rect width="18" height="11" x="3" y="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    badge: '<path d="M3.85 8.62a4 4 0 0 1 4.78-4.77 4 4 0 0 1 6.74 0 4 4 0 0 1 4.78 4.78 4 4 0 0 1 0 6.74 4 4 0 0 1-4.77 4.78 4 4 0 0 1-6.75 0 4 4 0 0 1-4.78-4.77 4 4 0 0 1 0-6.76Z"/><path d="m9 12 2 2 4-4"/>',
    zap: '<path d="M4 14a1 1 0 0 1-.78-1.63l9.9-10.2a.5.5 0 0 1 .86.46l-1.92 6.02A1 1 0 0 0 13 10h7a1 1 0 0 1 .78 1.63l-9.9 10.2a.5.5 0 0 1-.86-.46l1.92-6.02A1 1 0 0 0 11 14z"/>',
    sparkles: '<path d="M9.94 15.5A2 2 0 0 0 8.5 14.06l-6.14-1.58a.5.5 0 0 1 0-.96L8.5 9.94A2 2 0 0 0 9.94 8.5l1.58-6.14a.5.5 0 0 1 .96 0l1.58 6.14a2 2 0 0 0 1.44 1.44l6.14 1.58a.5.5 0 0 1 0 .96l-6.14 1.58a2 2 0 0 0-1.44 1.44l-1.58 6.14a.5.5 0 0 1-.96 0z"/>',
    layers: '<path d="M12.83 2.18a2 2 0 0 0-1.66 0L2.6 6.08a1 1 0 0 0 0 1.83l8.58 3.91a2 2 0 0 0 1.66 0l8.58-3.9a1 1 0 0 0 0-1.83Z"/><path d="m22 17.65-9.17 4.16a2 2 0 0 1-1.66 0L2 17.65"/><path d="m22 12.65-9.17 4.16a2 2 0 0 1-1.66 0L2 12.65"/>',
    table: '<path d="M12 3v18"/><rect width="18" height="18" x="3" y="3" rx="2"/><path d="M3 9h18"/><path d="M3 15h18"/>',
    chart: '<path d="M3 3v16a2 2 0 0 0 2 2h16"/><path d="m19 9-5 5-4-4-3 3"/>',
    ticket: '<path d="M2 9a3 3 0 0 1 0 6v2a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-2a3 3 0 0 1 0-6V7a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2Z"/><path d="M13 5v2"/><path d="M13 17v2"/><path d="M13 11v2"/>',
    external: '<path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>',
    copy: '<rect width="14" height="14" x="8" y="8" rx="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>',
    mail: '<rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/>',
    pause: '<rect x="14" y="4" width="4" height="16" rx="1"/><rect x="6" y="4" width="4" height="16" rx="1"/>',
    building: '<rect width="16" height="20" x="4" y="2" rx="2"/><path d="M9 22v-4h6v4"/><path d="M8 6h.01"/><path d="M16 6h.01"/><path d="M12 6h.01"/><path d="M12 10h.01"/><path d="M12 14h.01"/><path d="M16 10h.01"/><path d="M16 14h.01"/><path d="M8 10h.01"/><path d="M8 14h.01"/>',
    book: '<path d="M4 19.5v-15A2.5 2.5 0 0 1 6.5 2H20v20H6.5a2.5 2.5 0 0 1 0-5H20"/>',
    ghost: '<path d="M9 10h.01"/><path d="M15 10h.01"/><path d="M12 2a8 8 0 0 0-8 8v12l3-3 2.5 2.5L12 19l2.5 2.5L17 19l3 3V10a8 8 0 0 0-8-8z"/>',
    upload: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m17 8-5-5-5 5"/><path d="M12 3v12"/>',
    power: '<path d="M12 2v10"/><path d="M18.4 6.6a9 9 0 1 1-12.77.04"/>',
    ban: '<circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/>',
    terminal: '<path d="m4 17 6-6-6-6"/><path d="M12 19h8"/>',
    list: '<path d="M8 6h13"/><path d="M8 12h13"/><path d="M8 18h13"/><path d="M3 6h.01"/><path d="M3 12h.01"/><path d="M3 18h.01"/>',
    flag: '<path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><path d="M4 22v-7"/>',
    git: '<circle cx="18" cy="18" r="3"/><circle cx="6" cy="6" r="3"/><path d="M13 6h3a2 2 0 0 1 2 2v7"/><path d="M6 9v12"/>',
    sliders: '<path d="M21 4h-7"/><path d="M10 4H3"/><path d="M21 12h-9"/><path d="M8 12H3"/><path d="M21 20h-5"/><path d="M12 20H3"/><path d="M14 2v4"/><path d="M8 10v4"/><path d="M16 18v4"/>',
    globe: '<circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/>',
    cloud: '<path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z"/>',
    box: '<path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z"/><path d="m3.3 7 8.7 5 8.7-5"/><path d="M12 22V12"/>',
    database: '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14a9 3 0 0 0 18 0V5"/><path d="M3 12a9 3 0 0 0 18 0"/>',
    key: '<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/>',
    bug: '<path d="m8 2 1.88 1.88"/><path d="M14.12 3.88 16 2"/><path d="M9 7.13v-1a3 3 0 1 1 6 0v1"/><path d="M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v3c0 3.3-2.7 6-6 6"/><path d="M12 20v-9"/><path d="M6 13H2"/><path d="M22 13h-4"/>',
    network: '<rect x="16" y="16" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="9" y="2" width="6" height="6" rx="1"/><path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3"/><path d="M12 12V8"/>',
    user: '<circle cx="12" cy="8" r="5"/><path d="M20 21a8 8 0 0 0-16 0"/>',
    logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 17 5-5-5-5"/><path d="M21 12H9"/>',
    link: '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
    star: '<path d="M11.52 2.3a.53.53 0 0 1 .96 0l2.31 4.68a2.12 2.12 0 0 0 1.6 1.16l5.16.76a.53.53 0 0 1 .3.9l-3.74 3.64a2.12 2.12 0 0 0-.61 1.88l.88 5.14a.53.53 0 0 1-.77.56l-4.62-2.43a2.12 2.12 0 0 0-1.97 0L6.4 21.01a.53.53 0 0 1-.77-.56l.88-5.13a2.12 2.12 0 0 0-.61-1.88L2.16 9.8a.53.53 0 0 1 .29-.9l5.17-.76a2.12 2.12 0 0 0 1.6-1.16z"/>',
    activity: '<path d="M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2"/>',
    swords: '<path d="M14.5 17.5 3 6V3h3l11.5 11.5"/><path d="m13 19 6-6"/><path d="m16 16 4 4"/><path d="m19 21 2-2"/><path d="M14.5 6.5 18 3h3v3l-3.5 3.5"/><path d="m5 14 4 4"/><path d="m7 17-3 3"/><path d="m3 19 2 2"/>',
    inbox: '<path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>',
    pin: '<path d="M20 10c0 4.99-5.54 10.19-7.4 11.8a1 1 0 0 1-1.2 0C9.54 20.19 4 14.99 4 10a8 8 0 0 1 16 0"/><circle cx="12" cy="10" r="3"/>',
    dot: '<circle cx="12" cy="12" r="3"/>'
  };
  function icon(name, cls) {
    var el = document.createElementNS(NS, 'svg');
    el.setAttribute('viewBox', '0 0 24 24');
    el.setAttribute('class', 'ico' + (cls ? ' ' + cls : ''));
    el.setAttribute('aria-hidden', 'true');
    el.innerHTML = ICONS[name] || ICONS.dot; // static, trusted markup only
    return el;
  }
  function hydrateIcons(root) {
    $$('[data-icon]', root).forEach(function (ph) {
      var svg = icon(ph.getAttribute('data-icon'), ph.getAttribute('class') || '');
      ph.replaceWith(svg);
    });
  }

  /* -------------------------------------------------------------- Theme --- */
  var THEME_KEY = 'aud-theme';
  function theme() { return document.documentElement.getAttribute('data-theme') || 'dark'; }
  function setTheme(t) {
    document.documentElement.setAttribute('data-theme', t);
    try { localStorage.setItem(THEME_KEY, t); } catch (e) { /* storage may be blocked */ }
    $$('img[data-logo-dark]').forEach(function (img) {
      img.src = t === 'dark' ? img.getAttribute('data-logo-dark') : img.getAttribute('data-logo-light');
    });
    var b = $('#theme-btn');
    if (b) { b.replaceChildren(icon(t === 'dark' ? 'sun' : 'moon')); b.setAttribute('aria-label', t === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'); }
  }

  /* ------------------------------------------------------------ Tooltip --- */
  var tt = null;
  function tipEl() { if (!tt) { tt = h('div', { class: 'tt', role: 'tooltip' }); document.body.appendChild(tt); } return tt; }
  function tipShow(x, y, content) {
    var el = tipEl();
    el.replaceChildren(content);
    el.classList.add('on');
    var r = el.getBoundingClientRect();
    var left = x + 14, top = y + 14;
    if (left + r.width > window.innerWidth - 8) left = x - r.width - 14;
    if (top + r.height > window.innerHeight - 8) top = y - r.height - 14;
    el.style.left = Math.max(8, left) + 'px';
    el.style.top = Math.max(8, top) + 'px';
  }
  function tipHide() { if (tt) tt.classList.remove('on'); }
  function tipContent(header, rows, foot) {
    var box = h('div', null, header ? h('div', { class: 'tt-h' }, header) : null);
    (rows || []).forEach(function (r) {
      box.appendChild(h('div', { class: 'tt-row', style: r.strong === false ? 'opacity:.62' : '' },
        r.color ? h('span', { class: r.kind === 'sw' ? 'sw' : 'ln', style: 'background:' + r.color }) : null,
        h('span', { class: 'v' }, r.v),
        r.n ? h('span', { class: 'n' }, r.n) : null));
    });
    if (foot) box.appendChild(h('div', { class: 'tt-h', style: 'margin:6px 0 0' }, foot));
    return box;
  }
  function bindTip(el, build) {
    if (!el.hasAttribute('tabindex')) el.setAttribute('tabindex', '0');
    el.addEventListener('pointermove', function (e) { tipShow(e.clientX, e.clientY, build()); });
    el.addEventListener('pointerleave', tipHide);
    el.addEventListener('focus', function () { var r = el.getBoundingClientRect(); tipShow(r.left + r.width / 2, r.bottom, build()); });
    el.addEventListener('blur', tipHide);
  }

  /* -------------------------------------------------------------- Toast --- */
  function toast(msg) {
    var t = h('div', { class: 'tt on', role: 'status', style: 'left:50%;top:auto;bottom:24px;transform:translateX(-50%);pointer-events:none;font-size:12.5px;padding:10px 14px' }, msg);
    document.body.appendChild(t);
    setTimeout(function () { t.remove(); }, 2600);
  }

  /* ---------------------------------------------------------- Formatting --- */
  function dur(sec) { var m = Math.floor(sec / 60), s2 = Math.round(sec % 60); return m ? m + 'm ' + (s2 < 10 ? '0' : '') + s2 + 's' : s2 + 's'; }
  function signed(n, digits) { var v = digits ? Math.abs(n).toFixed(digits) : Math.abs(n); return (n > 0 ? '+' : n < 0 ? '−' : '±') + v; }

  /* --------------------------------------------------------- Primitives --- */
  var OUT = {
    P: { label: 'Prevented', cls: 'good', color: 'var(--prevented)', icon: 'shield' },
    D: { label: 'Detected only', cls: 'warning', color: 'var(--detected)', icon: 'eye' },
    M: { label: 'Missed', cls: 'critical', color: 'var(--missed)', icon: 'xoct' },
    U: { label: 'Not tested', cls: '', color: 'var(--untested)', icon: 'minus' }
  };
  function pill(cls, text, iconName) {
    return h('span', { class: 'pill ' + (cls || '') }, iconName ? icon(iconName) : h('span', { class: 'd' }), text);
  }
  function outcome(code) { var o = OUT[code] || OUT.U; return pill(o.cls, o.label, o.icon); }
  var SEV = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
  function sev(level) { return h('span', { class: 'sev ' + level }, h('i'), SEV[level] || level); }
  /* delta: n = change; goodWhen 'up'|'down'; unit text; vs text */
  function delta(n, goodWhen, unit, vs, textOverride) {
    var dir = n > 0 ? 'up' : n < 0 ? 'down' : 'flat';
    var cls = dir === 'flat' ? 'flat' : (dir === goodWhen ? 'good' : 'bad');
    var text = textOverride || (signed(n) + (unit || ''));
    return h('span', { class: 'delta ' + cls }, dir !== 'flat' ? icon(dir, 'sm') : null, text, vs ? h('span', { class: 'vs' }, vs) : null);
  }
  function meter(value, cls, extra) {
    var m = h('div', { class: 'meter ' + (cls || '') + (extra ? ' ' + extra : ''), role: 'meter', 'aria-valuenow': value, 'aria-valuemin': 0, 'aria-valuemax': 100 }, h('i', { style: 'width:' + value + '%' }));
    return m;
  }
  function band(v) { return v >= 80 ? 'good' : v >= 60 ? 'warning' : v >= 40 ? 'serious' : 'critical'; }
  function bandLabel(v) { return v >= 80 ? 'Strong' : v >= 60 ? 'Fair' : v >= 40 ? 'Poor' : 'Critical'; }
  function segbar(parts, cls) {
    var total = parts.reduce(function (a, p) { return a + p.v; }, 0) || 1;
    var bar = h('div', { class: 'segbar ' + (cls || ''), role: 'img', 'aria-label': parts.map(function (p) { return p.n + ' ' + p.v; }).join(', ') });
    parts.forEach(function (p) {
      if (!p.v) return;
      var seg = h('i', { style: 'flex:' + p.v + ' 1 0;background:' + p.color });
      bindTip(seg, function () { return tipContent(null, parts.map(function (q) { return { v: String(q.v), n: q.n + ' · ' + Math.round(q.v * 100 / total) + '%', color: q.color, kind: 'sw', strong: q === p ? true : false }; })); });
      bar.appendChild(seg);
    });
    return bar;
  }

  /* -------------------------------------------------------- Chart kit ---- */
  function observe(el, fn) {
    var w = el.clientWidth, raf = 0;
    if (!('ResizeObserver' in window)) { window.addEventListener('resize', fn); return; }
    new ResizeObserver(function () {
      if (Math.abs(el.clientWidth - w) < 2) return;
      w = el.clientWidth; cancelAnimationFrame(raf); raf = requestAnimationFrame(fn);
    }).observe(el);
  }

  /* Sparkline: de-emphasis line, current period in the accent. */
  function spark(values, o) {
    o = o || {};
    var w = o.w || 112, hh = o.h || 30, p = 4;
    var min = o.min != null ? o.min : Math.min.apply(null, values), max = o.max != null ? o.max : Math.max.apply(null, values);
    var span = (max - min) || 1;
    var X = function (i) { return p + i * (w - p * 2) / (values.length - 1); };
    var Y = function (v) { return p + (hh - p * 2) * (1 - (v - min) / span); };
    var d = values.map(function (v, i) { return (i ? 'L' : 'M') + X(i).toFixed(1) + ' ' + Y(v).toFixed(1); }).join('');
    var n = values.length - 1, col = o.color || 'var(--series-1)';
    return s('svg', { width: w, height: hh, viewBox: '0 0 ' + w + ' ' + hh, 'aria-hidden': 'true', style: 'overflow:visible;flex:none' },
      s('path', { d: d, fill: 'none', style: 'stroke:var(--viz-muted);stroke-width:1.5;stroke-linecap:round;stroke-linejoin:round' }),
      s('path', { d: 'M' + X(n - 1) + ' ' + Y(values[n - 1]) + 'L' + X(n) + ' ' + Y(values[n]), fill: 'none', style: 'stroke:' + col + ';stroke-width:2;stroke-linecap:round' }),
      s('circle', { cx: X(n), cy: Y(values[n]), r: 3.5, style: 'fill:' + col + ';stroke:var(--surface-1);stroke-width:2' }));
  }

  /* Radial gauge — the hero focal point. Full ring, rounded cap, band colour, big centre number. */
  function gauge(value, o) {
    o = o || {};
    var size = o.size || 196, w = o.w || 16, r = (size - w) / 2 - 2, cx = size / 2, cy = size / 2;
    var circ = 2 * Math.PI * r, v = Math.max(0, Math.min(100, value));
    var bandName = o.band || band(value), col = 'var(--' + bandName + ')';
    var dash = circ * v / 100;
    var svg = s('svg', { width: size, height: size, viewBox: '0 0 ' + size + ' ' + size, 'aria-hidden': 'true' },
      s('circle', { cx: cx, cy: cy, r: r, fill: 'none', stroke: 'var(--viz-track)', 'stroke-width': w }),
      s('circle', { cx: cx, cy: cy, r: r, fill: 'none', stroke: col, 'stroke-width': w, 'stroke-linecap': 'round', 'stroke-dasharray': dash.toFixed(1) + ' ' + (circ - dash).toFixed(1), transform: 'rotate(-90 ' + cx + ' ' + cy + ')' }));
    if (o.target != null) {
      var ang = (-90 + o.target * 3.6) * Math.PI / 180;
      var r1 = r - w / 2 - 2, r2 = r + w / 2 + 2;
      svg.appendChild(s('line', { x1: cx + r1 * Math.cos(ang), y1: cy + r1 * Math.sin(ang), x2: cx + r2 * Math.cos(ang), y2: cy + r2 * Math.sin(ang), stroke: 'var(--text-2)', 'stroke-width': 2, 'stroke-linecap': 'round' }));
    }
    var wrap = h('div', { class: 'gauge', style: '--g:' + size + 'px', role: 'img', 'aria-label': 'Score ' + value + ' of 100, ' + bandLabel(value) + (o.target != null ? ', target ' + o.target : '') }, svg,
      h('div', { class: 'g-center' },
        h('div', { class: 'g-num' }, String(value)),
        h('div', { class: 'g-den' }, 'out of 100'),
        o.pill !== false ? h('div', { class: 'g-lbl' }, pill(bandName + ' lg', bandLabel(value), bandName === 'good' ? 'checkCircle' : bandName === 'critical' ? 'xoct' : 'alert')) : null));
    return wrap;
  }

  /* Table twin for any chart. */
  function vizTable(head, rows) {
    var t = h('table', { class: 't' }, h('thead', null, h('tr', null, head.map(function (c, i) { return h('th', { class: i ? 'r' : '' }, c); }))),
      h('tbody', null, rows.map(function (r) { return h('tr', { style: 'cursor:default' }, r.map(function (c, i) { return h('td', { class: i ? 'r' : '' }, c); })); })));
    return h('div', { class: 'table-wrap', style: 'max-height:320px' }, t);
  }
  function vizToggle(btn, host) {
    btn.addEventListener('click', function () {
      var on = host.classList.toggle('show-table');
      btn.replaceChildren(icon(on ? 'chart' : 'table'), on ? 'Chart' : 'Table');
      btn.setAttribute('aria-pressed', on ? 'true' : 'false');
    });
  }

  /* Line chart: one y-axis, 2px lines, crosshair + one tooltip listing every series. */
  function lineChart(host, cfg) {
    host.classList.add('viz');
    var plot = h('div', { class: 'viz-plot' });
    var table = h('div', { class: 'viz-table' }, vizTable([cfg.xName || ''].concat(cfg.series.map(function (x) { return x.name; })),
      cfg.labels.map(function (lb, i) { return [lb].concat(cfg.series.map(function (x) { return (cfg.fmt || String)(x.values[i]); })); })));
    host.append(plot, table);
    var fmt = cfg.fmt || String;
    function draw() {
      var W = Math.max(300, plot.clientWidth || host.clientWidth || 600), H = cfg.height || 240;
      var m = { l: 36, r: cfg.endLabels === false ? 14 : 108, t: cfg.events ? 30 : 14, b: 26 };
      var iw = W - m.l - m.r, ih = H - m.t - m.b, n = cfg.labels.length;
      var y0 = cfg.yMin != null ? cfg.yMin : 0, y1 = cfg.yMax != null ? cfg.yMax : 100;
      var X = function (i) { return m.l + i * iw / (n - 1); };
      var Y = function (v) { return m.t + ih * (1 - (v - y0) / (y1 - y0)); };
      var svg = s('svg', { width: W, height: H, role: 'img', 'aria-label': cfg.aria || '' });
      (cfg.yTicks || [0, 25, 50, 75, 100]).forEach(function (t) {
        svg.appendChild(s('line', { x1: m.l, x2: m.l + iw, y1: Y(t), y2: Y(t), 'shape-rendering': 'crispEdges', style: 'stroke:' + (t === y0 ? 'var(--viz-axis)' : 'var(--viz-grid)') + ';stroke-width:1' }));
        svg.appendChild(s('text', { x: m.l - 8, y: Y(t) + 3.5, 'text-anchor': 'end', class: 'tick-label' }, (cfg.yFmt || String)(t)));
      });
      var every = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(iw / 70))));
      cfg.labels.forEach(function (lb, i) {
        if (i % every && i !== n - 1) return;
        if (i !== n - 1 && n - 1 - i < every * 0.6) return;
        svg.appendChild(s('text', { x: X(i), y: H - 7, 'text-anchor': i === 0 ? 'start' : i === n - 1 ? 'end' : 'middle' }, lb));
      });
      if (cfg.target) {
        svg.appendChild(s('line', { x1: m.l, x2: m.l + iw, y1: Y(cfg.target.value), y2: Y(cfg.target.value), 'shape-rendering': 'crispEdges', style: 'stroke:var(--text-3);stroke-width:1;opacity:.55' }));
        svg.appendChild(s('text', { x: m.l + 6, y: Y(cfg.target.value) - 6 }, cfg.target.label));
      }
      (cfg.events || []).forEach(function (ev) {
        var x = X(ev.i);
        svg.appendChild(s('line', { x1: x, x2: x, y1: m.t - 14, y2: m.t + ih, 'shape-rendering': 'crispEdges', style: 'stroke:var(--border-strong);stroke-width:1' }));
        svg.appendChild(s('circle', { cx: x, cy: m.t - 14, r: 3, style: 'fill:var(--text-2)' }));
        svg.appendChild(s('text', { x: x + 7, y: m.t - 10, style: 'fill:var(--text-2)' }, ev.label));
      });
      cfg.series.forEach(function (se) {
        var d = se.values.map(function (v, i) { return (i ? 'L' : 'M') + X(i).toFixed(1) + ' ' + Y(v).toFixed(1); }).join('');
        if (cfg.area && cfg.series.length === 1) svg.appendChild(s('path', { d: d + 'L' + X(n - 1) + ' ' + Y(y0) + 'L' + X(0) + ' ' + Y(y0) + 'Z', style: 'fill:' + se.color + ';opacity:.10' }));
        svg.appendChild(s('path', { d: d, fill: 'none', style: 'stroke:' + se.color + ';stroke-width:2;stroke-linejoin:round;stroke-linecap:round' }));
        svg.appendChild(s('circle', { cx: X(n - 1), cy: Y(se.values[n - 1]), r: 4, style: 'fill:' + se.color + ';stroke:var(--surface-1);stroke-width:2' }));
      });
      if (cfg.endLabels !== false) {
        var labs = cfg.series.map(function (se) { return { se: se, y: Y(se.values[n - 1]) }; }).sort(function (a, b) { return a.y - b.y; });
        var clear = labs.every(function (l, i) { return !i || l.y - labs[i - 1].y >= 25; });
        if (clear) labs.forEach(function (l) {
          svg.appendChild(s('text', { x: X(n - 1) + 12, y: l.y + 1, class: 'end-label' }, fmt(l.se.values[n - 1])));
          svg.appendChild(s('text', { x: X(n - 1) + 12, y: l.y + 14, class: 'end-sub' }, l.se.short || l.se.name));
        });
      }
      var cross = s('line', { y1: m.t, y2: m.t + ih, 'pointer-events': 'none', style: 'stroke:var(--text-3);stroke-width:1;opacity:0' });
      var dots = cfg.series.map(function (se) { return s('circle', { r: 4, 'pointer-events': 'none', style: 'fill:' + se.color + ';stroke:var(--surface-1);stroke-width:2;opacity:0' }); });
      svg.appendChild(cross); dots.forEach(function (d) { svg.appendChild(d); });
      var hit = s('rect', { x: m.l - 6, y: m.t, width: iw + 12, height: ih, fill: 'transparent', tabindex: 0, 'aria-label': (cfg.aria || 'Chart') + '. Use arrow keys to read values.', style: 'cursor:crosshair;outline:none' });
      svg.appendChild(hit);
      var cur = n - 1;
      function showAt(i, cx, cy) {
        var x = X(i);
        cross.setAttribute('x1', x); cross.setAttribute('x2', x); cross.style.opacity = '.7';
        dots.forEach(function (d, k) { d.setAttribute('cx', x); d.setAttribute('cy', Y(cfg.series[k].values[i])); d.style.opacity = '1'; });
        tipShow(cx, cy, tipContent(cfg.labels[i], cfg.series.map(function (se) { return { v: fmt(se.values[i]), n: se.name, color: se.color, kind: 'ln' }; }), cfg.tipFoot ? cfg.tipFoot(i) : null));
      }
      function clearX() { cross.style.opacity = '0'; dots.forEach(function (d) { d.style.opacity = '0'; }); tipHide(); }
      hit.addEventListener('pointermove', function (e) {
        var r = svg.getBoundingClientRect();
        cur = Math.max(0, Math.min(n - 1, Math.round((e.clientX - r.left - m.l) / (iw / (n - 1)))));
        showAt(cur, e.clientX, e.clientY);
      });
      hit.addEventListener('pointerleave', clearX);
      hit.addEventListener('blur', clearX);
      hit.addEventListener('focus', function () { var r = svg.getBoundingClientRect(); showAt(cur, r.left + X(cur), r.top + m.t + 20); });
      hit.addEventListener('keydown', function (e) {
        if (e.key === 'ArrowLeft') cur = Math.max(0, cur - 1); else if (e.key === 'ArrowRight') cur = Math.min(n - 1, cur + 1); else return;
        e.preventDefault(); var r = svg.getBoundingClientRect(); showAt(cur, r.left + X(cur), r.top + m.t + 20);
      });
      plot.replaceChildren(svg);
    }
    draw(); observe(plot, draw);
  }

  /* 100% stacked horizontal bars (DOM): 14px bars, 2px surface gaps, square baseline, 4px data-end. */
  function stackBars(host, cfg) {
    host.classList.add('viz');
    var plot = h('div', { class: 'viz-plot sb-plot' });
    if (cfg.target) {
      plot.appendChild(h('div', { class: 'sb-row sb-axis' }, h('div'), h('div', { class: 'sb-track' }, h('span', { class: 'sb-target-lb', style: 'left:' + cfg.target.value + '%' }, cfg.target.label)), h('div', { class: 'sb-val xs muted', style: 'font-weight:500' }, cfg.valueHead || '')));
    }
    cfg.rows.forEach(function (row) {
      var bar = h('div', { class: 'sb-bar' });
      row.values.forEach(function (v, k) {
        if (!v) return;
        var seg = h('i', { style: 'flex:' + v + ' 1 0;background:' + cfg.keys[k].color, 'aria-label': row.label + ': ' + cfg.keys[k].name + ' ' + v + '%' });
        bindTip(seg, function () {
          return tipContent(row.label, cfg.keys.map(function (key, j) { return { v: row.values[j] + '%', n: key.name, color: key.color, kind: 'sw', strong: j === k }; }), row.foot);
        });
        bar.appendChild(seg);
      });
      var track = h('div', { class: 'sb-track' }, bar, cfg.target ? h('b', { class: 'sb-target', style: 'left:' + cfg.target.value + '%' }) : null);
      plot.appendChild(h('div', { class: 'sb-row' + (row.flag ? ' flagged' : '') },
        h('div', { class: 'sb-label', title: row.label }, row.label),
        track,
        h('div', { class: 'sb-val' }, cfg.valueCol ? cfg.valueCol(row) : '')));
    });
    var table = h('div', { class: 'viz-table' }, vizTable([cfg.rowName || ''].concat(cfg.keys.map(function (k) { return k.name; })),
      cfg.rows.map(function (r) { return [r.label].concat(r.values.map(function (v) { return v + '%'; })); })));
    host.append(plot, table);
  }

  /* ATT&CK heat strip — one column per tactic, one cell per technique (worst outcome wins). */
  function heatStrip(host, tactics, onPick) {
    host.classList.add('hm');
    tactics.forEach(function (t) {
      var col = h('div', { class: 'hm-col' }, h('div', { class: 'hm-head', title: t.name }, t.short));
      t.tech.forEach(function (tc) {
        var o = OUT[tc[2]];
        var cell = h('div', { class: 'hm-cell o-' + tc[2].toLowerCase(), role: 'img', 'aria-label': tc[0] + ' ' + tc[1] + ': ' + o.label });
        bindTip(cell, function () { return tipContent(tc[0] + ' · ' + t.name, [{ v: o.label, n: tc[1], color: o.color, kind: 'sw' }], tc[3] || null); });
        if (onPick) cell.addEventListener('click', function () { onPick(t, tc); });
        col.appendChild(cell);
      });
      host.appendChild(col);
    });
  }

  /* ---------------------------------------------------------- App shell --- */
  var NAV = [
    { group: 'Overview', items: [
      { id: 'dashboard', label: 'Security posture', icon: 'gauge', href: '02-dashboard.html' }] },
    { group: 'Validate', items: [
      { id: 'assessments', label: 'Assessments', icon: 'play', href: '03-assessments.html', meta: '1 live', metaCls: 'live' },
      { id: 'library', label: 'Threat library', icon: 'library', href: '10-threat-library.html' },
      { id: 'purple', label: 'Purple-team exercises', icon: 'swords', href: '11-purple-team.html' }] },
    { group: 'Analyze', items: [
      { id: 'coverage', label: 'ATT&CK coverage', icon: 'grid', href: '05-coverage.html' },
      { id: 'detection', label: 'Detection validation', icon: 'radar', href: '12-detection.html' },
      { id: 'paths', label: 'Attack paths', icon: 'route', href: '13-attack-paths.html' },
      { id: 'intel', label: 'Threat intelligence', icon: 'target', href: '14-threat-intel.html' }] },
    { group: 'Remediate', items: [
      { id: 'findings', label: 'Findings', icon: 'alert', href: '04-findings.html', meta: '12', metaCls: 'alert' },
      { id: 'plans', label: 'Remediation plans', icon: 'wrench', href: '15-remediation.html' }] },
    { group: 'Govern', items: [
      { id: 'compliance', label: 'Compliance', icon: 'scale', href: '06-compliance.html' },
      { id: 'reports', label: 'Reports', icon: 'file', href: '08-reports.html' }] },
    { group: 'Manage', items: [
      { id: 'endpoints', label: 'Endpoints', icon: 'monitor', href: '07-endpoints.html', meta: '214' },
      { id: 'integrations', label: 'Integrations', icon: 'plug', href: '16-integrations.html' },
      { id: 'settings', label: 'Settings', icon: 'settings', href: '17-settings.html' }] }
  ];
  var TITLES = {}; NAV.forEach(function (g) { g.items.forEach(function (it) { TITLES[it.id] = it.label; }); });

  function renderSidebar(active) {
    var sb = $('#sidebar'); if (!sb) return;
    var D = window.AUD || {};
    var org = D.org || { name: 'Contoso Bank', short: 'CB', env: 'Production · 3 sites' };
    sb.replaceChildren(
      h('a', { class: 'brand', href: 'index.html', 'aria-label': 'Audspect home' },
        h('img', { src: 'assets/img/logo_ondark.png', alt: '' }),
        h('span', { class: 'wordmark' }, 'Aud', h('b', null, 'spect'))),
      h('div', { class: 'org-switch', id: 'org-btn', role: 'button', tabindex: 0, title: 'Switch organisation / site', 'aria-haspopup': 'menu' },
        h('span', { class: 'org-badge' }, org.short),
        h('span', { class: 'org-text', style: 'min-width:0;flex:1' }, h('div', { class: 'org-name truncate' }, org.name), h('div', { class: 'org-env' }, org.env)),
        h('span', { class: 'org-text' }, icon('chevDown', 'sm'))),
      h('div', { class: 'nav-groups' }, NAV.map(function (g) {
        return h('nav', { class: 'nav-group', 'aria-label': g.group },
          h('div', { class: 'nav-label' }, g.group),
          g.items.map(function (it) {
            var a = h('a', { class: 'nav-item' + (it.id === active ? ' active' : ''), href: it.href, title: it.label, 'aria-current': it.id === active ? 'page' : null },
              icon(it.icon), h('span', null, it.label), it.meta ? h('span', { class: 'nav-meta ' + (it.metaCls || '') }, it.meta) : null);
            if (it.href === '#') a.addEventListener('click', function (e) { e.preventDefault(); toast('"' + it.label + '" is not mocked in this proposal — see the IA map on the index page.'); });
            return a;
          }));
      })),
      h('div', { class: 'sidebar-foot' },
        h('div', { class: 'license-chip' },
          h('div', { class: 'row', style: 'color:var(--text-1);font-weight:600' }, icon('lock', 'sm'), 'On-prem · air-gapped'),
          h('div', { class: 'mt-1' }, 'Licence valid to 31 Mar 2027'),
          h('div', { class: 'mt-2' }, meter(86, '', 'sm')),
          h('div', { class: 'mt-1 xs muted' }, '214 of 250 endpoint seats · v3.0'))));
  }

  function renderTopbar(active, opts) {
    var tb = $('#topbar'); if (!tb) return;
    var D = window.AUD || {};
    var notesBtn = h('button', { class: 'btn btn-sm', id: 'notes-btn', type: 'button', title: 'Toggle design notes (N)', style: 'border-color:var(--note);color:var(--text-1)' }, icon('note'), 'Design notes');
    var themeBtn = h('button', { class: 'icon-btn', id: 'theme-btn', type: 'button', title: 'Toggle theme (T)' });
    var menuBtn = h('button', { class: 'icon-btn menu-btn', type: 'button', 'aria-label': 'Open navigation', 'aria-expanded': 'false' }, icon('list'));
    menuBtn.addEventListener('click', function () {
      var open = document.body.classList.toggle('nav-open');
      menuBtn.setAttribute('aria-expanded', String(open));
    });
    tb.replaceChildren(
      menuBtn,
      h('div', { class: 'crumbs' }, h('span', null, (D.org && D.org.name) || 'Contoso Bank'), icon('chevRight', 'sm'), h('b', null, (opts && opts.title) || TITLES[active] || '')),
      h('div', { class: 'search', id: 'cmdk-open', role: 'button', tabindex: 0, title: 'Command palette (Ctrl K)' }, icon('search'), h('span', { class: 'truncate' }, 'Search endpoints, techniques, findings, reports…'), h('span', { class: 'kbd' }, 'Ctrl K')),
      h('div', { class: 'spacer' }),
      h('span', { class: 'freshness', title: 'Orchestrator, database and agent channel healthy' }, h('span', { class: 'live-dot' }), h('span', { class: 'hide-sm' }, 'All services healthy')),
      notesBtn, themeBtn,
      h('button', { class: 'icon-btn', id: 'bell-btn', type: 'button', 'aria-label': 'Notifications (3 new)', 'aria-haspopup': 'menu' }, icon('bell'), h('span', { class: 'dot' })),
      h('a', { class: 'icon-btn', href: '#', 'aria-label': 'Help & docs' }, icon('help')),
      h('button', { class: 'avatar', id: 'user-btn', type: 'button', title: 'Signed in as CISO (Admin)', 'aria-haspopup': 'menu', style: 'border:0;cursor:pointer' }, 'CI'));
    themeBtn.addEventListener('click', function () { setTheme(theme() === 'dark' ? 'light' : 'dark'); });
    notesBtn.addEventListener('click', toggleNotes);
  }

  /* --------------------------------------------- Design-review notes ---- */
  function toggleNotes(force) {
    var on = typeof force === 'boolean' ? force : !document.body.classList.contains('notes-on');
    document.body.classList.toggle('notes-on', on);
    var b = $('#notes-btn'); if (b) b.classList.toggle('btn-primary', on);
  }
  function focusNote(n) {
    toggleNotes(true);
    $$('[data-note]').forEach(function (el) { el.classList.toggle('note-focus', el.getAttribute('data-note') === String(n)); });
    var target = $('[data-note="' + n + '"]');
    if (target) target.scrollIntoView({ behavior: 'smooth', block: 'center' });
    var item = $('#note-' + n); if (item) item.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
  function notes(list) {
    var body = h('div', { class: 'notes-b' });
    list.forEach(function (n) {
      var target = $(n.sel);
      if (target) {
        target.setAttribute('data-note', n.n);
        if (getComputedStyle(target).position === 'static') target.style.position = 'relative';
        target.appendChild(h('button', { class: 'note-pin', type: 'button', 'aria-label': 'Design note ' + n.n, onclick: function (e) { e.stopPropagation(); focusNote(n.n); } }, String(n.n)));
      }
      var meta = h('dl', { class: 'meta' });
      [['Why', n.why], ['Data', n.data], ['Today', n.today], ['Build', n.build]].forEach(function (p) {
        if (!p[1]) return;
        meta.append(h('dt', null, p[0]), h('dd', null, p[1]));
      });
      body.appendChild(h('div', { class: 'note', id: 'note-' + n.n, onclick: function () { focusNote(n.n); } },
        h('div', { class: 'note-t' }, h('span', { class: 'n' }, String(n.n)), h('span', null, n.title)),
        n.body ? h('p', null, n.body) : null, meta));
    });
    var panel = h('aside', { class: 'notes-panel', 'aria-label': 'Design notes' },
      h('div', { class: 'notes-h' }, icon('note'), h('b', null, 'Design notes'), h('span', { class: 'muted small' }, list.length + ' annotations'),
        h('span', { class: 'spacer' }), h('button', { class: 'icon-btn', type: 'button', 'aria-label': 'Close notes', onclick: function () { toggleNotes(false); } }, icon('x'))),
      body);
    document.body.appendChild(panel);
  }

  /* ------------------------------------------------------ Page builders --- */
  function banner(extra) {
    return h('div', { class: 'review-banner' }, icon('note'),
      h('span', null, h('b', null, 'Design proposal v0.2'), ' · sample data. Press ', h('span', { class: 'kbd' }, 'N'), ' for design notes, ', h('span', { class: 'kbd' }, 'T'), ' to switch theme.' + (extra ? ' ' + extra : '')),
      h('span', { class: 'spacer' }), h('a', { href: 'index.html' }, 'Proposal index'));
  }
  function pageHeader(o) {
    return h('div', { class: 'page-header' }, h('div', null, h('h1', { class: 'page-title' }, o.title), o.sub ? h('p', { class: 'page-sub' }, o.sub) : null),
      o.actions ? h('div', { class: 'page-actions' }, o.actions) : null);
  }
  function btn(label, o) {
    o = o || {};
    var cls = 'btn' + (o.primary ? ' btn-primary' : '') + (o.ghost ? ' btn-ghost' : '') + (o.sm ? ' btn-sm' : '') + (o.danger ? ' btn-danger' : '') + (o.cls ? ' ' + o.cls : '');
    return h(o.href ? 'a' : 'button', { class: cls, href: o.href || null, type: o.href ? null : 'button', disabled: o.disabled || null, title: o.title || null }, o.icon ? icon(o.icon) : null, label);
  }
  function chip(k, v, o) {
    o = o || {};
    return h('button', { class: 'chip' + (o.on ? ' on' : ''), type: 'button' }, o.icon ? icon(o.icon) : null, k ? h('span', { class: 'k' }, k) : null, v, icon(o.on ? 'x' : 'chevDown', 'sm'));
  }
  function searchBox(ph) { return h('span', { class: 'input-icon' }, icon('search'), h('input', { class: 'input search-input', type: 'search', placeholder: ph, 'aria-label': ph })); }
  function tabsNav(list, active) {
    return h('nav', { class: 'tabs', role: 'tablist' }, list.map(function (t) {
      return h('a', { class: 'tab' + (t[0] === active ? ' active' : ''), href: '#' + t[0], 'data-tab': t[0], role: 'tab' }, t[1], t[2] != null ? h('span', { class: 'count' }, String(t[2])) : null);
    }));
  }
  function bindTabs(nav, onChange) {
    var els = $$('[data-tab]', nav);
    function activate(id) {
      els.forEach(function (t) { var on = t.getAttribute('data-tab') === id; t.classList.toggle('active', on); t.setAttribute('aria-selected', on ? 'true' : 'false'); });
      onChange(id);
    }
    els.forEach(function (t) {
      t.addEventListener('click', function (e) {
        e.preventDefault(); var id = t.getAttribute('data-tab');
        try { history.replaceState(null, '', '#' + id); } catch (err) { /* file:// may refuse */ }
        activate(id);
      });
    });
    var start = (location.hash || '').replace('#', '');
    var has = els.some(function (t) { return t.getAttribute('data-tab') === start; });
    var cur = els.filter(function (t) { return t.classList.contains('active'); })[0] || els[0];
    activate(has ? start : cur.getAttribute('data-tab'));
    return activate;
  }
  function card(o) {
    return h('section', { class: 'card ' + (o.cls || ''), id: o.id || null },
      (o.title || o.actions) ? h('div', { class: 'card-h' }, h('div', { class: 'titles' }, h('h2', { class: 'card-title' }, o.title), o.sub ? h('div', { class: 'card-sub' }, o.sub) : null), o.actions ? h('div', { class: 'card-actions' }, o.actions) : null) : null,
      o.flush ? o.body : h('div', { class: 'card-b' }, o.body),
      o.foot ? h('div', { class: 'card-f' }, o.foot) : null);
  }
  function kpi(o) {
    return h(o.href ? 'a' : 'div', { class: 'card kpi' + (o.href ? ' link-card' : ''), href: o.href || null, title: o.title || null },
      h('div', { class: 'kpi-label' }, o.label),
      h('div', { class: 'kpi-value' }, String(o.value), o.unit ? h('span', { class: 'unit' }, o.unit) : null),
      o.extra || null,
      o.ctx ? h('div', { class: 'kpi-ctx' }, o.ctx) : null,
      (o.delta || o.spark) ? h('div', { class: 'kpi-foot' }, o.delta ? delta(o.delta[0], o.delta[1], o.delta[2] || '', o.delta[3] || null, o.delta[4]) : h('span'), o.spark ? spark(o.spark, { w: 72, h: 28 }) : null) : null);
  }
  function table(cols, rows, o) {
    o = o || {};
    var tb = h('tbody');
    rows.forEach(function (r, i) {
      var key = o.key ? o.key(r) : String(i);
      var tr = h('tr', { 'data-key': key, tabindex: o.onRow ? 0 : null, class: o.selected != null && key === o.selected ? 'selected' : null, style: o.onRow ? null : 'cursor:default' },
        cols.map(function (c) { return h('td', { class: c.cls || null }, c.render ? c.render(r) : r[c.k]); }));
      if (o.onRow) {
        tr.addEventListener('click', function (e) { if (e.target.closest('a,button,.checkbox')) return; o.onRow(r, tr); });
        tr.addEventListener('keydown', function (e) { if (e.key === 'Enter') o.onRow(r, tr); });
      }
      tb.appendChild(tr);
    });
    return h('table', { class: 't' + (o.cls ? ' ' + o.cls : '') }, h('thead', null, h('tr', null, cols.map(function (c) { return h('th', { class: c.hcls || c.cls || null }, c.h); }))), tb);
  }
  function selectRow(el, key) { $$('tbody tr', el).forEach(function (tr) { tr.classList.toggle('selected', tr.getAttribute('data-key') === String(key)); }); }
  function kv(pairs) { var dl = h('dl', { class: 'kv' }); pairs.forEach(function (p) { if (p) dl.append(h('dt', null, p[0]), h('dd', null, p[1])); }); return dl; }
  function listRow(o) {
    return h(o.href ? 'a' : 'div', { class: 'list-row' + (o.href ? ' link-card' : ''), href: o.href || null },
      o.icon ? (typeof o.icon === 'string' ? icon(o.icon, 'tx-muted') : o.icon) : null,
      h('div', { class: 'grow' }, h('div', { class: 'list-title' }, o.title), o.sub ? h('div', { class: 'list-sub' }, o.sub) : null),
      o.right || null);
  }
  function metric(v, label) {
    if (v == null) return h('div', { class: 'small muted' }, label || '—');
    return h('div', { class: 'metric' }, meter(v, band(v), 'sm'), h('span', null, v + '%'));
  }
  function statusPill(v) { var b = band(v); return pill(b, bandLabel(v), b === 'good' ? 'checkCircle' : b === 'critical' ? 'xoct' : 'alert'); }

  /* ------------------------------------------------- Popovers & palette --- */
  var openPop = null;
  function closePop() { if (openPop) { openPop.remove(); openPop = null; } }
  function popover(anchor, content, o) {
    closePop();
    var r = anchor.getBoundingClientRect();
    var p = h('div', { class: 'pop', role: 'menu' }, content);
    document.body.appendChild(p);
    var w = p.offsetWidth, left = o && o.alignLeft ? r.left : r.right - w;
    p.style.left = Math.max(8, Math.min(window.innerWidth - w - 8, left)) + 'px';
    p.style.top = (r.bottom + 6) + 'px';
    openPop = p;
  }
  document.addEventListener('click', function (e) { if (openPop && !openPop.contains(e.target) && !e.target.closest('#bell-btn,#user-btn,#org-btn')) closePop(); });
  var NOTIFS = [
    ['critical', 'xoct', 'New critical finding', 'Shadow copies deleted before encryption on 9 servers', '12 min ago', '04-findings.html#F-1035'],
    ['accent', 'zap', 'Assessment running', 'Ransomware readiness on core banking is 64% complete', '18 min ago', '02-dashboard.html#ops'],
    ['good', 'checkCircle', 'Re-test passed', 'Token impersonation fixed on 11 endpoints (F-0994)', '2 h ago', '04-findings.html'],
    ['warning', 'alert', 'Threat-intel feed is stale', 'MISP last synced 3 days ago; import the next offline bundle', '3 h ago', '16-integrations.html'],
    ['', 'file', 'Report delivered', 'Board scorecard · September emailed to CISO and CRO', '1 Oct', '08-reports.html']
  ];
  function notifPanel() {
    return h('div', { class: 'pop-wide' },
      h('div', { class: 'pop-h' }, h('b', null, 'Notifications'), pill('accent', '3 new'), h('span', { class: 'spacer' }), h('a', { href: '#', class: 'small' }, 'Mark all read')),
      NOTIFS.map(function (n, i) {
        return h('a', { class: 'pop-item' + (i < 3 ? ' unread' : ''), href: n[5] }, h('span', { class: 'pill ' + n[0] + ' pop-ic' }, icon(n[1])),
          h('span', { class: 'grow' }, h('b', null, n[2]), h('span', null, n[3])), h('small', null, n[4]));
      }),
      h('div', { class: 'pop-f' }, h('a', { href: '17-settings.html#notifications', class: 'small' }, 'Notification settings')));
  }
  function userPanel() {
    return h('div', null,
      h('div', { class: 'pop-h col' }, h('b', null, 'Chief Information Security Officer'), h('span', { class: 'small muted' }, 'ciso@contoso.example · Admin')),
      [['user', 'Profile', '17-settings.html#users'], ['sliders', 'Appearance', '17-settings.html#appearance'], ['note', 'Keyboard shortcuts', '#'], ['logout', 'Sign out', '00-login.html']].map(function (x) {
        return h('a', { class: 'pop-item compact', href: x[2] }, icon(x[0]), h('span', { class: 'grow' }, x[1]));
      }));
  }
  function orgPanel() {
    return h('div', null,
      h('div', { class: 'pop-h' }, h('b', null, 'Organisation')),
      [['CB', 'Contoso Bank', 'Production · 3 sites', true], ['CB', 'Contoso Bank', 'UAT environment', false], ['CN', 'Contoso Insurance', 'Production · 1 site', false]].map(function (o) {
        return h('a', { class: 'pop-item compact', href: '#' }, h('span', { class: 'org-badge' }, o[0]), h('span', { class: 'grow' }, h('b', null, o[1]), h('span', null, o[2])), o[3] ? icon('check', 'tx-accent') : null);
      }),
      h('div', { class: 'pop-h' }, h('b', null, 'Site')),
      ['All sites', 'Mumbai HQ', 'DC Navi Mumbai', 'Branches · Pune, Bengaluru'].map(function (s, i) {
        return h('a', { class: 'pop-item compact', href: '#' }, icon('pin'), h('span', { class: 'grow' }, s), i === 0 ? icon('check', 'tx-accent') : null);
      }));
  }
  function openPalette() {
    closePop();
    if ($('.cmdk-overlay')) return;
    var items = [];
    NAV.forEach(function (g) { g.items.forEach(function (it) { items.push({ g: 'Pages', ic: it.icon, t: it.label, s: g.group, href: it.href }); }); });
    [['play', 'Run an assessment', '03-assessments.html#new'], ['file', 'Generate board scorecard', '08-reports.html'], ['monitor', 'Deploy agents', '07-endpoints.html#deploy'], ['badge', 'Verify a report', '08-reports.html#verify']]
      .forEach(function (a) { items.push({ g: 'Actions', ic: a[0], t: a[1], href: a[2] }); });
    [['monitor', 'FIN-WS-023', 'Endpoint · Mumbai HQ · Finance', '07-endpoints.html'], ['grid', 'T1003 · OS Credential Dumping', 'Technique · missed', '05-coverage.html#T1003'],
      ['alert', 'F-1042 · LSASS memory dumping not prevented', 'Finding · critical', '04-findings.html#F-1042'], ['ghost', 'Lazarus Group', 'Threat group · partly protected', '14-threat-intel.html'],
      ['scale', 'RBI Cyber Security Framework', 'Compliance · 81%', '06-compliance.html'], ['mail', 'Email security', 'Module · 81 / 100', '09-module.html?m=email']]
      .forEach(function (e) { items.push({ g: 'Results', ic: e[0], t: e[1], s: e[2], href: e[3] }); });
    var input = h('input', { class: 'cmdk-input', type: 'text', placeholder: 'Search pages, endpoints, techniques, findings…', 'aria-label': 'Search' });
    var list = h('div', { class: 'cmdk-list', role: 'listbox' });
    var sel = 0, shown = [];
    function mark() { $$('.cmdk-item', list).forEach(function (el, i) { el.classList.toggle('on', i === sel); if (i === sel) el.scrollIntoView({ block: 'nearest' }); }); }
    function render() {
      var q = input.value.trim().toLowerCase();
      shown = items.filter(function (it) { return !q || (it.t + ' ' + (it.s || '')).toLowerCase().indexOf(q) >= 0; });
      list.replaceChildren();
      var lastG = null;
      shown.forEach(function (it, i) {
        if (it.g !== lastG) { list.appendChild(h('div', { class: 'cmdk-g' }, it.g)); lastG = it.g; }
        var row = h('a', { class: 'cmdk-item' + (i === sel ? ' on' : ''), href: it.href, role: 'option' }, icon(it.ic), h('span', { class: 'grow truncate' }, it.t), it.s ? h('small', null, it.s) : null);
        row.addEventListener('mousemove', function () { if (sel !== i) { sel = i; mark(); } });
        list.appendChild(row);
      });
      if (!shown.length) list.appendChild(h('div', { class: 'empty' }, icon('search'), h('span', { class: 'small' }, 'No matches. Try a host name, technique ID or finding ID.')));
    }
    var overlay = h('div', { class: 'cmdk-overlay', role: 'dialog', 'aria-modal': 'true', 'aria-label': 'Command palette' },
      h('div', { class: 'cmdk' }, h('div', { class: 'cmdk-top' }, icon('search'), input, h('span', { class: 'kbd' }, 'Esc')), list,
        h('div', { class: 'cmdk-f' }, h('span', null, h('span', { class: 'kbd' }, '↑'), ' ', h('span', { class: 'kbd' }, '↓'), ' move'), h('span', null, h('span', { class: 'kbd' }, 'Enter'), ' open'), h('span', null, 'Searches this installation only'))));
    function close() { overlay.remove(); document.removeEventListener('keydown', keys, true); }
    function keys(e) {
      if (e.key === 'Escape') { e.preventDefault(); close(); }
      else if (e.key === 'ArrowDown') { e.preventDefault(); sel = Math.min(shown.length - 1, sel + 1); mark(); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); sel = Math.max(0, sel - 1); mark(); }
      else if (e.key === 'Enter' && shown[sel]) { e.preventDefault(); location.href = shown[sel].href; }
    }
    overlay.addEventListener('click', function (e) { if (e.target === overlay) close(); });
    input.addEventListener('input', function () { sel = 0; render(); });
    document.addEventListener('keydown', keys, true);
    document.body.appendChild(overlay);
    render(); input.focus();
  }

  /* --------------------------------------------------------------- Boot --- */
  function boot(active, opts) {
    renderSidebar(active);
    renderTopbar(active, opts);
    setTheme(theme());
    hydrateIcons(document);
    document.addEventListener('keydown', function (e) {
      if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) { e.preventDefault(); openPalette(); return; }
      var tag = (e.target && e.target.tagName) || '';
      if (/INPUT|TEXTAREA|SELECT/.test(tag) || e.ctrlKey || e.metaKey || e.altKey) return;
      if (e.key === 'n' || e.key === 'N') toggleNotes();
      if (e.key === 't' || e.key === 'T') setTheme(theme() === 'dark' ? 'light' : 'dark');
      if (e.key === 'Escape') { toggleNotes(false); closePop(); document.body.classList.remove('nav-open'); }
    });
    var cm = $('#cmdk-open'); if (cm) { cm.addEventListener('click', openPalette); cm.addEventListener('keydown', function (e) { if (e.key === 'Enter') openPalette(); }); }
    var bb = $('#bell-btn'); if (bb) bb.addEventListener('click', function () { if (openPop) { closePop(); return; } popover(bb, notifPanel()); });
    var ub = $('#user-btn'); if (ub) ub.addEventListener('click', function () { if (openPop) { closePop(); return; } popover(ub, userPanel()); });
    var ob = $('#org-btn'); if (ob) ob.addEventListener('click', function () { if (openPop) { closePop(); return; } popover(ob, orgPanel(), { alignLeft: true }); });
    $$('a[href="#"]').forEach(function (a) {
      if (a.closest('.sidebar') || a.hasAttribute('data-tab')) return;
      a.addEventListener('click', function (e) { e.preventDefault(); toast('Not mocked in this proposal.'); });
    });
    if ((opts && opts.notesOpen) || /[?&]notes=1\b/.test(location.search)) setTimeout(function () { toggleNotes(true); }, 0);
  }

  window.UI = {
    h: h, s: s, $: $, $$: $$, icon: icon, hydrateIcons: hydrateIcons, boot: boot, notes: notes, toast: toast,
    theme: theme, setTheme: setTheme, tip: { show: tipShow, hide: tipHide, content: tipContent, bind: bindTip },
    OUT: OUT, pill: pill, outcome: outcome, sev: sev, delta: delta, meter: meter, band: band, bandLabel: bandLabel, segbar: segbar,
    spark: spark, gauge: gauge, lineChart: lineChart, stackBars: stackBars, heatStrip: heatStrip, vizTable: vizTable, vizToggle: vizToggle,
    dur: dur, signed: signed, NAV: NAV,
    banner: banner, pageHeader: pageHeader, btn: btn, chip: chip, searchBox: searchBox, tabsNav: tabsNav, bindTabs: bindTabs,
    card: card, kpi: kpi, table: table, selectRow: selectRow, kv: kv, listRow: listRow, metric: metric, statusPill: statusPill,
    openPalette: openPalette
  };
})();
