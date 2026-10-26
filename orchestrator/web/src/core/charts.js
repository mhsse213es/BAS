// Chart kit: line / bar (grouped or stacked) / donut / sparkline / heat map, drawn as inline SVG.
//
// A page asks for a chart with chartSlot(cfg), which returns an empty placeholder; the kit draws every
// placeholder it finds, at the real pixel width of its container, and redraws on resize. Nothing here
// needs a call after render. Tooltips come from data-tip attributes and are escaped.
//
// cfg shapes
//   { type:'line',  labels:[..], series:[{name,data:[..],color,dash?}], h?, suffix?, yMax?, yMin?, area? }
//   { type:'bar',   labels:[..], series:[{name,data:[..],color}], stacked?, h?, yMax? }
//   { type:'donut', segments:[{label,value,color}], center?, centerSub?, h?, legend?, legendRight? }
//   { type:'spark', data:[..], color, h? }
//   { type:'heat',  rows:[..], cols:[..], cells:[[0..1]], fmt?(v), rh? }
// Colours are CSS colours; use the CHART_COLORS entries so every theme stays consistent.
import { escapeHTML } from './escape.js';

export const CHART_COLORS = {
  accent: 'var(--accent)', ok: 'var(--success)', warn: 'var(--warning)', bad: 'var(--danger)',
  info: 'var(--info-text)', muted: 'var(--muted)', violet: '#a371f7', teal: '#2fd8c3', pink: '#e0609e',
};

const registry = new Map();
let seq = 0;
const esc = escapeHTML;
const NS = 'http://www.w3.org/2000/svg';
void NS;

const niceMax = (v) => {
  const p = Math.pow(10, Math.floor(Math.log10(Math.max(v, 1))));
  const n = v / p;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * p;
};
const nums = (a) => (a || []).map((v) => (Number.isFinite(Number(v)) ? Number(v) : 0));

export function chartSlot(cfg) {
  const id = 'ch' + (++seq);
  registry.set(id, cfg);
  return '<div class="chart-slot' + (cfg.type === 'donut' ? ' chart-donut' : '') + '" data-cid="' + id + '" data-h="' + (cfg.h || (cfg.type === 'donut' ? 180 : 200)) + '"></div>';
}

function drawLine(cfg, W) {
  const H = cfg.h || 200, L = 40, R = 14, T = 12, B = 26;
  const labels = cfg.labels || [];
  const n = labels.length;
  if (!n) return '';
  const series = cfg.series.map((s) => ({ ...s, data: nums(s.data) }));
  const all = series.flatMap((s) => s.data);
  const max = cfg.yMax || niceMax(Math.max(...all, 1)), min = cfg.yMin || 0;
  const x = (i) => L + (n <= 1 ? 0 : i * (W - L - R) / (n - 1));
  const y = (v) => T + (H - T - B) * (1 - (v - min) / (max - min));
  const gid = 'lg' + (++seq);
  let out = '<svg width="' + W + '" height="' + H + '" viewBox="0 0 ' + W + ' ' + H + '" class="chart-svg"><defs><linearGradient id="' + gid + '" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="' + series[0].color + '" stop-opacity=".30"/><stop offset="1" stop-color="' + series[0].color + '" stop-opacity="0"/></linearGradient></defs>';
  for (let t = 0; t <= 4; t++) {
    const v = min + (max - min) * t / 4, yy = y(v);
    out += '<line x1="' + L + '" x2="' + (W - R) + '" y1="' + yy + '" y2="' + yy + '" class="grid-line"/><text x="' + (L - 8) + '" y="' + (yy + 4) + '" class="axis-t" text-anchor="end">' + Math.round(v) + esc(cfg.suffix || '') + '</text>';
  }
  const longest = Math.max(...labels.map((l) => String(l).length));
  const every = Math.max(1, Math.ceil(n / Math.max(2, Math.floor((W - L) / (longest * 6.6 + 22)))));
  labels.forEach((lb, i) => { if (i % every === 0) out += '<text x="' + x(i) + '" y="' + (H - 6) + '" class="axis-t" text-anchor="middle">' + esc(lb) + '</text>'; });
  if (cfg.area !== false) out += '<polygon points="' + L + ',' + (H - B) + ' ' + series[0].data.map((v, i) => x(i) + ',' + y(v)).join(' ') + ' ' + x(n - 1) + ',' + (H - B) + '" fill="url(#' + gid + ')"/>';
  series.forEach((s, k) => {
    out += '<polyline points="' + s.data.map((v, i) => x(i) + ',' + y(v)).join(' ') + '" fill="none" stroke="' + s.color + '" stroke-width="' + (k ? 1.6 : 2.4) + '"' + (s.dash ? ' stroke-dasharray="5 5"' : '') + ' stroke-linejoin="round" stroke-linecap="round"/>';
    if (!k) out += '<circle cx="' + x(n - 1) + '" cy="' + y(s.data[n - 1]) + '" r="4" fill="' + s.color + '" class="chart-dot" stroke-width="2"/>';
  });
  const step = n > 1 ? (W - L - R) / (n - 1) : W;
  labels.forEach((lb, i) => {
    const tip = lb + ' — ' + series.map((s) => (s.name || 'Value') + ': ' + s.data[i] + (cfg.suffix || '')).join(' · ');
    out += '<rect x="' + (x(i) - step / 2) + '" y="' + T + '" width="' + step + '" height="' + (H - T - B) + '" fill="transparent" data-tip="' + esc(tip) + '" class="hit"/>';
  });
  return out + '</svg>';
}

function drawBar(cfg, W) {
  const H = cfg.h || 170, L = 34, R = 6, T = 10, B = 24;
  const labels = cfg.labels || [];
  const n = labels.length;
  if (!n) return '';
  const series = cfg.series.map((s) => ({ ...s, data: nums(s.data) }));
  const totals = labels.map((_, i) => (cfg.stacked ? series.reduce((a, s) => a + s.data[i], 0) : Math.max(...series.map((s) => s.data[i]))));
  const max = cfg.yMax || niceMax(Math.max(...totals, 1));
  const slot = (W - L - R) / n, bw = Math.max(3, slot * (cfg.stacked ? 0.66 : 0.7) / (cfg.stacked ? 1 : series.length));
  const y = (v) => T + (H - T - B) * (1 - v / max);
  const longest = Math.max(...labels.map((l) => String(l).length));
  const labelEvery = Math.max(1, Math.ceil(n / Math.max(2, Math.floor((W - L - R) / (longest * 7 + 14)))));
  let out = '<svg width="' + W + '" height="' + H + '" viewBox="0 0 ' + W + ' ' + H + '" class="chart-svg">';
  for (let t = 0; t <= 4; t++) { const v = max * t / 4; out += '<line x1="' + L + '" x2="' + (W - R) + '" y1="' + y(v) + '" y2="' + y(v) + '" class="grid-line"/><text x="' + (L - 6) + '" y="' + (y(v) + 4) + '" class="axis-t" text-anchor="end">' + Math.round(v) + '</text>'; }
  labels.forEach((lb, i) => {
    const cx = L + slot * i + slot / 2;
    let base = 0;
    if (cfg.stacked) {
      series.forEach((s) => {
        const v = s.data[i];
        if (v > 0) out += '<rect x="' + (cx - bw / 2) + '" y="' + y(base + v) + '" width="' + bw + '" height="' + Math.max(y(base) - y(base + v), 0.5) + '" fill="' + s.color + '" opacity=".92" data-tip="' + esc(lb + ' · ' + (s.name || '') + ': ' + v) + '"/>';
        base += v;
      });
    } else {
      series.forEach((s, k) => {
        const v = s.data[i], bx = cx - (bw * series.length) / 2 + k * bw;
        out += '<rect x="' + bx + '" y="' + y(v) + '" width="' + (bw - 1) + '" height="' + (y(0) - y(v)) + '" rx="3" fill="' + s.color + '" data-tip="' + esc(lb + ' · ' + (s.name || 'Value') + ': ' + v) + '"/>';
      });
    }
    if (i % labelEvery === 0) out += '<text x="' + cx + '" y="' + (H - 6) + '" class="axis-t" text-anchor="middle">' + esc(lb) + '</text>';
  });
  return out + '</svg>';
}

function drawDonut(cfg, W) {
  const segs = (cfg.segments || []).map((s) => ({ ...s, value: Math.max(0, Number(s.value) || 0) }));
  const total = segs.reduce((a, s) => a + s.value, 0);
  const size = Math.min(cfg.h || 180, W * (cfg.legendRight ? 0.5 : 1), 220);
  const r = size / 2 - 16, C = 2 * Math.PI * r, sw = cfg.thick || 18;
  let off = 0;
  let out = '<svg width="' + size + '" height="' + size + '" viewBox="0 0 ' + size + ' ' + size + '" class="chart-svg donut"><circle cx="' + size / 2 + '" cy="' + size / 2 + '" r="' + r + '" fill="none" class="track" stroke-width="' + sw + '"/>';
  segs.forEach((s) => {
    const len = total ? (s.value / total) * C : 0;
    out += '<circle cx="' + size / 2 + '" cy="' + size / 2 + '" r="' + r + '" fill="none" stroke="' + s.color + '" stroke-width="' + sw + '" stroke-dasharray="' + Math.max(len - 2, 0) + ' ' + C + '" stroke-dashoffset="' + (-off) + '" transform="rotate(-90 ' + size / 2 + ' ' + size / 2 + ')" class="hit" data-tip="' + esc(s.label + ': ' + s.value + ' (' + (total ? Math.round(s.value / total * 100) : 0) + '%)') + '"/>';
    off += len;
  });
  const center = cfg.center != null ? cfg.center : total;
  out += '<text x="' + size / 2 + '" y="' + (size / 2 - 2) + '" text-anchor="middle" class="donut-v">' + esc(center) + '</text><text x="' + size / 2 + '" y="' + (size / 2 + 16) + '" text-anchor="middle" class="donut-l">' + esc(cfg.centerSub || '') + '</text></svg>';
  const legend = cfg.legend === false ? '' : '<div class="donut-legend">' + segs.map((s) => '<div class="dl-row"><i class="dl-sw" data-color="' + esc(s.color) + '"></i><span>' + esc(s.label) + '</span><b>' + s.value + '</b><em>' + (total ? Math.round(s.value / total * 100) : 0) + '%</em></div>').join('') + '</div>';
  return out + legend;
}

function drawSpark(cfg, W) {
  const v = nums(cfg.data);
  if (v.length < 2) return '';
  const H = cfg.h || 36, max = Math.max(...v), min = Math.min(...v), n = v.length;
  const x = (i) => (i / (n - 1)) * (W - 2) + 1, y = (val) => 3 + (H - 6) * (1 - (val - min) / ((max - min) || 1));
  const pts = v.map((val, i) => x(i) + ',' + y(val)).join(' ');
  const gid = 'sg' + (++seq);
  return '<svg width="' + W + '" height="' + H + '" viewBox="0 0 ' + W + ' ' + H + '" class="spark"><defs><linearGradient id="' + gid + '" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="' + cfg.color + '" stop-opacity=".35"/><stop offset="1" stop-color="' + cfg.color + '" stop-opacity="0"/></linearGradient></defs><polygon points="1,' + H + ' ' + pts + ' ' + (W - 1) + ',' + H + '" fill="url(#' + gid + ')"/><polyline points="' + pts + '" fill="none" stroke="' + cfg.color + '" stroke-width="1.8" stroke-linejoin="round"/></svg>';
}

function drawHeat(cfg, W) {
  const rows = cfg.rows || [], cols = cfg.cols || [];
  if (!rows.length || !cols.length) return '';
  const L = 120, T = 22, cw = Math.max(18, (W - L) / cols.length), rh = cfg.rh || 26;
  const color = (v) => 'hsla(' + Math.round(4 + (1 - v) * 120) + ',78%,50%,' + (0.18 + v * 0.55) + ')';
  let out = '<svg width="' + W + '" height="' + (T + rows.length * rh + 4) + '" class="chart-svg">';
  cols.forEach((c, j) => { out += '<text x="' + (L + j * cw + cw / 2) + '" y="13" text-anchor="middle" class="axis-t">' + esc(c) + '</text>'; });
  rows.forEach((rw, i) => {
    out += '<text x="' + (L - 8) + '" y="' + (T + i * rh + rh / 2 + 4) + '" text-anchor="end" class="axis-t">' + esc(rw) + '</text>';
    cols.forEach((c, j) => {
      const v = Math.max(0, Math.min(1, Number(cfg.cells[i][j]) || 0));
      out += '<rect x="' + (L + j * cw + 2) + '" y="' + (T + i * rh + 2) + '" width="' + (cw - 4) + '" height="' + (rh - 4) + '" rx="4" fill="' + color(v) + '" data-tip="' + esc(rw + ' × ' + c + ': ' + (cfg.fmt ? cfg.fmt(v) : Math.round(v * 100) + '%')) + '" class="hit"/>';
    });
  });
  return out + '</svg>';
}

function drawChart(cfg, el) {
  const W = Math.max(el.clientWidth || 300, 120);
  const h = Number(el.dataset.h) || 200;
  if (cfg.type === 'donut') el.style.minHeight = h + 'px'; else el.style.height = h + 'px';
  let html = '';
  if (cfg.type === 'line') html = drawLine(cfg, W);
  else if (cfg.type === 'bar') html = drawBar(cfg, W);
  else if (cfg.type === 'donut') html = '<div class="donut-wrap">' + drawDonut(cfg, W) + '</div>';
  else if (cfg.type === 'spark') html = drawSpark(cfg, W);
  else if (cfg.type === 'heat') html = drawHeat(cfg, W);
  el.innerHTML = html || '<div class="chart-empty">No data</div>';
  // Legend swatches carry their colour as data (a style attribute would be blocked by the CSP).
  el.querySelectorAll('.dl-sw[data-color]').forEach((sw) => { sw.style.background = sw.getAttribute('data-color'); });
  el.dataset.drawn = String(W);
}

export function hydrateCharts(root) {
  const scope = root || document;
  scope.querySelectorAll('.chart-slot').forEach((el) => {
    const cfg = registry.get(el.dataset.cid);
    if (cfg) drawChart(cfg, el);
  });
  // Forget configs whose slot left the page.
  if (registry.size > 400) {
    const live = new Set([...document.querySelectorAll('.chart-slot')].map((e) => e.dataset.cid));
    for (const k of registry.keys()) if (!live.has(k)) registry.delete(k);
  }
}

let tipEl = null;
// Bar widths arrive as data-w (a style attribute would be blocked by the CSP); apply them as they appear.
export function applyDataWidths(root) {
  const scope = root || document;
  const list = scope.querySelectorAll ? scope.querySelectorAll('[data-w]') : [];
  list.forEach((el) => { el.style.width = el.getAttribute('data-w') + '%'; el.removeAttribute('data-w'); });
  if (scope.hasAttribute && scope.hasAttribute('data-w')) { scope.style.width = scope.getAttribute('data-w') + '%'; scope.removeAttribute('data-w'); }
}

export function installCharts() {
  if (tipEl || typeof document === 'undefined') return;
  tipEl = document.createElement('div');
  tipEl.className = 'chart-tip';
  document.body.appendChild(tipEl);
  const pending = new Set();
  let raf = 0;
  const flush = () => {
    raf = 0;
    pending.forEach((el) => {
      if (!el.isConnected || el.dataset.drawn) return;
      const cfg = registry.get(el.dataset.cid);
      if (cfg) drawChart(cfg, el);
    });
    pending.clear();
  };
  const obs = typeof window.MutationObserver === 'undefined' ? null : new window.MutationObserver((muts) => {
    for (const m of muts) {
      m.addedNodes.forEach((n) => {
        if (n.nodeType !== 1) return;
        applyDataWidths(n);
        if (n.classList && n.classList.contains('chart-slot')) pending.add(n);
        else if (n.querySelectorAll) n.querySelectorAll('.chart-slot').forEach((c) => pending.add(c));
      });
    }
    if (pending.size && !raf) raf = window.requestAnimationFrame(flush);
  });
  applyDataWidths(document);
  if (obs) obs.observe(document.body, { childList: true, subtree: true });
  let timer = 0;
  window.addEventListener('resize', () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      document.querySelectorAll('.chart-slot').forEach((el) => {
        const cfg = registry.get(el.dataset.cid);
        if (cfg && el.offsetParent !== null) drawChart(cfg, el);
      });
    }, 120);
  });
  document.addEventListener('mouseover', (e) => {
    const t = e.target.closest && e.target.closest('[data-tip]');
    if (!t) { tipEl.classList.remove('on'); return; }
    tipEl.textContent = t.getAttribute('data-tip');
    tipEl.classList.add('on');
  });
  document.addEventListener('mousemove', (e) => {
    if (!tipEl.classList.contains('on')) return;
    const pad = 14, w = tipEl.offsetWidth, h = tipEl.offsetHeight;
    let px = e.clientX + pad, py = e.clientY - h - pad;
    if (px + w > window.innerWidth - 8) px = e.clientX - w - pad;
    if (py < 8) py = e.clientY + pad;
    tipEl.style.transform = 'translate(' + px + 'px,' + py + 'px)';
  });
}
