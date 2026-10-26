// Responsive chart kit for the Audspect demo.
// Charts are declared as config objects, stored in a registry, and drawn after render
// at the real pixel width of their container (so they re-fit on resize). Tooltips use data-tip.
const CH = { reg: {}, n: 0 };
const NS = 'http://www.w3.org/2000/svg';
// Donuts grow with their legend (it wraps below the ring on narrow screens); other charts have a fixed height.
const chartSlot = (cfg) => { const id = 'c' + (++CH.n); CH.reg[id] = cfg; const size = cfg.type === 'donut' ? `min-height:${cfg.h || 180}px` : `height:${cfg.h || 200}px`; return `<div class="chart-slot" data-cid="${id}" style="${size}"></div>`; };
const esc2 = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
const niceMax = v => { const p = Math.pow(10, Math.floor(Math.log10(Math.max(v, 1)))); const n = v / p; return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * p; };

function drawLine(cfg, W) {
  const H = cfg.h || 200, L = 40, R = 14, T = 12, B = 26;
  const n = cfg.labels.length, all = cfg.series.flatMap(s => s.data);
  const max = cfg.yMax || niceMax(Math.max(...all)), min = cfg.yMin || 0;
  const x = i => L + (n <= 1 ? 0 : i * (W - L - R) / (n - 1));
  const y = v => T + (H - T - B) * (1 - (v - min) / (max - min));
  const gid = 'g' + (++CH.n);
  let out = `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" class="chart-svg"><defs><linearGradient id="${gid}" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="${cfg.series[0].color}" stop-opacity=".32"/><stop offset="1" stop-color="${cfg.series[0].color}" stop-opacity="0"/></linearGradient></defs>`;
  for (let t = 0; t <= 4; t++) {
    const v = min + (max - min) * t / 4, yy = y(v);
    out += `<line x1="${L}" x2="${W - R}" y1="${yy}" y2="${yy}" class="grid-line"/><text x="${L - 8}" y="${yy + 4}" class="axis-t" text-anchor="end">${Math.round(v)}${cfg.suffix || ''}</text>`;
  }
  const longest = Math.max(...cfg.labels.map(l => String(l).length));
  const every = Math.max(1, Math.ceil(n / Math.max(2, Math.floor((W - L) / (longest * 6.6 + 22)))));
  cfg.labels.forEach((lb, i) => { if (i % every === 0) out += `<text x="${x(i)}" y="${H - 6}" class="axis-t" text-anchor="middle">${esc2(lb)}</text>`; });
  const s0 = cfg.series[0];
  if (cfg.area !== false) out += `<polygon points="${L},${H - B} ${s0.data.map((v, i) => `${x(i)},${y(v)}`).join(' ')} ${x(n - 1)},${H - B}" fill="url(#${gid})"/>`;
  cfg.series.forEach((s, k) => {
    out += `<polyline points="${s.data.map((v, i) => `${x(i)},${y(v)}`).join(' ')}" fill="none" stroke="${s.color}" stroke-width="${k ? 1.6 : 2.4}" ${s.dash ? 'stroke-dasharray="5 5"' : ''} stroke-linejoin="round" stroke-linecap="round"/>`;
    if (!k) out += `<circle cx="${x(n - 1)}" cy="${y(s.data[n - 1])}" r="4" fill="${s.color}" style="stroke:var(--surface)" stroke-width="2"/>`;
  });
  const step = n > 1 ? (W - L - R) / (n - 1) : W;
  cfg.labels.forEach((lb, i) => {
    const tip = cfg.labels[i] + ' — ' + cfg.series.map(s => `${s.name || 'Value'}: ${s.data[i]}${cfg.suffix || ''}`).join(' · ');
    out += `<rect x="${x(i) - step / 2}" y="${T}" width="${step}" height="${H - T - B}" fill="transparent" data-tip="${esc2(tip)}" class="hit"/>`;
  });
  return out + '</svg>';
}

function drawBar(cfg, W) {
  const H = cfg.h || 170, L = 34, R = 6, T = 10, B = 24;
  const n = cfg.labels.length;
  const totals = cfg.labels.map((_, i) => cfg.stacked ? cfg.series.reduce((a, s) => a + s.data[i], 0) : Math.max(...cfg.series.map(s => s.data[i])));
  const max = cfg.yMax || niceMax(Math.max(...totals));
  const slot = (W - L - R) / n, bw = Math.max(3, slot * (cfg.stacked ? 0.66 : 0.7) / (cfg.stacked ? 1 : cfg.series.length));
  const y = v => T + (H - T - B) * (1 - v / max);
  const longest = Math.max(...cfg.labels.map(l => String(l).length));
  const labelEvery = Math.max(1, Math.ceil(n / Math.max(2, Math.floor((W - L - R) / (longest * 7 + 14)))));
  let out = `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" class="chart-svg">`;
  for (let t = 0; t <= 4; t++) { const v = max * t / 4; out += `<line x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}" class="grid-line"/><text x="${L - 6}" y="${y(v) + 4}" class="axis-t" text-anchor="end">${Math.round(v)}</text>`; }
  cfg.labels.forEach((lb, i) => {
    const cx = L + slot * i + slot / 2;
    let base = 0;
    if (cfg.stacked) {
      cfg.series.forEach(s => {
        const v = s.data[i], yy = y(base + v), hh = y(base) - y(base + v);
        if (v > 0) out += `<rect x="${cx - bw / 2}" y="${yy}" width="${bw}" height="${Math.max(hh, 0.5)}" rx="${base === 0 ? 0 : 0}" fill="${s.color}" opacity=".92" data-tip="${esc2(lb + ' · ' + (s.name || '') + ': ' + v)}"/>`;
        base += v;
      });
      const top = y(base);
      if (cfg.tops !== false) out += `<rect x="${cx - bw / 2}" y="${top - 3}" width="${bw}" height="3" rx="1.5" fill="rgba(255,255,255,.12)"/>`;
    } else {
      cfg.series.forEach((s, k) => {
        const v = s.data[i], bx = cx - (bw * cfg.series.length) / 2 + k * bw;
        out += `<rect x="${bx}" y="${y(v)}" width="${bw - 1}" height="${y(0) - y(v)}" rx="3" fill="${s.color}" data-tip="${esc2(lb + ' · ' + (s.name || 'Value') + ': ' + v)}"/>`;
      });
    }
    if (i % labelEvery === 0) out += `<text x="${cx}" y="${H - 6}" class="axis-t" text-anchor="middle">${esc2(lb)}</text>`;
  });
  return out + '</svg>';
}

function drawDonut(cfg, W) {
  const total = cfg.segments.reduce((a, s) => a + s.value, 0) || 1;
  const size = Math.min(cfg.h || 180, W * (cfg.legendRight ? 0.5 : 1), 220);
  const r = size / 2 - 16, C = 2 * Math.PI * r, sw = cfg.thick || 18;
  let off = 0, out = `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" class="chart-svg donut"><circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" class="track" stroke-width="${sw}"/>`;
  cfg.segments.forEach(s => {
    const len = (s.value / total) * C;
    out += `<circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="${s.color}" stroke-width="${sw}" stroke-dasharray="${Math.max(len - 2, 0)} ${C}" stroke-dashoffset="${-off}" transform="rotate(-90 ${size / 2} ${size / 2})" class="hit" data-tip="${esc2(s.label + ': ' + s.value + ' (' + Math.round(s.value / total * 100) + '%)')}"/>`;
    off += len;
  });
  out += `<text x="${size / 2}" y="${size / 2 - 2}" text-anchor="middle" class="donut-v">${cfg.center ?? total}</text><text x="${size / 2}" y="${size / 2 + 16}" text-anchor="middle" class="donut-l">${esc2(cfg.centerSub || '')}</text></svg>`;
  const legend = cfg.legend === false ? '' : `<div class="donut-legend">${cfg.segments.map(s => `<div class="dl-row"><i style="background:${s.color}"></i><span>${esc2(s.label)}</span><b>${s.value}</b><em>${Math.round(s.value / total * 100)}%</em></div>`).join('')}</div>`;
  return out + legend;
}

function drawSpark(cfg, W) {
  const H = cfg.h || 36, v = cfg.data, max = Math.max(...v), min = Math.min(...v), n = v.length;
  const x = i => (i / (n - 1)) * (W - 2) + 1, y = val => 3 + (H - 6) * (1 - (val - min) / ((max - min) || 1));
  const pts = v.map((val, i) => `${x(i)},${y(val)}`).join(' ');
  const gid = 'sg' + (++CH.n);
  return `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" class="spark"><defs><linearGradient id="${gid}" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="${cfg.color}" stop-opacity=".35"/><stop offset="1" stop-color="${cfg.color}" stop-opacity="0"/></linearGradient></defs><polygon points="1,${H} ${pts} ${W - 1},${H}" fill="url(#${gid})"/><polyline points="${pts}" fill="none" stroke="${cfg.color}" stroke-width="1.8" stroke-linejoin="round"/></svg>`;
}

function drawHeat(cfg, W) {
  // cfg.rows, cfg.cols, cfg.cells[r][c] = value 0..1, cfg.fmt(v) -> label
  const L = 120, T = 22, cw = Math.max(18, (W - L) / cfg.cols.length), rh = cfg.rh || 26;
  const color = v => `hsla(${Math.round(4 + (1 - v) * 120)},78%,50%,${0.18 + v * 0.55})`;
  let out = `<svg width="${W}" height="${T + cfg.rows.length * rh + 4}" class="chart-svg">`;
  cfg.cols.forEach((c, j) => out += `<text x="${L + j * cw + cw / 2}" y="13" text-anchor="middle" class="axis-t">${esc2(c)}</text>`);
  cfg.rows.forEach((rw, i) => {
    out += `<text x="${L - 8}" y="${T + i * rh + rh / 2 + 4}" text-anchor="end" class="axis-t">${esc2(rw)}</text>`;
    cfg.cols.forEach((c, j) => { const v = cfg.cells[i][j]; out += `<rect x="${L + j * cw + 2}" y="${T + i * rh + 2}" width="${cw - 4}" height="${rh - 4}" rx="4" fill="${color(v)}" data-tip="${esc2(rw + ' × ' + c + ': ' + (cfg.fmt ? cfg.fmt(v) : Math.round(v * 100) + '%'))}" class="hit"/>`; });
  });
  return out + '</svg>';
}

function drawChart(cfg, el) {
  const W = Math.max(el.clientWidth || 300, 120);
  if (cfg.type === 'line') el.innerHTML = drawLine(cfg, W);
  else if (cfg.type === 'bar') el.innerHTML = drawBar(cfg, W);
  else if (cfg.type === 'donut') el.innerHTML = `<div class="donut-wrap">${drawDonut(cfg, W)}</div>`;
  else if (cfg.type === 'spark') el.innerHTML = drawSpark(cfg, W);
  else if (cfg.type === 'heat') el.innerHTML = drawHeat(cfg, W);
}
function hydrateCharts(root = document) {
  root.querySelectorAll('.chart-slot').forEach(el => { const cfg = CH.reg[el.dataset.cid]; if (cfg) drawChart(cfg, el); });
}
// Donut and spark slots need the wrapper to shrink/grow with the card
let chartResizeTimer = null;
window.addEventListener('resize', () => { clearTimeout(chartResizeTimer); chartResizeTimer = setTimeout(() => hydrateCharts(), 120); });

// Shared tooltip
const tip = document.createElement('div');
tip.className = 'chart-tip';
document.body.appendChild(tip);
document.addEventListener('mouseover', e => {
  const t = e.target.closest && e.target.closest('[data-tip]');
  if (!t) { tip.style.opacity = 0; return; }
  tip.textContent = t.getAttribute('data-tip');
  tip.style.opacity = 1;
});
document.addEventListener('mousemove', e => {
  if (tip.style.opacity !== '1') return;
  const pad = 14, w = tip.offsetWidth, h = tip.offsetHeight;
  let x = e.clientX + pad, y = e.clientY - h - pad;
  if (x + w > window.innerWidth - 8) x = e.clientX - w - pad;
  if (y < 8) y = e.clientY + pad;
  tip.style.transform = `translate(${x}px, ${y}px)`;
});
