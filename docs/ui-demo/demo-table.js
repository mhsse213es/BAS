// Enterprise table layer for the Audspect demo.
// After each render every .tbl inside #content is upgraded in place: search, sort, column
// show/hide, row selection with a bulk bar, pagination and CSV export. Works on the existing markup.
const DT = { reg: {} };

const dtText = (r, c, off = 1) => (r.cells[c + off] ? r.cells[c + off].textContent.replace(/\s+/g, ' ').trim() : '');
const dtNum = v => { const m = v.replace(/,/g, '').match(/-?\d+(\.\d+)?/); return m ? parseFloat(m[0]) : -Infinity; };
const dtIsNum = vals => vals.length > 0 && vals.every(v => v === '' || v === '—' || /^[\s+\-▲▼]*\d/.test(v));

// Columns whose every value is a plain number / percentage / duration are right-aligned so digits line up
const dtPureNum = v => /^[\s+\-▲▼]*[\d,.]+\s*(%|ms|s|d|h|min|GB|MB)?\s*$/i.test(v);
function dtAlign(s) {
  [...s.tbl.tHead.rows[0].cells].forEach((th, j) => {
    if (j < s.off || !th.textContent.trim() || th.classList.contains('num')) return;
    const vals = s.rows.map(r => dtText(r, j - s.off, s.off)).filter(v => v !== '' && v !== '—');
    if (vals.length && vals.every(dtPureNum)) { th.classList.add('num'); s.rows.forEach(r => r.cells[j] && r.cells[j].classList.add('num')); }
  });
}

function enhanceTables(root, route) {
  root.querySelectorAll('.tbl-wrap').forEach((wrap, idx) => {
    const tbl = wrap.querySelector('table.tbl');
    if (!tbl || !tbl.tHead || !tbl.tBodies[0] || !tbl.tBodies[0].rows.length) return;
    const key = route + '#' + idx;
    if (!DT.reg[key]) DT.reg[key] = { q: '', col: -1, dir: 1, page: 0, per: 8, sel: new Set(), hidden: new Set() };
    const s = DT.reg[key];
    s.tbl = tbl; s.rows = [...tbl.tBodies[0].rows]; s.key = key;

    // Small tables inside a titled widget card get sortable headers only ("light" mode);
    // page-level lists (and anything with 8+ rows) get the full toolbar, selection and paging.
    const card = wrap.closest('.card');
    s.light = !!card && !!card.querySelector(':scope > .card-hd') && s.rows.length < 8;
    s.off = s.light ? 0 : 1;
    if (s.light) {
      wrap.dataset.tk = key;
      [...tbl.tHead.rows[0].cells].forEach((th, j) => { if (th.textContent.trim()) { th.classList.add('dt-th'); th.dataset.c = j; th.insertAdjacentHTML('beforeend', '<span class="dt-arrow"></span>'); } });
      dtAlign(s);
      dtApply(key);
      return;
    }

    // Wrapper that holds toolbar, table and footer
    const box = document.createElement('div');
    box.className = 'dt';
    box.dataset.tk = key;
    box.innerHTML = `
      <div class="dt-toolbar">
        <div class="input-icon dt-search">${ic('search')}<input class="input dt-q" placeholder="Filter rows…" value="${s.q.replace(/"/g, '&quot;')}"></div>
        <span class="dt-count muted"></span>
        <span class="grow"></span>
        <div class="dt-colwrap">
          <button class="btn sm dt-colbtn">${ic('list', 'sm')}Columns</button>
          <div class="dt-cols hidden">${[...tbl.tHead.rows[0].cells].filter(th => th.textContent.trim()).map(th => `<label class="dt-colitem"><input type="checkbox" class="check dt-colchk" data-c="${th.cellIndex - 1}" ${s.hidden.has(th.cellIndex - 1) ? '' : 'checked'}>${th.textContent.trim()}</label>`).join('')}</div>
        </div>
        <select class="select dt-per" style="height:30px">${[5, 8, 15, 9999].map(n => `<option value="${n}" ${s.per === n ? 'selected' : ''}>${n === 9999 ? 'All rows' : n + ' / page'}</option>`).join('')}</select>
        <button class="btn sm dt-export">${ic('download', 'sm')}Export CSV</button>
      </div>
      <div class="dt-bulk hidden"><b class="dt-n"></b><span>selected</span><span class="grow"></span><button class="btn sm dt-bexp">${ic('download', 'sm')}Export selected</button><button class="btn sm ghost dt-bclr">Clear selection</button></div>`;
    wrap.parentNode.insertBefore(box, wrap);
    box.appendChild(wrap);
    wrap.classList.add('dt-scroll');
    box.insertAdjacentHTML('beforeend', `<div class="dt-empty hidden">${ic('search')}<b>No matching rows</b><span>Try a different search term, or clear the filter.</span><button class="btn sm dt-clearq">Clear filter</button></div>`);
    const foot = document.createElement('div');
    foot.className = 'dt-foot';
    foot.innerHTML = `<span class="dt-range muted"></span><div class="dt-pager"></div>`;
    box.appendChild(foot);

    // Header: select-all + sortable headers
    const hr = tbl.tHead.rows[0];
    const thSel = document.createElement('th');
    thSel.className = 'dt-selcol';
    thSel.innerHTML = '<input type="checkbox" class="check dt-cb dt-all" title="Select all on this table">';
    hr.insertBefore(thSel, hr.firstChild);
    [...hr.cells].forEach((th, j) => { if (j && th.textContent.trim()) { th.classList.add('dt-th'); th.dataset.c = j - 1; th.insertAdjacentHTML('beforeend', '<span class="dt-arrow"></span>'); } });

    // Rows: checkbox column
    s.rows.forEach((r, i) => {
      const td = document.createElement('td');
      td.className = 'dt-selcol';
      td.innerHTML = `<input type="checkbox" class="check dt-cb" data-i="${i}">`;
      r.insertBefore(td, r.firstChild);
    });
    dtAlign(s);
    dtApply(key);
  });
}

function dtApply(key) {
  const s = DT.reg[key];
  if (!s || !s.tbl || !document.body.contains(s.tbl)) return;
  const q = s.q.trim().toLowerCase();
  let list = s.rows.map((r, i) => ({ r, i, t: r.textContent.replace(/\s+/g, ' ').toLowerCase() })).filter(o => !q || o.t.includes(q));
  if (s.col >= 0) {
    const vals = list.map(o => dtText(o.r, s.col, s.off));
    const numeric = dtIsNum(vals);
    list.sort((a, b) => {
      const x = dtText(a.r, s.col, s.off), y = dtText(b.r, s.col, s.off);
      const c = numeric ? dtNum(x) - dtNum(y) : x.localeCompare(y, undefined, { numeric: true });
      return (c || 0) * s.dir;
    });
  }
  const pages = Math.max(1, Math.ceil(list.length / s.per));
  s.page = Math.min(s.page, pages - 1);
  const start = s.page * s.per, vis = list.slice(start, start + s.per);

  // Reorder DOM: matching rows first (in sort order), then the filtered-out ones (hidden)
  const tb = s.tbl.tBodies[0];
  const rest = s.rows.filter(r => !list.some(o => o.r === r));
  tb.append(...list.map(o => o.r), ...rest);
  s.rows.forEach(r => { r.style.display = 'none'; });
  vis.forEach(o => { o.r.style.display = ''; });
  // Header arrows
  s.tbl.tHead.querySelectorAll('.dt-th').forEach(th => {
    const on = +th.dataset.c === s.col;
    th.classList.toggle('sorted', on);
    th.querySelector('.dt-arrow').textContent = on ? (s.dir > 0 ? '▲' : '▼') : '';
  });
  if (s.light) return;

  s.rows.forEach((r, i) => { const cb = r.querySelector('.dt-cb'); if (cb) cb.checked = s.sel.has(i); });
  s.rows.forEach(r => [...r.cells].forEach((td, j) => td.classList.toggle('dt-hide', j > 0 && s.hidden.has(j - 1))));
  [...s.tbl.tHead.rows[0].cells].forEach((th, j) => th.classList.toggle('dt-hide', j > 0 && s.hidden.has(j - 1)));

  // Master checkbox state (for the filtered set)
  const all = s.tbl.tHead.querySelector('.dt-all');
  const onShown = list.filter(o => s.sel.has(o.i)).length;
  all.checked = list.length > 0 && onShown === list.length;
  all.indeterminate = onShown > 0 && onShown < list.length;

  // Bulk bar + counts + pager
  const box = document.querySelector(`[data-tk="${key}"]`);
  if (!box) return;
  const bulk = box.querySelector('.dt-bulk');
  bulk.classList.toggle('hidden', s.sel.size === 0);
  bulk.querySelector('.dt-n').textContent = s.sel.size;
  box.querySelector('.dt-count').textContent = `${list.length} of ${s.rows.length} rows`;
  box.querySelector('.dt-empty').classList.toggle('hidden', list.length > 0);
  const to = Math.min(start + s.per, list.length);
  box.querySelector('.dt-range').textContent = list.length ? `Showing ${start + 1}–${to} of ${list.length}` : 'No rows match the filter';
  box.querySelector('.dt-pager').innerHTML = pages > 1
    ? `<button class="btn sm ghost dt-pg" data-d="-1" ${s.page === 0 ? 'disabled' : ''}>‹ Prev</button><span class="mono muted" style="font-size:12px">${s.page + 1} / ${pages}</span><button class="btn sm ghost dt-pg" data-d="1" ${s.page >= pages - 1 ? 'disabled' : ''}>Next ›</button>`
    : '';
}

function dtExport(key, onlySelected) {
  const s = DT.reg[key];
  const cols = [...s.tbl.tHead.rows[0].cells].map((th, j) => j).slice(1).filter(j => !s.hidden.has(j - 1));
  const rows = s.rows.filter((r, i) => (onlySelected ? s.sel.has(i) : r.style.display !== 'none'));
  const esc = v => `"${String(v).replace(/"/g, '""')}"`;
  const csv = [cols.map(j => esc(s.tbl.tHead.rows[0].cells[j].textContent.replace(/[▲▼]/g, '').trim()))]
    .concat(rows.map(r => cols.map(j => esc(dtText(r, j - 1))))).map(l => l.join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `${key.replace(/[^a-z0-9]+/gi, '-')}.csv`;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  if (typeof toast === 'function') toast('CSV exported', `${rows.length} rows · ${a.download}`);
}

// Row clicks open the row; checkbox clicks must not. Stop them before the row's data-act handler.
document.addEventListener('click', e => {
  if (e.target.closest && e.target.closest('.dt-selcol')) e.stopPropagation();
}, true);

document.addEventListener('click', e => {
  const t = e.target;
  const box = t.closest && t.closest('[data-tk]');
  if (!t.closest || (!t.closest('.dt-colwrap'))) document.querySelectorAll('.dt-cols').forEach(m => m.classList.add('hidden'));
  if (!box) return;
  const key = box.dataset.tk, s = DT.reg[key];
  if (!s) return;
  const th = t.closest('.dt-th');
  if (th) { const c = +th.dataset.c; if (s.col === c) s.dir = -s.dir; else { s.col = c; s.dir = 1; } s.page = 0; return dtApply(key); }
  const pg = t.closest('.dt-pg');
  if (pg) { s.page += +pg.dataset.d; return dtApply(key); }
  if (t.closest('.dt-colbtn')) { box.querySelector('.dt-cols').classList.toggle('hidden'); return; }
  if (t.closest('.dt-export')) return dtExport(key, false);
  if (t.closest('.dt-bexp')) return dtExport(key, true);
  if (t.closest('.dt-bclr')) { s.sel.clear(); return dtApply(key); }
  if (t.closest('.dt-clearq')) { s.q = ''; const qi = box.querySelector('.dt-q'); if (qi) qi.value = ''; s.page = 0; return dtApply(key); }
});

document.addEventListener('input', e => {
  if (!e.target.classList || !e.target.classList.contains('dt-q')) return;
  const box = e.target.closest('.dt'); const s = DT.reg[box.dataset.tk];
  s.q = e.target.value; s.page = 0; dtApply(box.dataset.tk);
});

document.addEventListener('change', e => {
  const t = e.target;
  const box = t.closest && t.closest('.dt');
  if (!box) return;
  const key = box.dataset.tk, s = DT.reg[key];
  if (t.classList.contains('dt-per')) { s.per = +t.value; s.page = 0; return dtApply(key); }
  if (t.classList.contains('dt-colchk')) { const c = +t.dataset.c; t.checked ? s.hidden.delete(c) : s.hidden.add(c); return dtApply(key); }
  if (t.classList.contains('dt-all')) {
    // Select (or clear) every row that matches the current filter, across pages
    const q = s.q.trim().toLowerCase();
    s.rows.forEach((r, i) => {
      if (q && !r.textContent.replace(/\s+/g, ' ').toLowerCase().includes(q)) return;
      if (t.checked) s.sel.add(i); else s.sel.delete(i);
    });
    return dtApply(key);
  }
  if (t.classList.contains('dt-cb')) { const i = +t.dataset.i; t.checked ? s.sel.add(i) : s.sel.delete(i); return dtApply(key); }
});
