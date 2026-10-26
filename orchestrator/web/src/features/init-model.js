// Pure helpers for the redesigned Initiatives page: the card facts, the job strip, the banner chips,
// the chip counts and the search filter. No DOM, no network. Everything is worked out from what
// GET /api/initiatives returned (Initiative: ID, Name, Description, State, CreatedBy, CreatedAt) and,
// per initiative, GET /api/initiatives/{id} (progress: Total, Completed, Running, Requested, Partial,
// Failed, Cancelled, PercentComplete). The design's owner, due date, milestones and on-track status
// have no field in the API; a card shows the creator, the job strip and a status derived from the jobs.

export var STATE_FILTERS = ['active', 'closed', 'archived', 'all'];

export function stateLabel(s) {
  var v = String(s || '');
  return v ? v.charAt(0).toUpperCase() + v.slice(1) : '—';
}

export function stateTone(s) {
  return s === 'active' ? 'ok' : s === 'closed' ? 'info' : 'muted';
}

export function shortId(id) {
  var v = String(id || '');
  return v.length > 13 ? v.slice(0, 8) : v;
}

// initials: up to two letters for the small round avatar next to a creator name.
export function initials(name) {
  var parts = String(name || '').split(/[\s._@-]+/).filter(Boolean);
  if (!parts.length) return '?';
  return ((parts[0].charAt(0) + (parts.length > 1 ? parts[1].charAt(0) : '')).toUpperCase());
}

function n(v) { return Number(v) || 0; }

var MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
// shortDate: "26 Sep 2026" in the viewer's zone, or an em dash for a missing or unreadable date.
export function shortDate(iso) {
  var t = iso ? new Date(iso) : null;
  if (!t || isNaN(t.getTime())) return '—';
  return t.getDate() + ' ' + MON[t.getMonth()] + ' ' + t.getFullYear();
}

// facts: what a card or the drawer shows about one initiative's jobs; null progress means "not loaded".
export function facts(progress) {
  if (!progress) return null;
  var total = n(progress.Total);
  var f = { total: total, completed: n(progress.Completed), running: n(progress.Running) + n(progress.Requested), partial: n(progress.Partial), failed: n(progress.Failed), cancelled: n(progress.Cancelled) };
  f.pct = Math.max(0, Math.min(100, Math.round(n(progress.PercentComplete))));
  return f;
}

// status: a state chip for an active initiative, worked out from its jobs. Closed and archived
// initiatives carry no extra chip (their state says it).
export function status(it, f) {
  if (!it || it.State !== 'active' || !f) return null;
  if (!f.total) return { label: 'No jobs yet', tone: 'muted' };
  if (f.failed || f.partial) return { label: 'At risk', tone: 'warn' };
  return { label: 'On track', tone: 'ok' };
}

export function barTone(it, f) {
  if (f && (f.failed || f.partial)) return 'warn';
  if (f && f.total && f.completed === f.total) return 'ok';
  return it && it.State === 'active' ? 'accent' : 'ok';
}

// strip: one segment per job (done / run / fail / '' for cancelled), scaled down to `max` segments.
export function strip(f, max) {
  if (!f || !f.total) return [];
  max = max || 36;
  var kinds = [['done', f.completed], ['run', f.running + f.partial], ['fail', f.failed], ['', Math.max(0, f.total - f.completed - f.running - f.partial - f.failed)]];
  var scale = f.total > max ? max / f.total : 1;
  var out = [];
  kinds.forEach(function(k) {
    var c = k[1] ? (scale === 1 ? k[1] : Math.max(1, Math.round(k[1] * scale))) : 0;
    for (var i = 0; i < c; i++) out.push(k[0]);
  });
  // Rounding up the small kinds can overshoot; trim the largest kind so every kind still shows.
  while (out.length > max) {
    var counts = {};
    out.forEach(function(k) { counts[k] = (counts[k] || 0) + 1; });
    var big = Object.keys(counts).sort(function(a, b) { return counts[b] - counts[a]; })[0];
    out.splice(out.lastIndexOf(big), 1);
  }
  return out;
}

// stateRows: the jobs by state for the drawer ([label, percent of all jobs, tone, count]), empty states left out.
export function stateRows(f) {
  if (!f || !f.total) return [];
  var rows = [['Completed', f.completed, 'ok'], ['Running or queued', f.running, 'info'], ['Partial', f.partial, 'warn'], ['Failed', f.failed, 'bad'], ['Cancelled', f.cancelled, 'muted']];
  return rows.filter(function(r) { return r[1] > 0; }).map(function(r) { return [r[0], r[1] / f.total * 100, r[2], r[1]]; });
}

export function jobTone(s) {
  var v = String(s || '').toLowerCase();
  return v === 'completed' ? 'ok' : v === 'failed' ? 'bad' : v === 'partial' ? 'warn' : v === 'running' || v === 'requested' ? 'info' : 'muted';
}

// heroStats: the four banner chips. `details` maps initiative id -> facts(progress) (missing = not loaded).
// Average progress is taken over the active initiatives whose progress has loaded (null when none has).
export function heroStats(all, details) {
  var out = { active: 0, avg: null, atRisk: 0, jobs: 0 };
  var sum = 0, cnt = 0;
  (all || []).forEach(function(it) {
    var f = details && details[it.ID];
    if (it.State === 'active') {
      out.active++;
      if (f) { sum += f.pct; cnt++; if (status(it, f) && status(it, f).label === 'At risk') out.atRisk++; }
    }
    if (f) out.jobs += f.total;
  });
  if (cnt) out.avg = Math.round(sum / cnt);
  return out;
}

// counts: initiatives per state for the chips.
export function chipCounts(all) {
  var c = { active: 0, closed: 0, archived: 0, all: 0 };
  (all || []).forEach(function(it) { c.all++; if (c[it.State] !== undefined) c[it.State]++; });
  return c;
}

export function search(list, q) {
  var t = String(q || '').trim().toLowerCase();
  if (!t) return (list || []).slice();
  return (list || []).filter(function(it) {
    return [it.Name, it.ID, it.CreatedBy, it.Description].join(' ').toLowerCase().indexOf(t) !== -1;
  });
}
