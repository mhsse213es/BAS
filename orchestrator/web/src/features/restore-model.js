// The agent's post-run list holds one line per endpoint change it put back, and one "restore incomplete: ..." line for
// each thing it could not put back or could not verify afterwards. Pure helpers so the console can tell them apart.

var PREFIX = 'restore incomplete: ';

// splitReverted -> { reverted: [lines the agent restored], incomplete: [findings, machine prefix removed] }
export function splitReverted(items) {
  var out = { reverted: [], incomplete: [] };
  (Array.isArray(items) ? items : []).forEach(function(l) {
    if (typeof l !== 'string' || !l) return;
    if (l.indexOf(PREFIX) === 0) out.incomplete.push(l.slice(PREFIX.length));
    else out.reverted.push(l);
  });
  return out;
}

// cleanupTile -> what the "Cleanup" ring shows: 100% and ok only when nothing is left unrestored.
export function cleanupTile(s) {
  var done = s.reverted.length, bad = s.incomplete.length;
  if (!bad) return { pct: 100, tone: 'ok', label: 'every captured change reverted' };
  return {
    pct: Math.round(done / (done + bad) * 100),
    tone: 'bad',
    label: bad + ' item' + (bad === 1 ? '' : 's') + ' not fully restored',
  };
}
