// Pure helpers for the content-import panel (Sigma/YARA import and chains). No DOM and no network here, so they can be
// tested on their own; the panel itself is content-import.js.

// resultRows turns an import response's results into one display row each.
export function resultRows(results) {
  return (results || []).map(function(r) {
    if (r.error) return { title: r.title || '(unreadable)', status: 'error', detail: r.error };
    var cov = r.coverage || {};
    if (!r.emulable || !r.draftId) {
      return { title: r.title || '', status: 'not-emulable', detail: (cov.notEmulated || []).join('; ') || 'cannot be reproduced' };
    }
    var notes = (cov.notes || []).join('; ');
    return {
      title: r.title || '', draftId: r.draftId, status: r.duplicate ? 'already-waiting' : 'draft',
      detail: (r.duplicate ? 'The same rule is already waiting for review. ' : '') + (notes ? 'Caveats: ' + notes : ''),
    };
  });
}

var RUN_IF = { always: 1, prev_allowed: 1, prev_blocked: 1 };

// parseChainLines reads lines of "scenario-id | step | run-if". Steps are numbered from 1 for people; the API counts from 0.
export function parseChainLines(text) {
  var stages = [], errors = [];
  String(text || '').split('\n').forEach(function(raw, i) {
    var line = raw.trim();
    if (!line) return;
    var p = line.split('|').map(function(s) { return s.trim(); });
    var n = parseInt(p[1], 10);
    if (!p[0] || p.length < 2 || !(n >= 1) || String(n) !== p[1]) { errors.push('Line ' + (i + 1) + ': expected "scenario-id | step number"'); return; }
    var runIf = p[2] || '';
    if (runIf && !RUN_IF[runIf]) { errors.push('Line ' + (i + 1) + ': run-if must be always, prev_allowed or prev_blocked'); return; }
    stages.push({ scenarioId: p[0], stepIndex: n - 1, runIf: runIf });
  });
  return { stages: stages, errors: errors };
}

// commandPreview returns the first step's executor and a shortened command, for the reviewer to read before approving.
export function commandPreview(draft) {
  var steps = (draft && draft.scenario && draft.scenario.steps) || [];
  if (!steps.length) return { executor: '', text: '' };
  var c = String(steps[0].command || '');
  return { executor: steps[0].executor || '', text: c.length > 300 ? c.slice(0, 300) + '…' : c };
}

export function statusLabel(s) {
  return { draft: 'Awaiting review', approved: 'Approved', rejected: 'Rejected' }[s] || s;
}
