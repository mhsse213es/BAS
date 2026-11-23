// Pure description of GET /api/ca-rotation/status for the CA rotation card. No DOM, no network.
// The server stays the authority: this only words what it returned, and never says a step has happened or is
// safe unless the server said so. A missing or unrecognised response is "unavailable", never "no rotation".

var STATES = { stable: 1, prepared: 1, promoted: 1 };

function list(v) {
  return Array.isArray(v) ? v.filter(function(s) { return typeof s === 'string'; }) : [];
}

export function describeRotation(r) {
  if (!r || typeof r.state !== 'string' || !STATES[r.state]) {
    return { state: 'unavailable', step: null, progress: null, pending: [], ready: false,
      headline: 'CA rotation status is not available right now.', next: '' };
  }
  if (r.state === 'stable') {
    return { state: 'stable', step: null, progress: null, pending: [], ready: false,
      headline: 'No CA rotation in progress.', next: '' };
  }
  var promote = r.state === 'prepared';
  var total = Number(r.agentsTotal) || 0;
  var done = Number(promote ? r.agentsWithNewRoot : r.agentsOnNewCA) || 0;
  var pending = list(promote ? r.agentsPending : r.agentsPendingRenewal);
  var ready = (promote ? r.readyToPromote : r.readyToRetire) === true && total > 0;
  var next;
  if (total === 0) {
    next = 'There are no agents to confirm, so the server will not call this ready.';
  } else if (promote) {
    next = ready
      ? 'Every agent trusts the new root. Run "ca-rotation promote --yes" on the server, then restart it.'
      : 'Not ready to promote. Run distribute again for agents that were offline.';
  } else {
    next = ready
      ? 'Every agent holds a certificate from the new CA. Run "ca-rotation retire --yes" on the server, then restart it. Rollback is no longer possible after retire.'
      : 'Not safe to retire yet: agents still on an old-CA certificate would be locked out.';
  }
  return {
    state: r.state,
    step: promote ? 'promote' : 'retire',
    progress: { done: done, total: total, label: promote ? 'trust the new root' : 'hold a certificate from the new CA' },
    pending: pending,
    ready: ready,
    headline: promote ? 'CA rotation prepared: the new root is being distributed.' : 'CA rotation promoted: agents are moving to the new CA.',
    next: next,
  };
}
