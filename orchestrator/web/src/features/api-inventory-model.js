// Pure helpers for the API Inventory page: labels, tones, input parsing and the example binding spec. No DOM and no network,
// so tests run them directly.

export const CLASS_LABELS = {
  object_level_authorization: 'Object-level authorization',
  function_level_authorization: 'Function-level authorization',
  property_level_authorization: 'Property-level authorization',
  unauthenticated_access: 'Public (no authentication)',
  sensitive_data_exposure: 'Sensitive data in response',
  resource_consumption: 'Paging / size control',
  server_side_request: 'Destination field',
  file_upload: 'File upload',
  lifecycle: 'Deprecated or older version',
};

export const MAX_OBSERVED = 20000;
export const MAX_SPEC_BYTES = 8 << 20;

export function classLabel(c) { return CLASS_LABELS[c] || String(c); }

export function authTone(auth) {
  return { required: 'ok', none: 'bad', optional: 'warn', unspecified: 'muted' }[auth] || 'muted';
}

export function authLabel(auth) {
  return { required: 'Required', none: 'Public', optional: 'Optional', unspecified: 'Not declared' }[auth] || String(auth || '');
}

export function envTone(env) {
  return { lab: 'info', staging: 'warn', production: 'bad' }[env] || 'muted';
}

// classOptions builds the segmented filter: "All" plus every class present, with counts, in a stable order.
export function classOptions(ops, counts) {
  const opts = [{ id: 'all', label: 'All', count: ops.length }];
  Object.keys(CLASS_LABELS).forEach((c) => {
    const n = counts && counts[c] ? counts[c] : 0;
    if (n > 0) opts.push({ id: c, label: classLabel(c), count: n });
  });
  return opts;
}

export function filterOps(ops, cls) {
  if (!cls || cls === 'all') return ops;
  return ops.filter((o) => Array.isArray(o.classes) && o.classes.includes(cls));
}

// parseObserved reads "METHOD /path" lines (blank lines and # comments ignored) the way the server validates them, so a bad
// line is reported with its number before anything is sent.
export function parseObserved(text) {
  const routes = [];
  const lines = String(text == null ? '' : text).split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line === '' || line[0] === '#') continue;
    const parts = line.split(/\s+/);
    if (parts.length !== 2 || !/^[A-Z]{3,7}$/.test(parts[0]) || parts[1][0] !== '/' || parts[1].length > 2048) {
      return { routes: [], error: 'Line ' + (i + 1) + ': write a route as an upper-case method and a path, for example GET /v2/orders' };
    }
    routes.push({ method: parts[0], path: parts[1] });
    if (routes.length > MAX_OBSERVED) return { routes: [], error: 'At most ' + MAX_OBSERVED + ' routes can be compared at once' };
  }
  if (routes.length === 0) return { routes: [], error: 'Enter at least one route' };
  return { routes, error: '' };
}

// parseBindingSpec parses the test-data JSON and checks its outline. The server validates the content.
export function parseBindingSpec(text) {
  const raw = String(text == null ? '' : text).trim();
  if (raw === '') return { spec: null, error: 'Enter the test data as JSON' };
  if (raw.length > (1 << 20)) return { spec: null, error: 'The test data is too large' };
  let spec;
  try { spec = JSON.parse(raw); } catch (e) { return { spec: null, error: 'The test data is not valid JSON: ' + (e && e.message ? e.message : 'parse error') }; }
  if (!spec || typeof spec !== 'object' || Array.isArray(spec) || !Array.isArray(spec.identities) || !Array.isArray(spec.objects)) {
    return { spec: null, error: 'The test data needs an "identities" list and an "objects" list' };
  }
  return { spec, error: '' };
}

// exampleBindingSpec proposes a starting point from the first GET operation with a path parameter. The credential references are
// placeholders for names the runner resolves later; the page never takes a credential value.
export function exampleBindingSpec(ops) {
  const op = (ops || []).find((o) => o.method === 'GET' && Array.isArray(o.path_params) && o.path_params.length > 0 && o.auth !== 'none');
  const params = (suffix) => {
    const p = {};
    (op ? op.path_params : ['id']).forEach((n) => { p[n] = 'REPLACE-' + suffix; });
    return p;
  };
  return {
    identities: [
      { name: 'alice', credential_ref: 'REPLACE/alice-credential-name' },
      { name: 'bob', credential_ref: 'REPLACE/bob-credential-name' },
    ],
    objects: [
      { operation: op ? op.method + ' ' + op.path : 'GET /path/{id}', params: params('A'), owner: 'alice', protected_values: ['a value only alice may see'] },
      { operation: op ? op.method + ' ' + op.path : 'GET /path/{id}', params: params('B'), owner: 'bob', protected_values: ['a value only bob may see'] },
    ],
  };
}

// changeLines turns the import response's "changes" into short sentences, with the first few routes named.
export function changeLines(ch) {
  if (!ch) return [];
  const out = [];
  const list = (arr, n) => arr.slice(0, n).join(', ') + (arr.length > n ? ', …' : '');
  if (ch.added_total) out.push(ch.added_total + ' added: ' + list(ch.added || [], 5));
  if (ch.removed_total) out.push(ch.removed_total + ' removed: ' + list(ch.removed || [], 5));
  if (ch.auth_changed_total) {
    out.push(ch.auth_changed_total + ' changed authentication: ' + (ch.auth_changed || []).slice(0, 5).map((a) => a.key + ' (' + a.from + ' → ' + a.to + ')').join(', ') + (ch.auth_changed_total > 5 ? ', …' : ''));
  }
  return out;
}

// errorText returns the message of an API error body, or '' when the body is not an error.
export function errorText(r) {
  if (!r) return 'No response from the server';
  if (typeof r.error === 'string' && r.error) return r.error;
  return '';
}

// ---- stored test data, bound jobs

export function jobTone(status) {
  return { completed: 'ok', failed: 'bad', cancelled: 'muted', queued: 'info', running: 'info' }[status] || 'muted';
}

export function resultTone(result) {
  return { PASS: 'ok', FAIL: 'bad', ERROR: 'warn', SKIPPED: 'muted' }[result] || 'muted';
}

export function isFinalStatus(status) {
  return status === 'completed' || status === 'failed' || status === 'cancelled';
}

// resultText says in a sentence what a graded report means, so a result is not read as more than it is.
export function resultText(rep) {
  if (!rep) return '';
  switch (rep.result) {
    case 'FAIL': return 'The other identity got through: the control failed.';
    case 'PASS': return 'The request was refused and nothing the test could see changed or leaked.';
    case 'ERROR': return 'The test could not finish' + (rep.reason ? ' (' + rep.reason + ')' : '') + '. This is not a pass.';
    case 'SKIPPED': return 'Not conclusive' + (rep.reason ? ' (' + rep.reason + ')' : '') + '. This is not a pass.';
    default: return '';
  }
}

// newJobKey makes a unique idempotency key for a run. rand returns a number in [0, 1) and is replaceable in tests.
export function newJobKey(rand) {
  const r = typeof rand === 'function' ? rand : () => {
    try {
      const a = new Uint32Array(1);
      globalThis.crypto.getRandomValues(a);
      return a[0] / 4294967296;
    } catch (e) { return Math.random(); }
  };
  let s = '';
  for (let i = 0; i < 20; i++) s += Math.floor(r() * 16).toString(16);
  return 'ui-' + s;
}

// storedNote words the stored-data state for the banner; '' means nothing to say.
export function storedNote(stored) {
  if (!stored) return '';
  const when = stored.updated_at ? ' on ' + stored.updated_at : '';
  const who = stored.updated_by ? ' by ' + stored.updated_by : '';
  if (stored.stale) {
    return 'Stored' + when + who + ', but checked against inventory v' + stored.validated_inventory + ' and the newest is v' + stored.newest_inventory + '. Save it again before running.';
  }
  return 'Stored' + when + who + ' and checked against the newest inventory (v' + stored.validated_inventory + ').';
}

// exampleWriteBindingSpec proposes test data with write blocks from the first authenticated PUT or PATCH with a path parameter. The
// bodies and credential references are placeholders to replace; the restore body must be a request the target accepts.
export function exampleWriteBindingSpec(ops) {
  const op = (ops || []).find((o) => (o.method === 'PUT' || o.method === 'PATCH') && Array.isArray(o.path_params) && o.path_params.length > 0 && o.auth !== 'none');
  const key = op ? op.method + ' ' + op.path : 'PATCH /path/{id}';
  const hasGet = op && (ops || []).some((o) => o.method === 'GET' && o.path === op.path);
  const block = () => {
    const w = { attack_body: '{"field": "value the other identity tries to set"}', restore_body: '{"field": "value that puts the object back"}', ignore_fields: ['updated_at'] };
    if (op && !hasGet) w.read_operation = 'GET /path/that/reads/the/object/{id}';
    return w;
  };
  const params = (suffix) => {
    const p = {};
    (op ? op.path_params : ['id']).forEach((n) => { p[n] = 'REPLACE-' + suffix; });
    return p;
  };
  return {
    allow_writes: true,
    identities: [
      { name: 'alice', credential_ref: 'REPLACE/alice-credential-name' },
      { name: 'bob', credential_ref: 'REPLACE/bob-credential-name' },
    ],
    objects: [
      { operation: key, params: params('A'), owner: 'alice', write: block() },
      { operation: key, params: params('B'), owner: 'bob', write: block() },
    ],
  };
}

// countsText summarises a job's grades for a list row: only the non-zero ones, worst first.
export function countsText(results) {
  if (!results) return 'no results';
  const parts = [];
  [['fail', 'fail'], ['error', 'error'], ['pass', 'pass'], ['skipped', 'skipped']].forEach((p) => {
    const n = Number(results[p[0]]) || 0;
    if (n > 0) parts.push(n + ' ' + p[1]);
  });
  return parts.length ? parts.join(' · ') : 'no results';
}

// worstTone gives a job row the tone of its worst grade: a failure outranks an error, which outranks a skip.
export function worstTone(results) {
  if (!results) return 'muted';
  if (results.fail > 0) return 'bad';
  if (results.error > 0) return 'warn';
  if (results.skipped > 0) return 'muted';
  if (results.pass > 0) return 'ok';
  return 'muted';
}
