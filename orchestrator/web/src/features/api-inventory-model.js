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
  const checks = spec && (Array.isArray(spec.functions) || Array.isArray(spec.properties));
  if (!spec || typeof spec !== 'object' || Array.isArray(spec) || !Array.isArray(spec.identities) || (!Array.isArray(spec.objects) && !checks)) {
    return { spec: null, error: 'The test data needs an "identities" list and an "objects" list' };
  }
  return { spec, error: '' };
}

// exampleBindingSpec proposes a starting point from the first GET operation with a path parameter. The credential references are
// placeholders for names the runner resolves later; the page never takes a credential value.
export function exampleBindingSpec(ops) {
  const op = (ops || []).find((o) => o.method === 'GET' && Array.isArray(o.path_params) && o.path_params.length > 0 && o.auth !== 'none');
  if (!op) {
    const gq = graphQLExampleOp(ops);
    if (gq) return exampleGraphQLSpec(gq);
  }
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

// ---- write-block form: pure helpers. The form edits the test-data JSON; it never replaces it.

const PARAM_RE = /^[A-Za-z0-9._~-]{1,128}$/;
const FIELD_RE = /^[A-Za-z0-9_.-]{1,64}$/;
export const MAX_WRITE_BODY = 4096;

export function opKey(o) { return o.method + ' ' + o.path; }

// writeOperations are the operations a write block can attach to: PUT or PATCH, with a path parameter, not declared public.
export function writeOperations(ops) {
  return (ops || []).filter((o) => (o.method === 'PUT' || o.method === 'PATCH') && Array.isArray(o.path_params) && o.path_params.length > 0 && o.auth !== 'none');
}

function paramSet(o) { return [...(o.path_params || [])].sort().join(','); }

// readChoices are the GET operations an object of a write operation can be read back through: authenticated, same path parameters.
export function readChoices(ops, writeOp) {
  if (!writeOp) return [];
  const want = paramSet(writeOp);
  return (ops || []).filter((o) => o.method === 'GET' && o.auth !== 'none' && paramSet(o) === want).map(opKey);
}

// defaultReadOperation is the GET with the same path as the write ('' when there is none): what the server uses when none is named.
export function defaultReadOperation(ops, writeOp) {
  const k = 'GET ' + writeOp.path;
  return readChoices(ops, writeOp).includes(k) ? k : '';
}

function jsonObjectError(text, label) {
  const t = String(text == null ? '' : text).trim();
  if (t.length < 2 || t.length > MAX_WRITE_BODY) return label + ' must be a JSON object of 2 to ' + MAX_WRITE_BODY + ' characters';
  let v;
  try { v = JSON.parse(t); } catch (e) { return label + ' is not valid JSON'; }
  if (!v || typeof v !== 'object' || Array.isArray(v)) return label + ' must be a JSON object';
  return '';
}

// buildWriteObject checks the form's values the way the server will, and returns the object to add to the test data.
export function buildWriteObject(v, ops) {
  const fail = (error) => ({ object: null, error });
  const op = writeOperations(ops).find((o) => opKey(o) === (v && v.operation));
  if (!op) return fail('Choose a PUT or PATCH operation from the inventory');
  const params = {};
  for (const name of op.path_params) {
    const val = String(v.params && v.params[name] != null ? v.params[name] : '').trim();
    if (!PARAM_RE.test(val)) return fail('Enter a value for ' + name + ': 1 to 128 letters, digits and . _ ~ -');
    params[name] = val;
  }
  const owner = String(v.owner == null ? '' : v.owner).trim();
  if (!owner) return fail('Choose the identity that owns the object');
  let e = jsonObjectError(v.attack_body, 'The attack body');
  if (e) return fail(e);
  e = jsonObjectError(v.restore_body, 'The restore body');
  if (e) return fail(e);
  const attack = String(v.attack_body).trim();
  const restore = String(v.restore_body).trim();
  if (attack === restore || JSON.stringify(JSON.parse(attack)) === JSON.stringify(JSON.parse(restore))) {
    return fail('The attack body and the restore body are the same, so a successful write could not be told from none');
  }
  const choices = readChoices(ops, op);
  const def = defaultReadOperation(ops, op);
  const chosen = String(v.read_operation || '').trim();
  if (chosen && !choices.includes(chosen)) return fail('The read-back must be an authenticated GET with the same path parameters');
  if (!chosen && !def) return fail('No GET on the same path reads this object back; choose how to read it back');
  const ignore = String(v.ignore_fields || '').split(',').map((f) => f.trim()).filter(Boolean);
  if (ignore.length > 20) return fail('At most 20 ignored fields');
  const badField = ignore.find((f) => !FIELD_RE.test(f));
  if (badField) return fail('Ignored field "' + badField.slice(0, 40) + '" must be 1 to 64 letters, digits and . _ -');
  const write = { attack_body: attack, restore_body: restore };
  if (chosen && chosen !== def) write.read_operation = chosen;
  if (ignore.length) write.ignore_fields = ignore;
  return { object: { operation: opKey(op), params, owner, write }, error: '' };
}

function sameObject(a, b) {
  if (a.operation !== b.operation) return false;
  const pa = a.params || {};
  const pb = b.params || {};
  const ka = Object.keys(pa).sort();
  const kb = Object.keys(pb).sort();
  return ka.length === kb.length && ka.every((k, i) => k === kb[i] && pa[k] === pb[k]);
}

// mergeWriteObject returns the spec with the object added (or replacing the one for the same operation and values) and writes
// allowed. The owner must already be one of the spec's identities. The input spec is not changed.
export function mergeWriteObject(spec, object) {
  const base = spec && typeof spec === 'object' && !Array.isArray(spec) ? spec : {};
  const identities = Array.isArray(base.identities) ? base.identities : [];
  if (!identities.some((i) => i && i.name === object.owner)) {
    return { spec: null, error: 'The owner "' + object.owner + '" is not one of the identities in the test data. Add the identities first.', replaced: false };
  }
  const out = JSON.parse(JSON.stringify(base));
  out.identities = identities.map((i) => ({ ...i }));
  out.objects = Array.isArray(out.objects) ? out.objects : [];
  out.allow_writes = true;
  const at = out.objects.findIndex((o) => o && sameObject(o, object));
  if (at >= 0) out.objects[at] = object; else out.objects.push(object);
  return { spec: out, error: '', replaced: at >= 0 };
}

// writeObjectsOf lists the objects that carry a write block, with their position in the spec.
export function writeObjectsOf(spec) {
  const objs = spec && Array.isArray(spec.objects) ? spec.objects : [];
  const out = [];
  objs.forEach((o, index) => { if (o && o.write && typeof o.write === 'object') out.push({ index, operation: o.operation, params: o.params || {}, owner: o.owner, write: o.write }); });
  return out;
}

// removeObjectAt returns the spec without the object at index. The input spec is not changed.
export function removeObjectAt(spec, index) {
  const out = JSON.parse(JSON.stringify(spec));
  if (Array.isArray(out.objects) && index >= 0 && index < out.objects.length) out.objects.splice(index, 1);
  return out;
}

export function identityNames(spec) {
  return spec && Array.isArray(spec.identities) ? spec.identities.map((i) => i && i.name).filter(Boolean) : [];
}

// ---- schedule: pure helpers

export const MAX_EVERY_HOURS = 720;

// parseEveryHours reads the interval box: a whole number of hours from 1 to 720.
export function parseEveryHours(v) {
  const t = String(v == null ? '' : v).trim();
  if (!/^[0-9]{1,4}$/.test(t)) return { hours: 0, error: 'Enter a whole number of hours, from 1 to ' + MAX_EVERY_HOURS };
  const n = Number(t);
  if (n < 1 || n > MAX_EVERY_HOURS) return { hours: 0, error: 'The interval must be from 1 to ' + MAX_EVERY_HOURS + ' hours' };
  return { hours: n, error: '' };
}

export function everyLabel(h) {
  if (h === 1) return 'every hour';
  if (h === 24) return 'every day';
  if (h === 168) return 'every week';
  if (h % 24 === 0 && h < 168) return 'every ' + (h / 24) + ' days';
  return 'every ' + h + ' hours';
}

// scheduleState says what a schedule is doing. 'paused' means it turned itself off after repeated failures to queue its job.
export function scheduleState(s) {
  if (!s) return 'none';
  if (s.paused_for_failures) return 'paused';
  return s.enabled ? 'on' : 'off';
}

export function scheduleTone(s) {
  const st = scheduleState(s);
  if (st === 'paused') return 'bad';
  if (st === 'on') return 'ok';
  return 'muted';
}

// scheduleNote is the sentence under the form: what runs, when next, and how the last attempt went.
export function scheduleNote(s) {
  if (!s) return 'No schedule. The stored test data runs only when you run it.';
  const st = scheduleState(s);
  const parts = [];
  if (st === 'paused') {
    parts.push('Paused after ' + s.consecutive_failures + ' runs in a row could not be queued. Fix the cause, then save the schedule again to resume.');
  } else if (st === 'off') {
    parts.push('The schedule is off.');
  } else {
    parts.push('Runs ' + everyLabel(s.every_hours) + (s.include_writes ? ', including write scenarios' : ', read scenarios only') + '. Next run ' + whenText(s.next_run_at) + '.');
  }
  if (s.last_result) parts.push('Last attempt' + (s.last_run_at ? ' ' + whenText(s.last_run_at) : '') + ': ' + s.last_result + '.');
  return parts.join(' ');
}

function whenText(iso) {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return 'at an unknown time';
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

// ---- function-level and property-level checks

// boundKindLabel is the chip on a bound scenario: what kind of check it is.
export function boundKindLabel(b) {
  if (b && b.kind === 'function') return 'function';
  if (b && b.kind === 'property') return 'property';
  return 'read';
}

// boundWho says who does what in a bound scenario, in words that match its kind.
export function boundWho(b) {
  if (!b) return '';
  if (b.kind === 'function') return b.attacker + ' (ordinary) calls a function of ' + b.victim + ' (privileged)';
  if (b.kind === 'property') return b.attacker + ' reads their own object';
  return b.attacker + ' → ' + b.victim;
}

// exampleChecksSpec proposes a function check on the most privileged-looking authenticated GET and a property check on the first
// authenticated GET with a path parameter. Credential names and values are placeholders; nothing here is a real value.
export function exampleChecksSpec(ops) {
  const gets = (ops || []).filter((o) => o.method === 'GET' && o.auth !== 'none');
  const fnOp = gets.find((o) => (o.classes || []).includes('function_level_authorization')) || gets[0];
  const propOp = gets.find((o) => Array.isArray(o.path_params) && o.path_params.length > 0) || gets[0];
  const params = (op, suffix) => {
    const p = {};
    ((op && op.path_params) || []).forEach((n) => { p[n] = 'REPLACE-' + suffix; });
    return p;
  };
  const key = (op, fallback) => (op ? op.method + ' ' + op.path : fallback);
  return {
    identities: [
      { name: 'admin', credential_ref: 'REPLACE/admin-credential-name' },
      { name: 'alice', credential_ref: 'REPLACE/alice-credential-name' },
    ],
    objects: [],
    functions: [
      { operation: key(fnOp, 'GET /admin/path'), params: params(fnOp, 'F'), privileged: 'admin', ordinary: 'alice', protected_values: ['a value only the admin response contains'] },
    ],
    properties: [
      { operation: key(propOp, 'GET /path/{id}'), params: params(propOp, 'P'), owner: 'alice', forbidden_values: ['a value alice must never receive'] },
    ],
  };
}

// ---- job list filter

export const JOB_STATUSES = [['', 'All'], ['queued', 'Queued'], ['running', 'Running'], ['completed', 'Completed'], ['failed', 'Failed'], ['cancelled', 'Cancelled']];

export function validJobStatus(v) {
  return JOB_STATUSES.some((s) => s[0] === v);
}

// ---- GraphQL read example

// graphQLQueryOps are the query fields a bound GraphQL check can use: a query that does not return a union and whose arguments are
// plain values (no lists, no input objects).
function usableGraphQL(o) {
  return o && o.method === 'QUERY' && o.field && o.returns && !o.returns_union && Array.isArray(o.args || []) &&
    (o.args || []).every((a) => !a.list && (a.kind === 'SCALAR' || a.kind === 'ENUM'));
}

// graphQLExampleOp picks the first usable query that takes a required argument, which is what makes an object belong to someone.
export function graphQLExampleOp(ops) {
  const list = (ops || []).filter(usableGraphQL);
  return list.find((o) => (o.args || []).some((a) => a.required)) || list[0] || null;
}

// opFullKey is the operation name the test data uses: "METHOD path", with "#field" for a GraphQL field.
export function opFullKey(o) {
  return o.method + ' ' + o.path + (o.field ? '#' + o.field : '');
}

// exampleGraphQLSpec is a starting point for a GraphQL query. Argument values and the selection are placeholders to replace.
export function exampleGraphQLSpec(op) {
  const params = (suffix) => {
    const p = {};
    (op.args || []).filter((a) => a.required).forEach((a) => {
      p[a.name] = a.type === 'Int' || a.type === 'Float' ? '1' : a.type === 'Boolean' ? 'true' : 'REPLACE-' + suffix;
    });
    return p;
  };
  const obj = (owner, suffix) => {
    const o = { operation: opFullKey(op), params: params(suffix), owner, protected_values: ['a value only ' + owner + ' may see'] };
    if (op.returns_composite) o.selection = 'id';
    return o;
  };
  return {
    identities: [
      { name: 'alice', credential_ref: 'REPLACE/alice-credential-name' },
      { name: 'bob', credential_ref: 'REPLACE/bob-credential-name' },
    ],
    objects: [obj('alice', 'A'), obj('bob', 'B')],
  };
}
