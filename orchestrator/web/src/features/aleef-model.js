// Aleef console: pure state and request-building functions (no DOM, no fetch). The DOM layer in aleef.js
// renders what these return, so the rules that matter (findings stay in separate lists, polling stops when a
// run is finished, secrets are references only) are unit-testable.

export var ALEEF_CLASSES = ['unknown', 'read', 'setup_safe', 'reversible', 'money', 'notifying'];
export var ALEEF_PRIOR_KNOWLEDGE = [
  { value: 'not_checked', label: 'Not checked' },
  { value: 'checked_none_found', label: 'New to Audspect (checked, none found)' },
  { value: 'known_public', label: 'Known: publicly reported' },
  { value: 'known_vendor', label: 'Known: reported by vendor' }
];
export var ALEEF_ENVIRONMENTS = ['lab', 'uat'];
export var ALEEF_OPENAPI_WARN_BYTES = 1 << 20;   // warn above 1 MiB
export var ALEEF_OPENAPI_MAX_BYTES = 4 << 20;    // the server body limit is 5 MiB for the whole request
export var ALEEF_SECRET_REF_RE = /^[A-Za-z0-9_./-]{1,64}$/;

export var SAFETY_BANNER = 'Lab/UAT only. Production testing is prohibited. Findings are NEW TO AUDSPECT candidates/verified results, not zero-day claims.';

// aleefPerms maps the console role to the Aleef permissions the server grants it (internal/auth/permissions.go).
// The server is the authority; this only decides which controls to offer.
export function aleefPerms(role) {
  var admin = role === 'admin';
  var analyst = role === 'analyst';
  return { view: admin || analyst, run: admin || analyst, authorize: admin };
}

// hasAleefAddon reads the licence info (GET /api/license) for the aleef special add-on.
export function hasAleefAddon(lic) {
  var list = lic && Array.isArray(lic.specialAddons) ? lic.specialAddons : [];
  return list.some(function(a) { return a && a.name === 'aleef' && (!a.category || a.category === 'special'); });
}

// splitFindings keeps the server's lists separate. verified is fed ONLY from body.verified; pending_regression is
// never counted as verified; nothing is merged or re-derived from state strings.
export function splitFindings(body) {
  var b = body && typeof body === 'object' ? body : {};
  function list(k) { return Array.isArray(b[k]) ? b[k].slice() : []; }
  return {
    candidates: list('candidates'),
    verified: list('verified'),
    pendingRegression: list('pending_regression'),
    unconfirmed: list('unconfirmed'),
    rejected: list('rejected')
  };
}

export function isRunFinished(status) {
  return !!status && status !== 'running' && status !== 'stopping' && status !== 'pending';
}

function pick(o, a, b) { if (!o) return undefined; return o[a] !== undefined ? o[a] : o[b]; }

// runSummary normalises the run view (the Go report struct has capitalised field names).
export function runSummary(run) {
  var r = run || {};
  var rep = r.report && typeof r.report === 'object' ? r.report : null;
  var per = rep ? (pick(rep, 'PerOperation', 'per_operation') || {}) : {};
  var rows = Object.keys(per).sort().map(function(op) {
    var c = per[op] || {};
    return {
      operation: op, cls: pick(c, 'Class', 'class') || '', generated: pick(c, 'Generated', 'generated') || 0,
      executed: pick(c, 'Executed', 'executed') || 0, notExecuted: pick(c, 'NotExecuted', 'not_executed') || 0,
      findings: pick(c, 'Findings', 'findings') || 0, verified: pick(c, 'Verified', 'verified') || 0,
      skipped: pick(c, 'Skipped', 'skipped') || ''
    };
  });
  var orphans = Array.isArray(r.orphans) ? r.orphans : [];
  return {
    runId: r.run_id || '', status: r.status || '', finished: isRunFinished(r.status || ''),
    error: r.error || '', haltedReason: r.halted_reason || '',
    orphans: orphans.map(function(o) {
      return { operation: pick(o, 'Operation', 'operation') || '', id: pick(o, 'ID', 'id') || '', owner: pick(o, 'Owner', 'owner') || '' };
    }),
    total: rep ? (pick(rep, 'Total', 'total') || 0) : 0, executed: rep ? (pick(rep, 'Executed', 'executed') || 0) : 0,
    notExecuted: rep ? (pick(rep, 'NotExecuted', 'not_executed') || 0) : 0, coverage: rows
  };
}

// createPoller polls fetchFn every intervalMs while the run is not finished and stops itself when it is. The timer
// functions are injectable so tests do not wait. stop() is idempotent and is what a tab switch calls.
export function createPoller(opts) {
  var setT = opts.setTimer || function(f, ms) { return setTimeout(f, ms); };
  var clearT = opts.clearTimer || function(t) { clearTimeout(t); };
  var interval = opts.intervalMs || 3000;
  var timer = null, active = false, generation = 0;
  function schedule(gen) {
    timer = setT(function() { timer = null; tick(gen); }, interval);
  }
  function tick(gen) {
    if (!active || gen !== generation) return;
    Promise.resolve().then(opts.fetchFn).then(function(run) {
      if (!active || gen !== generation) return;
      opts.onUpdate(run);
      if (isRunFinished(run && run.status)) { active = false; if (opts.onFinished) opts.onFinished(run); return; }
      schedule(gen);
    }).catch(function(err) {
      if (!active || gen !== generation) return;
      if (opts.onError) opts.onError(err);
      schedule(gen); // transient failure: keep polling until the user leaves the tab
    });
  }
  return {
    start: function() { this.stop(); active = true; generation++; tick(generation); },
    stop: function() { active = false; generation++; if (timer !== null) { clearT(timer); timer = null; } },
    isActive: function() { return active; }
  };
}

// ── request builders (return { error } or { body }) ──────────────────────────
function lines(s) { return String(s || '').split(/[\n,]+/).map(function(x) { return x.trim(); }).filter(Boolean); }

export function buildEngagementRequest(f) {
  if (ALEEF_ENVIRONMENTS.indexOf(f.environment) < 0) return { error: 'Environment must be lab or uat. Production is refused.' };
  if (!String(f.customer || '').trim()) return { error: 'Customer is required.' };
  var nb = new Date(f.notBefore), na = new Date(f.notAfter);
  if (!f.notBefore || !f.notAfter || isNaN(nb.getTime()) || isNaN(na.getTime())) return { error: 'Window start and end are required.' };
  if (!(na > nb)) return { error: 'Window end must be after the start.' };
  var hosts = lines(f.hosts);
  if (!hosts.length) return { error: 'At least one host origin is required (for example https://uat.example:8443).' };
  var maxRequests = parseInt(f.maxRequests, 10), maxConcurrent = parseInt(f.maxConcurrent, 10), rps = parseFloat(f.rps);
  if (!(maxRequests > 0) || !(maxConcurrent > 0) || !(rps > 0)) return { error: 'Max requests, max concurrent and requests per second must be positive.' };
  var body = {
    customer: String(f.customer).trim(), environment: f.environment, hosts: hosts,
    notBefore: nb.toISOString(), notAfter: na.toISOString(),
    maxRequests: maxRequests, maxConcurrent: maxConcurrent, rps: rps
  };
  var ops = lines(f.operations);
  if (ops.length) body.operations = ops;
  if (String(f.targetScopeId || '').trim()) body.target_scope_id = String(f.targetScopeId).trim();
  return { body: body };
}

export function buildRunRequest(f) {
  if (!f.engagementId) return { error: 'Choose an engagement.' };
  if (!String(f.baseUrl || '').trim()) return { error: 'Base URL is required.' };
  var spec = String(f.openapi || '').trim();
  if (!spec) return { error: 'Paste or upload the OpenAPI document.' };
  if (spec.length > ALEEF_OPENAPI_MAX_BYTES) return { error: 'The OpenAPI document is too large (limit about 4 MiB).' };
  var accounts = [];
  var inAccounts = f.accounts || [];
  for (var i = 0; i < inAccounts.length; i++) {
    var a = inAccounts[i];
    if (!a.name && !a.customerId && !a.tokenRef && !a.role) continue;
    if (!a.name || !a.customerId || !a.role) return { error: 'Account ' + (i + 1) + ': name, customer id and role are required.' };
    if (!ALEEF_SECRET_REF_RE.test(a.tokenRef || '')) return { error: 'Account ' + (i + 1) + ': enter a secret reference name (letters, digits, . _ / -), never a token value.' };
    accounts.push({ name: a.name, customer_id: a.customerId, token_ref: a.tokenRef, role: a.role });
  }
  if (!accounts.length) return { error: 'At least one account is required.' };
  var classes = {};
  var cl = f.classes || {};
  Object.keys(cl).forEach(function(op) {
    if (ALEEF_CLASSES.indexOf(cl[op]) < 0) return;
    if (cl[op] !== 'unknown') classes[op] = cl[op]; // unknown is the server default; never sent
  });
  var setup = [];
  if (String(f.setup || '').trim()) {
    try { setup = JSON.parse(f.setup); } catch (e) { return { error: 'Setup operations must be valid JSON.' }; }
    if (!Array.isArray(setup)) return { error: 'Setup operations must be a JSON array.' };
  }
  var num = {};
  var keys = ['seed', 'maxTests', 'reproductions'];
  for (var k = 0; k < keys.length; k++) {
    var raw = String(f[keys[k]] === undefined ? '' : f[keys[k]]).trim();
    if (raw === '') continue;
    var n = parseInt(raw, 10);
    if (isNaN(n) || (keys[k] !== 'seed' && n < 0)) return { error: 'Seed, max tests and reproductions must be whole numbers.' };
    num[keys[k]] = n;
  }
  var options = {};
  if (num.seed !== undefined) options.seed = num.seed;
  if (num.maxTests !== undefined) options.max_tests = num.maxTests;
  if (num.reproductions !== undefined) options.reproductions = num.reproductions;
  return { body: { engagement_id: f.engagementId, openapi: spec, base_url: String(f.baseUrl).trim(), accounts: accounts, setup: setup, classes: classes, options: options } };
}

function sanitizeSeg(s) { return s.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, ''); }
// derivedOpId mirrors the server (internal/aleef/model/openapi.go opID): GET /items/{id} -> get_items_by_id.
export function derivedOpId(method, path) {
  var parts = [method.toLowerCase()];
  String(path).split('/').forEach(function(seg) {
    if (!seg) return;
    if (seg.charAt(0) === '{' && seg.charAt(seg.length - 1) === '}') { parts.push('by', sanitizeSeg(seg.slice(1, -1))); } else { parts.push(sanitizeSeg(seg)); }
  });
  if (parts.length === 1) parts.push('root');
  return parts.join('_');
}

// operationIdsFromOpenAPI lists operationIds (or the derived id when absent) for the classification table.
export function operationIdsFromOpenAPI(text) {
  var doc;
  try { doc = JSON.parse(text); } catch (e) { return { error: 'The OpenAPI document must be JSON (YAML is not read in the console).', ops: [] }; }
  var ops = [];
  var paths = doc && doc.paths && typeof doc.paths === 'object' ? doc.paths : {};
  Object.keys(paths).sort().forEach(function(p) {
    ['get', 'put', 'post', 'delete', 'patch', 'head', 'options'].forEach(function(m) {
      var o = paths[p] && paths[p][m];
      if (o && typeof o === 'object') ops.push(typeof o.operationId === 'string' && o.operationId ? o.operationId : derivedOpId(m, p));
    });
  });
  return { ops: ops };
}

// apiErrorMessage turns a status and body into a one-line message; 403 product_not_licensed and 401 are explicit.
export function apiErrorMessage(status, body) {
  if (status === 401) return 'Your session has expired. Sign in again.';
  if (status === 403 && body && body.error === 'product_not_licensed') return 'The Aleef add-on is not licensed on this server.';
  if (status === 403) return 'You do not have permission for this action.';
  return (body && body.error) ? String(body.error) : 'Request failed (HTTP ' + status + ').';
}
