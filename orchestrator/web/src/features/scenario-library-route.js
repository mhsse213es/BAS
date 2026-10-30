// Routes one Scenario Library entry to exactly one execution path. The route is
// decided by the server-set type and status only. Nothing is inferred from a
// name or an ID, and anything malformed, unknown, or not executable has no path.

export const LIBRARY_TYPE_AGENT = 'agent';
export const LIBRARY_TYPE_PHISHING = 'phishing';

// Only these two server statuses are runnable. unavailable and catalog_only never route.
const RUNNABLE_STATUSES = ['available', 'experimental'];

export function libraryEntryRoute(entry) {
  if (!entry || typeof entry !== 'object') return { kind: 'none' };
  if (!RUNNABLE_STATUSES.includes(entry.status)) return { kind: 'none' };
  if (entry.type === LIBRARY_TYPE_AGENT) return { kind: 'agent', id: entry.id };
  if (entry.type === LIBRARY_TYPE_PHISHING) return { kind: 'phishing', id: entry.id };
  return { kind: 'none' };
}

// Builds the POST body for a phishing run from the library form. Only the
// schema's own fields are sent, values are trimmed, and numbers become numbers.
// The server validates every parameter again: this check is for the form alone.
export function buildPhishingRunRequest(entry, values) {
  const route = libraryEntryRoute(entry);
  if (route.kind !== LIBRARY_TYPE_PHISHING) return { ok: false, errors: ['not-a-runnable-phishing-entry'] };
  const specs = Array.isArray(entry.parameters) ? entry.parameters : [];
  const parameters = {};
  const errors = [];
  for (const spec of specs) {
    const raw = values && typeof values[spec.name] === 'string' ? values[spec.name].trim() : '';
    if (raw === '') {
      if (spec.required) errors.push(spec.name);
      continue;
    }
    if (spec.kind === 'number') {
      const n = Number(raw);
      if (!Number.isInteger(n) || n <= 0) { errors.push(spec.name); continue; }
      parameters[spec.name] = n;
    } else if (spec.kind === 'email') {
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(raw)) { errors.push(spec.name); continue; }
      parameters[spec.name] = raw;
    } else {
      parameters[spec.name] = raw;
    }
  }
  if (errors.length) return { ok: false, errors };
  return { ok: true, body: { scenarioId: route.id, parameters } };
}

// Attaches the optional exercise execution a run belongs to. An empty value adds
// nothing, so an unlinked run sends exactly what it did before.
export function withExecutionLink(built, executionId) {
  const id = typeof executionId === 'string' ? executionId.trim() : '';
  if (!built || !built.ok || id === '') return built;
  return { ok: true, body: { ...built.body, parameters: { ...built.body.parameters, executionId: id } } };
}

// Counts phishing entries for the landing card. Each count reads only the
// server's status field, so the browser never decides availability itself.
export function phishingLibraryCounts(entries) {
  const counts = { total: 0, runnable: 0, unavailable: 0, catalogOnly: 0 };
  if (!Array.isArray(entries)) return counts;
  for (const entry of entries) {
    if (!entry || entry.type !== LIBRARY_TYPE_PHISHING) continue;
    counts.total += 1;
    if (entry.status === 'available' || entry.status === 'experimental') counts.runnable += 1;
    else if (entry.status === 'unavailable') counts.unavailable += 1;
    else if (entry.status === 'catalog_only') counts.catalogOnly += 1;
  }
  return counts;
}

// True when the page has nothing at all to show: no agent scenarios and no
// phishing entries. Phishing entries keep the page reachable on their own.
export function showNoScenariosMessage(agentCount, entries) {
  return agentCount === 0 && phishingLibraryCounts(entries).total === 0;
}

// Dispatch bounds, mirroring the server's EmailGW dwell window (30 seconds to 2 hours).
// The server is the authority and refuses anything outside them. This check is for the form.
export const DISPATCH_MIN_MS = 30 * 1000;
export const DISPATCH_MAX_MS = 2 * 60 * 60 * 1000;

// Builds the dispatch fields for a phishing run. Dispatch is opt-in: with the box
// unticked, nothing is added and the run is a normal run. With it ticked, the test
// window and an idempotency key are required, and the campaign is optional.
export function buildDispatchFields(values, nowMs, idempotencyKey) {
  if (!values || values.dispatch !== true) return { ok: true, fields: {} };
  const errors = [];
  const local = typeof values.testWindowEnd === 'string' ? values.testWindowEnd.trim() : '';
  const endMs = local ? new Date(local).getTime() : NaN;
  if (Number.isNaN(endMs)) {
    errors.push('testWindowEnd');
  } else {
    const dwell = endMs - nowMs;
    if (dwell < DISPATCH_MIN_MS || dwell > DISPATCH_MAX_MS) errors.push('testWindowEnd');
  }
  if (!idempotencyKey) errors.push('idempotencyKey');
  if (errors.length) return { ok: false, errors };
  const fields = {
    dispatch: true,
    idempotencyKey,
    testWindowEnd: new Date(endMs).toISOString().replace(/\.\d{3}Z$/, 'Z'),
  };
  const campaign = typeof values.campaignId === 'string' ? values.campaignId.trim() : '';
  if (campaign) fields.campaignId = campaign;
  return { ok: true, fields };
}
